from typing import Dict, Optional
import json
import sys
import os
import redis
from mythic import mythic, mythic_classes
import asyncio
import aiohttp
import logging
import traceback

from datetime import datetime
from sys import exit

logging.basicConfig(format="%(levelname)s:%(message)s")
mythic_sync_log = logging.getLogger("mythic_sync_logger")
mythic_sync_log.setLevel(logging.DEBUG)

# How long to wait to make another HTTP request to see if service has started
WAIT_TIMEOUT = 5
MYTHIC_API_KEY = os.environ.get("MYTHIC_API_KEY") or ""
MYTHIC_USERNAME = os.environ.get("MYTHIC_USERNAME") or ""
MYTHIC_PASSWORD = os.environ.get("MYTHIC_PASSWORD") or ""
MYTHIC_IP = os.environ.get("MYTHIC_IP")
if MYTHIC_IP is None:
    mythic_sync_log.error("[!] MYTHIC_IP must be supplied!\n")
    sys.exit(1)
MYTHIC_PORT = os.environ.get("MYTHIC_PORT")
if MYTHIC_PORT is None:
    mythic_sync_log.error("[!] MYTHIC_PORT must be supplied!\n")
    sys.exit(1)
REDIS_PORT = os.environ.get("REDIS_PORT")
if REDIS_PORT is None:
    mythic_sync_log.error("[!] REDIS_PORT must be supplied!\n")
    sys.exit(1)
GHOSTWRITER_API_KEY = os.environ.get("GHOSTWRITER_API_KEY")
if GHOSTWRITER_API_KEY is None:
    mythic_sync_log.error("[!] GHOSTWRITER_API_KEY must be supplied!\n")
    sys.exit(1)
GHOSTWRITER_URL = os.environ.get("GHOSTWRITER_URL")
if GHOSTWRITER_URL is None:
    mythic_sync_log.error("[!] GHOSTWRITER_URL must be supplied!\n")
    sys.exit(1)
GHOSTWRITER_OPLOG_ID = os.environ.get("GHOSTWRITER_OPLOG_ID")
if GHOSTWRITER_OPLOG_ID is None:
    mythic_sync_log.error("[!] GHOSTWRITER_OPLOG_ID must be supplied!\n")
    sys.exit(1)
REDIS_HOSTNAME = os.environ.get("REDIS_HOSTNAME")
if REDIS_HOSTNAME is None:
    mythic_sync_log.error("[!] REDIS_HOSTNAME must be supplied!\n")
    sys.exit(1)
if GHOSTWRITER_OPLOG_ID is None:
    mythic_sync_log.error("[!] GHOSTWRITER_OPLOG_ID must be supplied!\n")
    sys.exit(1)
AUTH: Dict[str, str] = {}

MYTHIC_URL = f"https://{MYTHIC_IP}:{MYTHIC_PORT}"

rconn = None
headers = {
    "Authorization": f"Api-Key {GHOSTWRITER_API_KEY}",
    "Content-Type": "application/json",
}
missed_response = {}


async def createInitialEntry():
    """Create initial entry message for Ghostwriter's Oplog (POST)"""
    mythic_sync_log.info("[*] Creating Initial Ghostwriter Oplog Entry")

    gw_message = {}
    gw_message["oplog_id"] = GHOSTWRITER_OPLOG_ID
    gw_message["source_ip"] = f"Mythic TS ({MYTHIC_IP})"
    gw_message[
        "description"
    ] = f"Initial entry from mythic_sync at: {MYTHIC_IP}. If you're seeing this then oplog syncing is working for this C2 server!"
    gw_message["tool"] = "Mythic"
    while True:
        try:
            # Fun fact, if you leave off the trailing "/" on oplog/api/entries/ then this POST return "200 OK" without actually doing a thing!
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{GHOSTWRITER_URL}/oplog/api/entries/",
                    data=json.dumps(gw_message),
                    headers=headers,
                    ssl=False,
                ) as resp:
                    if resp.status != 201:
                        mythic_sync_log.error(
                            f"[!] Error posting to Ghostwriter with HTTP code {resp.status}, trying again in {WAIT_TIMEOUT} seconds..."
                        )
                        await asyncio.sleep(WAIT_TIMEOUT)
                        continue
        except Exception as e:
            mythic_sync_log.error(
                f"[!] Exception trying to post the initial entry to Ghostwriter!\n{str(e)}\nTrying again in {WAIT_TIMEOUT} seconds..."
            )
            await asyncio.sleep(WAIT_TIMEOUT)
            continue
        return


async def mythic_task_to_ghostwriter_message(message) -> dict:
    """Converts a Mythic task to the fields expected by Ghostwriter's Oplog API"""
    gw_message = {}
    try:
        if message["status_timestamp_submitted"] is not None:
            start_date = datetime.strptime(
                message["status_timestamp_submitted"], "%Y-%m-%dT%H:%M:%S.%f"
            )
            gw_message["start_date"] = start_date.strftime("%Y-%m-%d %H:%M:%S")
        if message["status_timestamp_processed"] is not None:
            end_date = datetime.strptime(
                message["status_timestamp_processed"], "%Y-%m-%dT%H:%M:%S.%f"
            )
            gw_message["end_date"] = end_date.strftime("%Y-%m-%d %H:%M:%S")
        gw_message[
            "command"
        ] = f"{message['command_name']} {message['original_params']}"
        gw_message["comments"] = (
            message["comment"] if message["comment"] is not None else ""
        )
        gw_message["operator_name"] = (
            message["operator"]["username"] if message["operator"] is not None else ""
        )
        gw_message["oplog_id"] = GHOSTWRITER_OPLOG_ID
        hostname = message["callback"]["host"]
        source_ip = message["callback"]["ip"]
        gw_message["source_ip"] = f"{hostname} ({source_ip})"
        gw_message["user_context"] = message["callback"]["user"]
        gw_message["tool"] = message["callback"]["payload"]["payloadtype"]["ptype"]
    except Exception as e:
        mythic_sync_log.error(
            "[!] Failed to process message from Mythic into message for GhostWriter: {}".format(
                str(e)
            )
        )
    return gw_message


async def createEntry(mythic_instance: mythic_classes.Mythic, message: dict):
    """Create entry for Ghostwriter's Oplog (POST)"""
    mythic_sync_log.debug(f"[*] Adding task: {message['agent_task_id']}")
    gw_message = await mythic_task_to_ghostwriter_message(message)
    try:
        # Fun fact, if you leave off the trailing "/" on oplog/api/entries/ then this POST return "200 OK" without actually doing a thing!
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{GHOSTWRITER_URL}/oplog/api/entries/",
                data=json.dumps(gw_message),
                headers=headers,
                ssl=False,
            ) as resp:
                if resp.status != 201:
                    mythic_sync_log.error(
                        f"[!] Error posting to Ghostwriter in createEntry: {resp.status}\n"
                    )
                else:
                    created_obj = await resp.json()
                    rconn.set(message["agent_task_id"], created_obj["id"])
    except Exception as e:
        mythic_sync_log.error("[!] Exception in create entry: " + str(e))


async def updateEntry(message: dict, entry_id: str):
    """Update an existing Ghostwriter oplog entry with more details from Mythic (PUT)"""
    mythic_sync_log.debug(
        f"[*] Updating task: {message['agent_task_id']} - {message['id']} : {entry_id}"
    )
    gw_message = await mythic_task_to_ghostwriter_message(message)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.put(
                f"{GHOSTWRITER_URL}/oplog/api/entries/{entry_id}/?format=json",
                data=json.dumps(gw_message),
                headers=headers,
                ssl=False,
            ) as resp:
                if resp.status != 200:
                    mythic_sync_log.error(
                        f"[!] Error posting to Ghostwriter in updateEntry: {resp.status}\n"
                    )
    except Exception as e:
        mythic_sync_log.error("[!] Exception in update entry: " + str(e))


async def handle_task(mythic_instance: mythic_classes.Mythic):
    custom_return_attributes = """
    agent_task_id
    id
    timestamp
    status_timestamp_submitted
    status_timestamp_processed
    command_name
    original_params
    comment
    operator {
        username
    }
    callback {
        host
        ip
        user
        payload {
            payloadtype {
                ptype
            }
        }
    }
    """
    mythic_sync_log.info(f"[+] Starting subscription for tasks")
    async for data in mythic.subscribe_all_tasks_and_updates(
        mythic=mythic_instance, custom_return_attributes=custom_return_attributes
    ):
        try:
            entry_id = rconn.get(data["agent_task_id"])
        except Exception as e:
            mythic_sync_log.error(
                f"[!] Failed to connect to Redis or process Mythic Task in handle_task: {str(e)}"
            )
            continue
        if entry_id is not None:
            await updateEntry(data, entry_id.decode())
        else:
            await createEntry(mythic_instance, data)


async def wait_for_service():
    while True:
        mythic_sync_log.info(f"[*] Attempting to connect to {MYTHIC_URL}")
        async with aiohttp.ClientSession() as session:
            async with session.get(MYTHIC_URL, ssl=False) as resp:
                if resp.status != 200:
                    mythic_sync_log.info(
                        f"[-] Got an HTTP {resp.status} response, trying again in {WAIT_TIMEOUT} seconds..."
                    )
                    await asyncio.sleep(WAIT_TIMEOUT)
                    continue
        return


async def wait_for_redis():
    global rconn
    while True:
        try:
            rconn = redis.Redis(host=REDIS_HOSTNAME, port=REDIS_PORT, db=1)
            return
        except Exception as e:
            mythic_sync_log.info(
                f"[-] Failed to connect to redis at {REDIS_HOSTNAME}:{REDIS_PORT}, trying again in {WAIT_TIMEOUT} seconds..."
            )
            await asyncio.sleep(WAIT_TIMEOUT)
            continue


async def wait_for_authentication() -> mythic_classes.Mythic:
    while True:
        if len(MYTHIC_API_KEY) == 0:
            mythic_sync_log.info(
                f"[*] Authenticating to Mythic, https://{MYTHIC_IP}:{MYTHIC_PORT}, with username and password"
            )
            try:
                mythic_instance = await mythic.login(
                    username=MYTHIC_USERNAME,
                    password=MYTHIC_PASSWORD,
                    server_ip=MYTHIC_IP,
                    server_port=MYTHIC_PORT,
                    ssl=True,
                    timeout=-1,
                )
            except Exception as e:
                mythic_sync_log.error(
                    f"[-] Failed to Authenticate: {str(e)}, trying again in {WAIT_TIMEOUT} seconds..."
                )
                await asyncio.sleep(WAIT_TIMEOUT)
                continue
            try:
                await mythic.get_me(mythic=mythic_instance)
            except Exception as e:
                mythic_sync_log.error(
                    f"[-] Failed to authenticate with API token: {e}, trying again in {WAIT_TIMEOUT} seconds..."
                )
                await asyncio.sleep(WAIT_TIMEOUT)
                continue
            return mythic_instance
        elif MYTHIC_USERNAME == "" and MYTHIC_PASSWORD == "":
            mythic_sync_log.error(
                "[!] Must supply a MYTHIC_USERNAME and MYTHIC_PASSWORD\n"
            )
            sys.exit(1)
        else:
            mythic_sync_log.info(
                f"[*] Authenticating to Mythic, https://{MYTHIC_IP}:{MYTHIC_PORT}, with a specified API Key"
            )
            try:
                mythic_instance = await mythic.login(
                    apitoken=MYTHIC_API_KEY,
                    server_ip=MYTHIC_IP,
                    server_port=MYTHIC_PORT,
                    ssl=True,
                    global_timeout=-1,
                )
                await mythic.get_me(mythic=mythic_instance)
            except Exception as e:
                mythic_sync_log.error(
                    f"[-] Failed to authenticate with API token: {e}, trying again in {WAIT_TIMEOUT} seconds..."
                )
                await asyncio.sleep(WAIT_TIMEOUT)
                continue
            return mythic_instance


async def scripting():
    while True:
        await wait_for_redis()
        mythic_sync_log.info(f"[+] Successfully connected to Redis")
        await wait_for_service()
        mythic_sync_log.info(f"[+] Successfully connected to {MYTHIC_URL}")
        mythic_sync_log.info(f"[*] Trying to authenticate to Mythic")
        mythic_instance = await wait_for_authentication()
        mythic_sync_log.info(f"[+] Successfully authenticated to Mythic")
        # Perform our initial entry to verify everything works!
        await createInitialEntry()
        try:
            gather = await asyncio.gather(handle_task(mythic_instance=mythic_instance))
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            mythic_sync_log.error(
                f"[-] Hit exception while subscribing to tasks, {traceback.format_exc()} \n {e}, restarting"
            )


asyncio.run(scripting())
