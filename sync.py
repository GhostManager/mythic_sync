from typing import Dict, Optional
import json
import sys
import os
import redis
from mythic import mythic_rest
import asyncio
import aiohttp

from datetime import datetime
from sys import exit


def print_flush(message: str):
    print(message)
    sys.stdout.flush()


# How long to wait to make another HTTP request to see if service has started
WAIT_TIMEOUT = 5
MYTHIC_API_KEY = os.environ.get("MYTHIC_API_KEY") or ''
MYTHIC_USERNAME = os.environ.get("MYTHIC_USERNAME") or ''
MYTHIC_PASSWORD = os.environ.get("MYTHIC_PASSWORD") or ''
MYTHIC_IP = os.environ.get("MYTHIC_IP")
if MYTHIC_IP is None:
    print_flush("[!] MYTHIC_IP must be supplied!\n")
    sys.exit(1)
MYTHIC_PORT = os.environ.get("MYTHIC_PORT")
if MYTHIC_PORT is None:
    print_flush("[!] MYTHIC_PORT must be supplied!\n")
    sys.exit(1)
REDIS_PORT = os.environ.get("REDIS_PORT")
if REDIS_PORT is None:
    print_flush("[!] REDIS_PORT must be supplied!\n")
    sys.exit(1)
GHOSTWRITER_API_KEY = os.environ.get("GHOSTWRITER_API_KEY")
if GHOSTWRITER_API_KEY is None:
    print_flush("[!] GHOSTWRITER_API_KEY must be supplied!\n")
    sys.exit(1)
GHOSTWRITER_URL = os.environ.get("GHOSTWRITER_URL")
if GHOSTWRITER_URL is None:
    print_flush("[!] GHOSTWRITER_URL must be supplied!\n")
    sys.exit(1)
GHOSTWRITER_OPLOG_ID = os.environ.get("GHOSTWRITER_OPLOG_ID")
if GHOSTWRITER_OPLOG_ID is None:
    print_flush("[!] GHOSTWRITER_OPLOG_ID must be supplied!\n")
    sys.exit(1)
REDIS_HOSTNAME = os.environ.get("REDIS_HOSTNAME")
if REDIS_HOSTNAME is None:
    print_flush("[!] REDIS_HOSTNAME must be supplied!\n")
    sys.exit(1)
if GHOSTWRITER_OPLOG_ID is None:
    print_flush("[!] GHOSTWRITER_OPLOG_ID must be supplied!\n")
    sys.exit(1)
AUTH: Dict[str, str] = {}

MYTHIC_URL = f'https://{MYTHIC_IP}:{MYTHIC_PORT}'

rconn = None
headers = {'Authorization': f"Api-Key {GHOSTWRITER_API_KEY}", "Content-Type": "application/json"}
missed_response = {}


async def createInitialEntry():
    """ Create initial entry message for Ghostwriter's Oplog (POST) """
    print_flush("[*] Creating Initial Ghostwriter Oplog Entry")

    gw_message = {}
    gw_message["oplog_id"] = GHOSTWRITER_OPLOG_ID
    gw_message["source_ip"] = f"Mythic TS ({MYTHIC_IP})"
    gw_message["description"] = f"Initial entry from mythic_sync at: {MYTHIC_IP}. If you're seeing this then oplog syncing is working for this C2 server!"
    gw_message["tool"] = "Mythic"
    while True:
        try:
            # Fun fact, if you leave off the trailing "/" on oplog/api/entries/ then this POST return "200 OK" without actually doing a thing!
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{GHOSTWRITER_URL}/oplog/api/entries/", data=json.dumps(gw_message), headers=headers, ssl=False) as resp:
                    if resp.status != 201:
                        print_flush(f"[!] Error posting to Ghostwriter with HTTP code {resp.status}, trying again in {WAIT_TIMEOUT} seconds...")
                        await asyncio.sleep(WAIT_TIMEOUT)
                        continue
        except Exception as e:
            print_flush(f"[!] Exception trying to post the initial entry to Ghostwriter!\n{str(e)}\nTrying again in {WAIT_TIMEOUT} seconds...")
            await asyncio.sleep(WAIT_TIMEOUT)
            continue
        return


async def mythic_response_to_ghostwriter_message(message) -> Optional[Dict[str, str]]:
    gw_message: Dict[str, str] = {}
    if message.response is not None:
        gw_message['output'] = message.response
        return gw_message
    else:
        print_flush("[!] Could not locate response in message.")
    return None


async def mythic_task_to_ghostwriter_message(message) -> dict:
    """ Converts a Mythic task to the fields expected by Ghostwriter's Oplog API """
    gw_message = {}
    try:
        if message.status_timestamp_submitted is not None:
            start_date = datetime.strptime(
                message.status_timestamp_submitted, "%m/%d/%Y %H:%M:%S")
            gw_message["start_date"] = start_date.strftime("%Y-%m-%d %H:%M:%S")
        if message.status_timestamp_processed is not None:
            end_date = datetime.strptime(
                message.status_timestamp_processed, "%m/%d/%Y %H:%M:%S")
            gw_message["end_date"] = end_date.strftime("%Y-%m-%d %H:%M:%S")
        # gw_message['start_date'] = message['status_timestamp_submitted']
        # gw_message['end_date'] = message['status_timestamp_processed']
        gw_message["command"] = f"{message.command.cmd if message.command is not None else ''} {message.original_params if message.original_params is not None else ''}"
        #gw_message["command"] = f"{message.get('command', '')} {message.get('params', '')}"
        gw_message["comments"] = message.comment if message.comment is not None else ''
        #gw_message["comments"] = message.get("comment", "")
        gw_message["operator_name"] = message.operator.username if message.operator is not None else ""
        #gw_message["operator_name"] = message.get("operator", "")
        gw_message["oplog_id"] = GHOSTWRITER_OPLOG_ID
        if message.callback is not None:
            hostname = message.callback.host if message.callback.host is not None else ''
            source_ip = message.callback.ip if message.callback.ip is not None else ''
            gw_message["source_ip"] = f"{hostname} ({source_ip})"
            gw_message["user_context"] = message.callback.user if message.callback.user is not None else ''
            gw_message["tool"] = message.callback.payload_type.ptype if message.callback.payload_type is not None else ''
    except Exception as e:
        print_flush("[!] Failed to process message from Mythic into message for GhostWriter: {}".format(str(e)))
    return gw_message


async def createEntry(mythic: mythic_rest.Mythic, message: mythic_rest.Task):
    """ Create entry for Ghostwriter's Oplog (POST) """
    print_flush(f"[*] Adding task: {message.agent_task_id}")
    gw_message = await mythic_task_to_ghostwriter_message(message)
    try:
        # Fun fact, if you leave off the trailing "/" on oplog/api/entries/ then this POST return "200 OK" without actually doing a thing!
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{GHOSTWRITER_URL}/oplog/api/entries/", data=json.dumps(gw_message), headers=headers, ssl=False) as resp:
                if resp.status != 201:
                    print_flush(f"[!] Error posting to Ghostwriter in createEntry: {resp.status}\n")
                else:
                    created_obj = await resp.json()
                    rconn.set(message.agent_task_id, created_obj["id"])
        if message.agent_task_id in missed_response:
            resp = await mythic.get_all_responses_for_task(task=message)
            if resp.status == "success":
                for r in resp.response.responses:
                    await handle_response(mythic, r)
            else:
                print_flush(f"[!] Failed to fetch missed responses for task! {resp.error}")
    except Exception as e:
        print_flush("[!] Exception in create entry: " + str(e))


async def updateEntry(message, entry_id):
    """ Update an existing Ghostwriter oplog entry with more details from Mythic (PUT) """
    print_flush(f"[*] Updating task: {message.agent_task_id} : {entry_id}")
    gw_message = await mythic_task_to_ghostwriter_message(message)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.put(f"{GHOSTWRITER_URL}/oplog/api/entries/{entry_id}/?format=json", data=json.dumps(gw_message), headers=headers, ssl=False) as resp:
                if resp.status != 200:
                    print_flush(f"[!] Error posting to Ghostwriter in updateEntry: {resp.status}\n")
    except Exception as e:
        print_flush("[!] Exception in update entry: " + str(e))


async def handle_task(mythic, data):
    try:
        #await mythic_rest.json_print(data)
        entry_id = rconn.get(data.agent_task_id)
    except Exception as e:
        print_flush(f"[!] Failed to connect to Redis or process Mythic Task in handle_task: {str(e)}")
        return
    try:
        if entry_id is not None:
            await updateEntry(data, entry_id.decode())
        else:
            await createEntry(mythic, data)
    except Exception as e:
        print_flush(f"[!] Exception in Handle Task!: " + str(e))


async def handle_response(mythic, data):
    try:
        entry_id = rconn.get(data.task.agent_task_id)
    except Exception as e:
        print_flush(f"[!] Failed to connect to Redis or process Mythic Response in handle_response: {str(e)}")
        return

    if not entry_id:
        print_flush(f"[!] Received a response for a task that doesn't exist. Saving task id to fetch later: {data.task.agent_task_id}")
        missed_response[data.task.agent_task_id] = True
        return
    try:
        gw_message = await mythic_response_to_ghostwriter_message(data)

        print_flush(f"[*] Updating entry with response data: {entry_id.decode()}")
        async with aiohttp.ClientSession() as session:
            async with session.put(f"{GHOSTWRITER_URL}/oplog/api/entries/{entry_id.decode()}/?format=json", data=json.dumps(gw_message), headers=headers, ssl=False) as resp:
                if resp.status != 200:
                    print_flush(f"[!] Error updating ghostwriter entry: {resp.status}")
    except Exception as e:
        print_flush("[!] Exception in handle response! " + str(e))


async def wait_for_service():
    while True:
        print_flush(f'[*] Attempting to connect to {MYTHIC_URL}')
        async with aiohttp.ClientSession() as session:
            async with session.get(MYTHIC_URL, ssl=False) as resp:
                if resp.status != 200:
                    print_flush(f"[-] Got an HTTP {resp.status} response, trying again in {WAIT_TIMEOUT} seconds...")
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
            print_flush(f"[-] Failed to connect to redis at {REDIS_HOSTNAME}:{REDIS_PORT}, trying again in {WAIT_TIMEOUT} seconds...")
            await asyncio.sleep(WAIT_TIMEOUT)
            continue


async def wait_for_authentication() -> mythic_rest.Mythic:
    while True:
        if len(MYTHIC_API_KEY) == 0:
            print_flush(
                f"[*] Authenticating to Mythic, https://{MYTHIC_IP}:{MYTHIC_PORT}, with username and password")
            mythic = mythic_rest.Mythic(username=MYTHIC_USERNAME, password=MYTHIC_PASSWORD,
                                        server_ip=MYTHIC_IP, server_port=MYTHIC_PORT, ssl=True, global_timeout=-1)
            try:
                resp = await mythic.login()
            except Exception as e:
                print_flush(f"[-] Failed to Authenticate: {str(e)}, trying again in {WAIT_TIMEOUT} seconds...")
                await asyncio.sleep(WAIT_TIMEOUT)
                continue
            await mythic.set_or_create_apitoken()
            me = await mythic.get_self()
            if me.status == "error":
                print_flush(
                    f"[-] Failed to authenticate with API token: {me.error}, trying again in {WAIT_TIMEOUT} seconds...")
                await asyncio.sleep(WAIT_TIMEOUT)
                continue
            return mythic
        elif MYTHIC_USERNAME == "" and MYTHIC_PASSWORD == "":
            print_flush("[!] Must supply a MYTHIC_USERNAME and MYTHIC_PASSWORD\n")
            sys.exit(1)
        else:
            print_flush(f"[*] Authenticating to Mythic, https://{MYTHIC_IP}:{MYTHIC_PORT}, with a specified API Key")
            mythic = mythic_rest.Mythic(apitoken=MYTHIC_API_KEY, server_ip=MYTHIC_IP,
                                        server_port=MYTHIC_PORT, ssl=True, global_timeout=-1)
            me = await mythic.get_self()
            if me.status == "error":
                print_flush(f"[-] Failed to authenticate with API token: {me.error}, trying again in {WAIT_TIMEOUT} seconds...")
                await asyncio.sleep(WAIT_TIMEOUT)
                continue
            return mythic


async def listen_for_all_tasks_exception_handler(mythic: mythic_rest.Mythic, e: Exception):
    print_flush(f"[!] Ran into an issue with the websocket connection for tasking: {str(e)}\nrestarting it in {WAIT_TIMEOUT} seconds...")
    await asyncio.sleep(WAIT_TIMEOUT)
    await mythic.listen_for_all_tasks(callback_function=handle_task,
                                                     exception_handler=listen_for_all_tasks_exception_handler)


async def listen_for_all_responses_exception_handler(mythic: mythic_rest.Mythic, e: Exception):
    print_flush(f"[!] Ran into an issue with the websocket connection for responses: {str(e)}\nrestarting it in {WAIT_TIMEOUT} seconds...")
    await asyncio.sleep(WAIT_TIMEOUT)
    await mythic.listen_for_all_responses(callback_function=handle_task,
                                                          exception_handler=listen_for_all_responses_exception_handler)


async def scripting():
    await wait_for_redis()
    print_flush(f"[+] Successfully connected to Redis")
    await wait_for_service()
    print_flush(f'[+] Successfully connected to {MYTHIC_URL}')
    print_flush(f"[*] Trying to authenticate to Mythic")
    mythic = await wait_for_authentication()
    print_flush(f"[+] Successfully authenticated to Mythic")
    # Perform our initial entry to verify everything works!
    await createInitialEntry()

    await mythic.listen_for_all_tasks(callback_function=handle_task,
                                      exception_handler=listen_for_all_tasks_exception_handler)
    await mythic.listen_for_all_responses(callback_function=handle_response,
                                          exception_handler=listen_for_all_responses_exception_handler)


async def main():
    await scripting()
    try:
        while True:
            pending = asyncio.all_tasks()
            if len(pending) == 0:
                exit(0)
            else:
                await asyncio.gather(*pending)

    except KeyboardInterrupt:
        pending = asyncio.all_tasks()
        for p in pending:
            p.cancel()

print_flush("[*] Starting sync")
loop = asyncio.get_event_loop()
loop.run_until_complete(main())
