import json
import os
import redis
import requests
from mythic import mythic_rest
import asyncio

from datetime import datetime
from mythic import *
from sys import exit

MYTHIC_USERNAME = os.environ["MYTHIC_USERNAME"]
MYTHIC_PASSWORD = os.environ["MYTHIC_PASSWORD"]
MYTHIC_IP = os.environ["MYTHIC_IP"]

GHOSTWRITER_API_KEY = os.environ["GHOSTWRITER_API_KEY"]
GHOSTWRITER_URL = os.environ["GHOSTWRITER_URL"]
GHOSTWRITER_OPLOG_ID = os.environ["GHOSTWRITER_OPLOG_ID"]
REDIS_HOSTNAME =os.environ["REDIS_HOSTNAME"]
AUTH = {}

rconn = redis.Redis(host=REDIS_HOSTNAME, port=6379, db=0)
headers = {'Authorization': f"Api-Key {GHOSTWRITER_API_KEY}", "Content-Type": "application/json"}

def createInitialEntry():
    """ Create initial entry message for Ghostwriter's Oplog (POST) """
    print("[*] Creating Initial Ghostwriter Oplog Entry")

    gw_message = {}
    gw_message["oplog_id"] = GHOSTWRITER_OPLOG_ID
    gw_message["source_ip"] = f"Mythic TS ({MYTHIC_IP})"
    gw_message["description"] = f"Initial entry from mythic_sync at: {MYTHIC_IP}. If you're seeing this then oplog syncing is working for this C2 server!"
    gw_message["tool"] = "Mythic"

    try:
        # Fun fact, if you leave off the trailing "/" on oplog/api/entries/ then this POST return "200 OK" without actually doing a thing!
        response = requests.post (
            f"{GHOSTWRITER_URL}/oplog/api/entries/", data=json.dumps(gw_message), headers=headers, verify=False
    )

        if response.status_code != 201:
            print(f"[!] Error posting to Ghostwriter: {response.status_code}")

    except Exception as e:
        print(e)

def mythic_response_to_ghostwriter_message(message) -> dict:
    gw_message = {}
    if message.response is not None:
        gw_message['output'] = message.response
        return gw_message
    else:
        print("[!] Could not locate response in message.")
    return None

def mythic_task_to_ghostwriter_message(message) -> dict:
    """ Converts a Mythic task to the fields expected by Ghostwriter's Oplog API """
    gw_message = {}
    if message.status_timestamp_submitted is not None:
        start_date = datetime.strptime(message.status_timestamp_submitted, "%m/%d/%Y %H:%M:%S")
        gw_message["start_date"] = start_date.strftime("%Y-%m-%d %H:%M:%S")
    if message.status_timestamp_processed is not None:
        end_date = datetime.strptime(message.status_timestamp_processed, "%m/%d/%Y %H:%M:%S")
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
    
    return gw_message

def createEntry(message):
    """ Create entry for Ghostwriter's Oplog (POST) """
    print(f"[*] Adding task: {message.agent_task_id}")
    gw_message = mythic_task_to_ghostwriter_message(message)
    try:
        # Fun fact, if you leave off the trailing "/" on oplog/api/entries/ then this POST return "200 OK" without actually doing a thing!
        response = requests.post (
            f"{GHOSTWRITER_URL}/oplog/api/entries/", data=json.dumps(gw_message), headers=headers, verify=False
        )

        if response.status_code != 201:
            print(f"[!] Error posting to Ghostwriter: {response.status_code}")
        else:
            created_obj = json.loads(response.text)
            rconn.set(message.agent_task_id, created_obj["id"])

    except Exception as e:
        print(e)


def updateEntry(message, entry_id):
    """ Update an existing Ghostwriter oplog entry with more details from Mythic (PUT) """
    print(f"[*] Updating task: {message.agent_task_id} : {entry_id}")
    gw_message = mythic_task_to_ghostwriter_message(message)
    try:
        response = requests.put (
            f"{GHOSTWRITER_URL}/oplog/api/entries/{entry_id}/?format=json", data=json.dumps(gw_message), headers=headers, verify=False
        )

        if response.status_code != 200:
            print(f"[!] Error posting to Ghostwriter: {response.status_code}")
        
    except Exception as e:
        print(e)


async def handle_task(mythic, data):
    try:
        entry_id = rconn.get(data.agent_task_id)
    except Exception as e:
        print(f"[!] Failed to connect to Redis: {str(e)}")
        return
    if entry_id != None:
        updateEntry(data, entry_id.decode())
        return
    else:
        createEntry(data)
    
async def handle_response(token, data):
    try:
        entry_id = rconn.get(data.task.agent_task_id)
    except Exception as e:
        print(f"[!] Failed to connect to Redis: {str(e)}")
        return
    if not entry_id:
        print(f"[!] Received a response for a task that doesn't exist.")
        return

    gw_message = mythic_response_to_ghostwriter_message(data)

    print(f"[*] Updating entry with response data: {entry_id.decode()}")

    response = requests.put(
        f"{GHOSTWRITER_URL}/oplog/api/entries/{entry_id.decode()}/?format=json",
        data=json.dumps(gw_message),
        headers=headers,
        verify=False
    )

    if response.status_code !=  200:
        print(f"[!] Error updating ghostwriter entry: {response.status_code}")

async def scripting():
    mythic = mythic_rest.Mythic(username=MYTHIC_USERNAME, password=MYTHIC_PASSWORD,
                    server_ip=MYTHIC_IP, server_port="7443", ssl=True, global_timeout=-1)

    await mythic.login()
    resp = await mythic.set_or_create_apitoken()

    await mythic.listen_for_all_tasks(handle_task)
    await mythic.listen_for_all_responses(handle_response)

async def main():
    await scripting()
    try:
        while True:
            pending = asyncio.Task.all_tasks()
            if len(pending) == 0:
                exit(0)
            else:
                await asyncio.gather(*pending)

    except KeyboardInterrupt:
        pending = asyncio.Task.all_tasks()
        for p in pending:
            p.cancel()

# Perform our initial entry to verify everything works!
createInitialEntry()

print("[*] Starting sync")
loop = asyncio.get_event_loop()
loop.run_until_complete(main())
