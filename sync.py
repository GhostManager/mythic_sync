# Standard Libraries
import asyncio
import json
import logging
import os
import sys
from datetime import datetime

# 3rd Party Libraries
import aiohttp
import redis

# Mythic Sync Libraries
from mythic import mythic, mythic_classes

logging.basicConfig(format="%(levelname)s:%(message)s")
mythic_sync_log = logging.getLogger("mythic_sync_logger")
mythic_sync_log.setLevel(logging.DEBUG)

# Map integrity level numbers to their meanings (based on Windows integrity levels)
# The *nix agents will always report ``2`` (not root) or ``3`` (root)
INTEGRITY_LEVELS = {
    1: "Low",
    2: "Medium",
    3: "High",
    4: "SYSTEM",
}

# How long to wait to make another HTTP request to see if the service has started
WAIT_TIMEOUT = 5

# Mythic server & authentication
MYTHIC_API_KEY = os.environ.get("MYTHIC_API_KEY") or ""
MYTHIC_USERNAME = os.environ.get("MYTHIC_USERNAME") or ""
MYTHIC_PASSWORD = os.environ.get("MYTHIC_PASSWORD") or ""
MYTHIC_IP = os.environ.get("MYTHIC_IP")
if MYTHIC_IP is None:
    mythic_sync_log.error("MYTHIC_IP must be supplied!\n")
    sys.exit(1)
MYTHIC_PORT = os.environ.get("MYTHIC_PORT")
if MYTHIC_PORT is None:
    mythic_sync_log.error("MYTHIC_PORT must be supplied!\n")
    sys.exit(1)
MYTHIC_URL = f"https://{MYTHIC_IP}:{MYTHIC_PORT}"
REDIS_HOSTNAME = os.environ.get("REDIS_HOSTNAME")
if REDIS_HOSTNAME is None:
    mythic_sync_log.error("REDIS_HOSTNAME must be supplied!\n")
    sys.exit(1)
REDIS_PORT = os.environ.get("REDIS_PORT")
if REDIS_PORT is None:
    mythic_sync_log.error("REDIS_PORT must be supplied!\n")
    sys.exit(1)

# Ghostwriter server & authentication
GHOSTWRITER_API_KEY = os.environ.get("GHOSTWRITER_API_KEY")
if GHOSTWRITER_API_KEY is None:
    mythic_sync_log.error("GHOSTWRITER_API_KEY must be supplied!\n")
    sys.exit(1)
GHOSTWRITER_URL = os.environ.get("GHOSTWRITER_URL")
if GHOSTWRITER_URL is None:
    mythic_sync_log.error("GHOSTWRITER_URL must be supplied!\n")
    sys.exit(1)
GHOSTWRITER_OPLOG_ID = os.environ.get("GHOSTWRITER_OPLOG_ID")
if GHOSTWRITER_OPLOG_ID is None:
    mythic_sync_log.error("GHOSTWRITER_OPLOG_ID must be supplied!\n")
    sys.exit(1)
if GHOSTWRITER_OPLOG_ID is None:
    mythic_sync_log.error("GHOSTWRITER_OPLOG_ID must be supplied!\n")
    sys.exit(1)

# Ghostwriter GraphQL request configuration
GRAPHQL_URL = GHOSTWRITER_URL.rstrip("/") + "/v1/graphql"
HEADERS = {"Authorization": f"Bearer {GHOSTWRITER_API_KEY}", "Content-Type": "application/json"}

# Redis connector
rconn = None

# Query for the first log sent after initialization
INITIAL_QUERY = """
    mutation InitializeMythicSync {{
        insert_oplogEntry(objects: {{
            oplog: "{0}",
            description: "Initial entry from mythic_sync at: {1}. If you're seeing this then oplog syncing is working for this C2 server!",
            sourceIp: "Mythic TS ({2})",
            tool: "Mythic",
        }}) {{
            returning {{ id }}
        }}
    }}
"""
INITIAL_QUERY = INITIAL_QUERY.format(GHOSTWRITER_OPLOG_ID, MYTHIC_IP, MYTHIC_IP)

# Query template for inserting a new log entry
INSERT_QUERY = """
    mutation InsertMythicSyncLog {{
        insert_oplogEntry(objects: {{{LOG_DATA}}}) {{
            returning {{ id }}
        }}
    }}
"""

# Query template for updating a new log entry
UPDATE_QUERY = """
    mutation UpdateMythicSyncLog {{
        update_oplogEntry(where: {{id: {{_eq: "{ENTRY_ID}"}}}}, _set: {{{LOG_DATA}}}) {{
            returning {{ id }}
        }}
    }}
"""


def prepare_query(query, operation) -> str:
    """
    Create a GraphQL query with the given query and the name of the operation to execute.

    **Parameters**

    ``query``
        The query to be sent to the Ghostwriter GraphQL API
    ``operation``
        The name of the operation performed by the query
    """
    return json.dumps({
        "query": query,
        "operationName": operation
    })


async def create_initial_entry() -> None:
    """Send the initial log entry to Ghostwriter's Oplog."""
    mythic_sync_log.info("Sending the initial Ghostwriter log entry")
    while True:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(GRAPHQL_URL, data=prepare_query(INITIAL_QUERY, "InitializeMythicSync"), headers=HEADERS, ssl=False) as resp:
                    if resp.status != 200:
                        mythic_sync_log.error(
                            "Expected 200 OK and received HTTP code %s while trying to create the initial log entry, trying again in %s seconds...",
                            resp.status, WAIT_TIMEOUT
                        )
                        await asyncio.sleep(WAIT_TIMEOUT)
                        continue
        except Exception:
            mythic_sync_log.exception(
                "Exception occurred while trying to post the initial entry to Ghostwriter! Trying again in %s seconds...", WAIT_TIMEOUT
            )
            await asyncio.sleep(WAIT_TIMEOUT)
            continue
        return


async def mythic_task_to_ghostwriter_message(message: dict) -> dict:
    """
    Converts a Mythic task to the fields expected by Ghostwriter's GraphQL API and ``OplogEntry`` model.

    **Parameters**

    ``message``
        The message dictionary to be converted
    """
    gw_message = {}
    try:
        if message["status_timestamp_submitted"] is not None:
            start_date = datetime.strptime(
                message["status_timestamp_submitted"], "%Y-%m-%dT%H:%M:%S.%f")
            gw_message["startDate"] = start_date.strftime("%Y-%m-%d %H:%M:%S")
        if message["status_timestamp_processed"] is not None:
            end_date = datetime.strptime(
                message["status_timestamp_processed"], "%Y-%m-%dT%H:%M:%S.%f")
            gw_message["endDate"] = end_date.strftime("%Y-%m-%d %H:%M:%S")
        gw_message["command"] = f"{message['command_name']} {message['original_params']}"
        gw_message["comments"] = message["comment"] if message["comment"] is not None else ""
        gw_message["operatorName"] = message["operator"]["username"] if message["operator"] is not None else ""
        gw_message["oplog"] = GHOSTWRITER_OPLOG_ID
        hostname = message["callback"]["host"]
        source_ip = message["callback"]["ip"]
        gw_message["sourceIp"] = f"{hostname} ({source_ip})"
        gw_message["userContext"] = message["callback"]["user"]
        gw_message["tool"] = message["callback"]["payload"]["payloadtype"]["ptype"]
    except Exception:
        mythic_sync_log.exception("Encountered an exception while processing Mythic's message into a message for Ghostwriter")
    return gw_message


async def mythic_callback_to_ghostwriter_message(message: dict) -> dict:
    """
    Converts a Mythic callback event to the fields expected by Ghostwriter's GraphQL API and ``OplogEntry`` model.

    **Parameters**

    ``message``
        The message dictionary to be converted
    """
    gw_message = {}
    try:
        callback_date = datetime.strptime(message["init_callback"], "%Y-%m-%dT%H:%M:%S.%f")
        gw_message["startDate"] = callback_date.strftime("%Y-%m-%d %H:%M:%S")
        gw_message["output"] = f"New Callback {message['id']}"
        integrity = INTEGRITY_LEVELS[message["integrity_level"]]
        os = message['os'].replace("\n", " ")
        gw_message["comments"] = f"Integrity Level: {integrity}, Process {message['process_name']} (pid {message['pid']}), OS: {os}"
        gw_message["operatorName"] = message["operator"]["username"] if message["operator"] is not None else ""
        gw_message["sourceIp"] = f"{message['host']} ({message['ip']})"
        gw_message["userContext"] = message["user"]
        gw_message["tool"] = message["payload"]["payloadtype"]["ptype"]
        gw_message["oplog"] = GHOSTWRITER_OPLOG_ID
    except Exception:
        mythic_sync_log.exception(
            "Encountered an exception while processing Mythic's message into a message for Ghostwriter! Received message: %s", message
        )
    return gw_message


async def create_entry(mythic_instance: mythic_classes.Mythic, message: dict) -> None:
    """
    Create an entry for a Mythic task in Ghostwriter's ``OplogEntry`` model. Uses the
    ``INSERT_QUERY`` template and the operation name ``InsertMythicSyncLog``.

    **Parameters**

    ``mythic_instance``
        The Mythic instance to be used to query the Mythic database
    ``message``
        Dictionary produced by ``mythic_task_to_ghostwriter_message()`` or ``mythic_callback_to_ghostwriter_message()``
    """
    entry_id = ""
    if "agent_task_id" in message:
        entry_id = message["agent_task_id"]
        mythic_sync_log.debug(f"Adding task: {message['agent_task_id']}")
        gw_message = await mythic_task_to_ghostwriter_message(message)
    elif "agent_callback_id" in message:
        entry_id = message["agent_callback_id"]
        mythic_sync_log.debug(f"Adding callback: {message['agent_callback_id']}")
        gw_message = await mythic_callback_to_ghostwriter_message(message)
    else:
        mythic_sync_log.error(
            "Failed to create an entry for task, no `agent_task_id` or `agent_callback_id` found! Message contents: %s", message
        )

    if entry_id:
        created_obj = None
        try:
            async with aiohttp.ClientSession() as session:
                data = ", ".join('{}: "{}"'.format(k, v) for k, v in gw_message.items())
                query = prepare_query(INSERT_QUERY.format(LOG_DATA=data), "InsertMythicSyncLog")
                async with session.post(GRAPHQL_URL, data=query, headers=HEADERS, ssl=False) as resp:
                    if resp.status != 200:
                        mythic_sync_log.error("Expected 200 OK and received HTTP code %s while trying to create a log entry", resp.status)
                    else:
                        # JSON response example: `{'data': {'insert_oplogEntry': {'returning': [{'id': 192}]}}}`
                        created_obj = await resp.json()
                        rconn.set(entry_id, created_obj["data"]["insert_oplogEntry"]["returning"][0]["id"])
        except Exception:
            mythic_sync_log.exception(
                "Encountered an exceptio while trying to create a new log entry! Response from Ghostwriter: %s", created_obj
            )


async def update_entry(message: dict, entry_id: str) -> None:
    """
    Update an existing Ghostwriter ``OplogEntry`` entry for a task with more details from Mythic.
    Uses the ``UPDATE_QUERY`` template and the operation name ``UpdateMythicSyncLog``.

    **Parameters**

    ``message``
        Dictionary produced by ``mythic_task_to_ghostwriter_message()``
    ``entry_id``
        The ID of the log entry to be updated
    """
    mythic_sync_log.debug(f"Updating task: {message['agent_task_id']} - {message['id']} : {entry_id}")
    gw_message = await mythic_task_to_ghostwriter_message(message)
    try:
        async with aiohttp.ClientSession() as session:
            data = ", ".join('{}: "{}"'.format(k, v) for k, v in gw_message.items())
            query = prepare_query(UPDATE_QUERY.format(ENTRY_ID=entry_id, LOG_DATA=data), "UpdateMythicSyncLog")
            async with session.post(GRAPHQL_URL, data=query, headers=HEADERS, ssl=False) as resp:
                if resp.status != 200:
                    mythic_sync_log.error("Expected 200 OK and received HTTP code %s while trying to update a log entry", resp.status)
    except Exception:
        mythic_sync_log.exception("Exception encountered while trying to update task log entry in Ghostwriter!")


async def handle_task(mythic_instance: mythic_classes.Mythic) -> None:
    """
    Start a subscription for Mythic tasks and handle them. Send new tasks to Ghostwriter
    with ``create_entry()`` or send updates for existign tasks with ``update_entry()``.

    **Parameters**

    ``mythic_instance``
        The Mythic instance to be used to query the Mythic database
    """
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
    mythic_sync_log.info("Starting subscription for tasks")
    async for data in mythic.subscribe_all_tasks_and_updates(mythic=mythic_instance, custom_return_attributes=custom_return_attributes):
        try:
            entry_id = rconn.get(data["agent_task_id"])
        except Exception:
            mythic_sync_log.exception("Encountered an exception while connecting to Redis to fetch data! Data returned by Mythic: %s", data)
            continue
        if entry_id is not None:
            await update_entry(data, entry_id.decode())
        else:
            await create_entry(mythic_instance, data)


async def handle_callback(mythic_instance: mythic_classes.Mythic) -> None:
    """
    Start a subscription for Mythic agent callbacks and send all new callbacks to Ghostwriter
    with ``create_entry()``.

    **Parameters**

    ``mythic_instance``
        The Mythic instance to be used to query the Mythic database
    """
    custom_return_attributes = """
    agent_callback_id
    init_callback
    integrity_level
    description
    host
    id
    extra_info
    ip
    os
    pid
    process_name
    user
    operator {
      username
    }
    payload {
      payloadtype {
        ptype
      }
    }
    """
    mythic_sync_log.info("Starting subscription for callbacks")
    async for data in mythic.subscribe_new_callbacks(mythic=mythic_instance, custom_return_attributes=custom_return_attributes):
        await create_entry(mythic_instance, data)


async def wait_for_service() -> None:
    """Wait for an HTTP session to be established with Mythic."""
    while True:
        mythic_sync_log.info(f"Attempting to connect to {MYTHIC_URL}")
        async with aiohttp.ClientSession() as session:
            async with session.get(MYTHIC_URL, ssl=False) as resp:
                if resp.status != 200:
                    mythic_sync_log.warning("Expected 200 OK and received HTTP code %s while trying to connect to Mythic, trying again in %s seconds...", resp.status, WAIT_TIMEOUT)
                    await asyncio.sleep(WAIT_TIMEOUT)
                    continue
        return


async def wait_for_redis() -> None:
    """Wait for a connection to be established with Mythic's Redis container."""
    global rconn
    while True:
        try:
            rconn = redis.Redis(host=REDIS_HOSTNAME, port=REDIS_PORT, db=1)
            return
        except Exception:
            mythic_sync_log.exception(
                "Encountered an exception while trying to connect to Redis, %s:%s, trying again in %s seconds...",
                REDIS_HOSTNAME, REDIS_PORT, WAIT_TIMEOUT
            )
            await asyncio.sleep(WAIT_TIMEOUT)
            continue


async def wait_for_authentication() -> mythic_classes.Mythic:
    """Wait for authentication with Mythic to complete."""
    while True:
        # If ``MYTHIC_API_KEY`` is not set in the environment, then authenticate with user credentials
        if len(MYTHIC_API_KEY) == 0:
            mythic_sync_log.info(
                "Authenticating to Mythic, https://%s:%s, with username and password", MYTHIC_IP, MYTHIC_PORT)
            try:
                mythic_instance = await mythic.login(
                    username=MYTHIC_USERNAME,
                    password=MYTHIC_PASSWORD,
                    server_ip=MYTHIC_IP,
                    server_port=MYTHIC_PORT,
                    ssl=True,
                    timeout=-1)
            except Exception:
                mythic_sync_log.exception(
                    "Encountered an exception while trying to authenticate to Mythic, trying again in %s seconds...",
                    WAIT_TIMEOUT
                )
                await asyncio.sleep(WAIT_TIMEOUT)
                continue
            try:
                await mythic.get_me(mythic=mythic_instance)
            except Exception:
                mythic_sync_log.exception(
                    "Encountered an exception while trying to authenticate to Mythic, trying again in %s seconds...",
                    WAIT_TIMEOUT
                )
                await asyncio.sleep(WAIT_TIMEOUT)
                continue
        elif MYTHIC_USERNAME == "" and MYTHIC_PASSWORD == "":
            mythic_sync_log.error("You must supply a MYTHIC_USERNAME and MYTHIC_PASSWORD")
            sys.exit(1)
        else:
            mythic_sync_log.info("Authenticating to Mythic, https://%s:%s, with a specified API Key", MYTHIC_IP, MYTHIC_PORT)
            try:
                mythic_instance = await mythic.login(
                    apitoken=MYTHIC_API_KEY,
                    server_ip=MYTHIC_IP,
                    server_port=MYTHIC_PORT,
                    ssl=True,
                    global_timeout=-1)
                await mythic.get_me(mythic=mythic_instance)
            except Exception:
                mythic_sync_log.exception(
                    "Failed to authenticate with the Mythic API token, trying again in %s seconds...",
                    WAIT_TIMEOUT
                )
                await asyncio.sleep(WAIT_TIMEOUT)
                continue

        return mythic_instance


async def scripting():
    while True:
        await wait_for_redis()
        mythic_sync_log.info("Successfully connected to Redis")
        await wait_for_service()
        mythic_sync_log.info(f"Successfully connected to {MYTHIC_URL}")
        mythic_sync_log.info("Trying to authenticate to Mythic")
        mythic_instance = await wait_for_authentication()
        mythic_sync_log.info("Successfully authenticated to Mythic")
        # Perform our initial entry to verify everything works!
        await create_initial_entry()
        try:
            _ = await asyncio.gather(
                handle_task(mythic_instance=mythic_instance),
                handle_callback(mythic_instance=mythic_instance),
            )
        except Exception:
            mythic_sync_log.exception("Encountered an exception while subscribing to tasks and responses, restarting...")

asyncio.run(scripting())
