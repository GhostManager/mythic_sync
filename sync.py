# Standard Libraries
import asyncio
import ipaddress
import json
import logging
import os
import sys
from asyncio.exceptions import TimeoutError
from datetime import datetime, timedelta, timezone

# 3rd Party Libraries
import aiohttp
import redis
from gql import Client, gql
from gql.client import DocumentNode
from gql.transport.aiohttp import AIOHTTPTransport
from gql.transport.exceptions import TransportQueryError
from graphql.error.graphql_error import GraphQLError

# Mythic Sync Libraries
from mythic import mythic, mythic_classes

VERSION = "3.0.0"

# Logging configuration
# Level applies to all loggers, including ``gql`` Transport and Client loggers
# Using a level below ``WARNING`` may make logs difficult to read
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s %(asctime)s %(message)s"
)
mythic_sync_log = logging.getLogger("mythic_sync_logger")
mythic_sync_log.setLevel(logging.DEBUG)


class MythicSync:
    # Redis and Mythic connectors
    rconn = None
    mythic_instance = None

    # Map integrity level numbers to their meanings (based on Windows integrity levels)
    # The *nix agents will always report ``2`` (not root) or ``3`` (root)
    integrity_levels = {
        1: "Low",
        2: "Medium",
        3: "High",
        4: "SYSTEM",
    }

    # How long to wait for a service to start before retrying an HTTP request
    wait_timeout = 5

    # Query for the whoami expiration checks
    whoami_query = gql(
        """
        query whoami {
          whoami {
            expires
          }
        }
        """
    )

    # Query for the first log sent after initialization
    initial_query = gql(
        """
        mutation InitializeMythicSync ($oplogId: bigint!, $description: String!, $server: String!) {
            insert_oplogEntry(objects: {
                oplog: $oplogId,
                description: $description,
                sourceIp: $server,
                tool: "Mythic",
            }) {
                returning { id }
            }
        }
        """
    )

    # Query inserting a new log entry
    insert_query = gql(
        """
        mutation InsertMythicSyncLog (
            $oplog: bigint!, $startDate: timestamptz, $endDate: timestamptz, $sourceIp: String, $destIp: String,
            $tool: String, $userContext: String, $command: String, $description: String,
            $output: String, $comments: String, $operatorName: String
        ) {
            insert_oplogEntry(objects: {
                oplog: $oplog,
                startDate: $startDate,
                endDate: $endDate,
                sourceIp: $sourceIp,
                destIp: $destIp,
                tool: $tool,
                userContext: $userContext,
                command: $command,
                description: $description,
                output: $output,
                comments: $comments,
                operatorName: $operatorName,
            }) {
                returning { id }
            }
        }
        """
    )

    # Query for updating a new log entry
    update_query = gql(
        """
        mutation UpdateMythicSyncLog (
            $id: bigint!, $oplog: bigint!, $startDate: timestamptz, $endDate: timestamptz, $sourceIp: String,
            $destIp: String, $tool: String, $userContext: String, $command: String,
            $description: String, $output: String, $comments: String, $operatorName: String,
        ) {
            update_oplogEntry(where: {
                id: {_eq: $id}
            }, _set: {
                oplog: $oplog,
                startDate: $startDate,
                endDate: $endDate,
                sourceIp: $sourceIp,
                destIp: $destIp,
                tool: $tool,
                userContext: $userContext,
                command: $command,
                description: $description,
                output: $output,
                comments: $comments,
                operatorName: $operatorName,
            }) {
                returning { id }
            }
        }
        """
    )

    # Mythic authentication
    MYTHIC_API_KEY = os.environ.get("MYTHIC_API_KEY") or ""
    MYTHIC_USERNAME = os.environ.get("MYTHIC_USERNAME") or ""
    MYTHIC_PASSWORD = os.environ.get("MYTHIC_PASSWORD") or ""

    # Mythic server
    MYTHIC_IP = os.environ.get("MYTHIC_IP")
    if MYTHIC_IP is None:
        mythic_sync_log.error("MYTHIC_IP must be supplied!")
        sys.exit(1)

    MYTHIC_PORT = os.environ.get("MYTHIC_PORT")
    if MYTHIC_PORT is None:
        mythic_sync_log.error("MYTHIC_PORT must be supplied!")
        sys.exit(1)
    else:
        MYTHIC_PORT = int(MYTHIC_PORT)

    MYTHIC_URL = f"https://{MYTHIC_IP}:{MYTHIC_PORT}"

    # Redis server
    REDIS_HOSTNAME = "127.0.0.1"
    REDIS_PORT = 6379

    # Ghostwriter server authentication
    GHOSTWRITER_API_KEY = os.environ.get("GHOSTWRITER_API_KEY")
    if GHOSTWRITER_API_KEY is None:
        mythic_sync_log.error("GHOSTWRITER_API_KEY must be supplied!")
        sys.exit(1)

    # Ghostwriter server & oplog target
    GHOSTWRITER_URL = os.environ.get("GHOSTWRITER_URL")
    if GHOSTWRITER_URL is None:
        mythic_sync_log.error("GHOSTWRITER_URL must be supplied!")
        sys.exit(1)

    GHOSTWRITER_OPLOG_ID = os.environ.get("GHOSTWRITER_OPLOG_ID")
    if GHOSTWRITER_OPLOG_ID is None:
        mythic_sync_log.error("GHOSTWRITER_OPLOG_ID must be supplied!")
        sys.exit(1)

    # GraphQL transport configuration
    GRAPHQL_URL = GHOSTWRITER_URL.rstrip("/") + "/v1/graphql"
    headers = {
        "User-Agent": f"Mythic_Sync/{VERSION}",
        "Authorization": f"Bearer {GHOSTWRITER_API_KEY}",
        "Content-Type": "application/json"
    }
    transport = AIOHTTPTransport(url=GRAPHQL_URL, timeout=10, headers=headers)

    def __init__(self):
        pass

    async def initialize(self) -> None:
        """
        Function to initialize necessary connections with Mythic services. This must
        always be run before anything else.
        """
        await self._wait_for_redis()
        mythic_sync_log.info("Successfully connected to Redis")

        await self._wait_for_service()
        mythic_sync_log.info("Successfully connected to %s", {self.MYTHIC_URL})

        mythic_sync_log.info("Trying to authenticate to Mythic")
        self.mythic_instance = await self.__wait_for_authentication()
        mythic_sync_log.info("Successfully authenticated to Mythic")

        await self._check_token()
        await self._create_initial_entry()

    async def _get_sorted_ips(self, ip: str) -> str:
        source_ips = json.loads(ip)
        source_ips = [x for x in source_ips if x != ""]
        source_ipv4 = []
        for i in range(len(source_ips)):
            new_address = ipaddress.ip_address(source_ips[i])
            if isinstance(new_address, ipaddress.IPv4Address):
                source_ipv4.append(new_address)
        source_ipv4 = [str(x) for x in sorted(source_ipv4)]
        source_ips = source_ipv4
        source_ip = json.dumps(source_ips)
        return source_ip

    async def _execute_query(self, query: DocumentNode, variable_values: dict = None) -> dict:
        """
        Execute a GraphQL query against the Ghostwriter server.

        **Parameters**

        ``query``
            The GraphQL query to execute
        ``variable_values``
            The parameters to pass to the query
        """
        while True:
            try:
                async with Client(transport=self.transport, fetch_schema_from_transport=False, ) as session:
                    try:
                        result = await session.execute(query, variable_values=variable_values)
                        mythic_sync_log.debug("Successfully executed query with result: %s", result)
                        return result
                    except TimeoutError:
                        mythic_sync_log.error(
                            "Timeout occurred while trying to connect to Ghostwriter at %s",
                            self.GHOSTWRITER_URL
                        )
                        await self._post_error_notification(f"MythicSync:\nTimeout occurred while trying to connect to Ghostwriter at {self.GHOSTWRITER_URL}",)
                        await asyncio.sleep(self.wait_timeout)
                        continue
                    except TransportQueryError as e:
                        mythic_sync_log.exception("Error encountered while fetching GraphQL schema: %s", e)
                        await self._post_error_notification(f"MythicSync:\nError encountered while fetching GraphQL schema: {e}")
                        payload = e.errors[0]
                        if "extensions" in payload:
                            if "code" in payload["extensions"]:
                                if payload["extensions"]["code"] == "access-denied":
                                    mythic_sync_log.error(
                                        "Access denied for the provided Ghostwriter API token! Check if it is valid, update your configuration, and restart")
                                    await mythic.send_event_log_message(
                                        mythic=self.mythic_instance,
                                        message=f"Access denied for the provided Ghostwriter API token! Check if it is valid, update your Mythic Sync configuration, and restart the service.",
                                        source="mythic_sync_reject",
                                        level="warning"
                                    )
                                    exit(1)
                                if payload["extensions"]["code"] == "postgres-error":
                                    mythic_sync_log.error(
                                        "Ghostwriter's database rejected the query! Check if your configured log ID is correct.")
                                    await mythic.send_event_log_message(
                                        mythic=self.mythic_instance,
                                        message=f"Ghostwriter's database rejected the query! Check if your configured log ID ({self.GHOSTWRITER_OPLOG_ID}) is correct.",
                                        source="mythic_sync_reject",
                                        level="warning"
                                    )
                        await asyncio.sleep(self.wait_timeout)
                        continue
                    except GraphQLError as e:
                        mythic_sync_log.exception("Error with GraphQL query: %s", e)
                        await self._post_error_notification(f"MythicSync:\nError with GraphQL query: {e}")
                        await asyncio.sleep(self.wait_timeout)
                        continue
            except Exception as exc:
                mythic_sync_log.exception(
                    "Exception occurred while trying to post the query to Ghostwriter! Trying again in %s seconds...",
                    self.wait_timeout
                )
                await self._post_error_notification(f"MythicSync:\nException occurred while trying to post the query to Ghostwriter!\n{exc}")
                await asyncio.sleep(self.wait_timeout)
                continue

    async def _check_token(self) -> None:
        """Send a `whoami` query to Ghostwriter to check authentication and token expiration."""
        whoami = await self._execute_query(self.whoami_query)
        expiry = datetime.fromisoformat(whoami["whoami"]["expires"])
        await mythic.send_event_log_message(
            mythic=self.mythic_instance,
            message=f"Mythic Sync has successfully authenticated to Ghostwriter. Your configured token expires at: {expiry}",
            source="mythic_sync",
            level="info"
        )

        # Check if the token will expire within 24 hours
        now = datetime.now(timezone.utc)
        if expiry - now < timedelta(hours=24):
            mythic_sync_log.debug(f"The provided Ghostwriter API token expires in less than 24 hours ({expiry})!")
            await mythic.send_event_log_message(
                mythic=self.mythic_instance,
                message=f"The provided Ghostwriter API token expires in less than 24 hours ({expiry})!",
                source="mythic_sync",
                level="warning"
            )

    async def _create_initial_entry(self) -> None:
        """Send the initial log entry to Ghostwriter's Oplog."""
        mythic_sync_log.info("Sending the initial Ghostwriter log entry")
        variable_values = {
            "oplogId": self.GHOSTWRITER_OPLOG_ID,
            "description": f"Initial entry from mythic_sync at: {self.MYTHIC_IP}. If you're seeing this then oplog "
                           f"syncing is working for this C2 server!",
            "server": f"Mythic Server ({self.MYTHIC_IP})",
        }
        await self._execute_query(self.initial_query, variable_values)
        await mythic.send_event_log_message(
            mythic=self.mythic_instance,
            message="Mythic Sync successfully posted its initial log entry to Ghostwriter",
            source="mythic_sync",
            level="info"
        )
        return

    async def _post_error_notification(self, message: str = None) -> None:
        """Send an error notification to Mythic's notification center."""
        if message is None:
            message = "Mythic Sync logged an error and may need attention to continue syncing.\n" \
                      "Run this command to review the issue:\n\n" \
                      "  sudo ./mythic-cli logs mythic_sync"
        mythic_sync_log.info("Submitting an error notification to Mythic's notification center")
        await mythic.send_event_log_message(mythic=self.mythic_instance,
                                            message=message,
                                            source="mythic_sync",
                                            level="warning")
        return

    async def _mythic_task_to_ghostwriter_message(self, message: dict) -> dict:
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
            gw_message["oplog"] = self.GHOSTWRITER_OPLOG_ID
            hostname = message["callback"]["host"]
            source_ip = await self._get_sorted_ips(message["callback"]["ip"])
            gw_message["sourceIp"] = f"{hostname} ({source_ip})"
            gw_message["userContext"] = message["callback"]["user"]
            gw_message["tool"] = message["callback"]["payload"]["payloadtype"]["name"]
        except Exception:
            mythic_sync_log.exception(
                "Encountered an exception while processing Mythic's message into a message for Ghostwriter"
            )
        return gw_message

    async def _mythic_callback_to_ghostwriter_message(self, message: dict) -> dict:
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
            gw_message["output"] = f"New Callback {message['display_id']}"
            integrity = self.integrity_levels[message["integrity_level"]]
            opsys = message['os'].replace("\n", " ")
            gw_message["comments"] = f"Integrity Level: {integrity}\nProcess: {message['process_name']} (pid {message['pid']})\nOS: {opsys}"
            gw_message["operatorName"] = message["operator"]["username"] if message["operator"] is not None else ""
            source_ip = await self._get_sorted_ips(message["ip"])
            gw_message["sourceIp"] = f"{message['host']} ({source_ip})"
            gw_message["userContext"] = message["user"]
            gw_message["tool"] = message["payload"]["payloadtype"]["name"]
            gw_message["oplog"] = self.GHOSTWRITER_OPLOG_ID
        except Exception:
            mythic_sync_log.exception(
                "Encountered an exception while processing Mythic's message into a message for Ghostwriter! Received message: %s",
                message
            )
        return gw_message

    async def _create_entry(self, message: dict) -> None:
        """
        Create an entry for a Mythic task in Ghostwriter's ``OplogEntry`` model. Uses the
        ``insert_query`` template and the operation name ``InsertMythicSyncLog``.

        **Parameters**

        ``message``
            Dictionary produced by ``_mythic_task_to_ghostwriter_message()`` or ``_mythic_callback_to_ghostwriter_message()``
        """
        entry_id = ""
        gw_message = {}
        if "agent_task_id" in message:
            entry_id = message["agent_task_id"]
            mythic_sync_log.debug(f"Adding task: {message['agent_task_id']}")
            gw_message = await self._mythic_task_to_ghostwriter_message(message)
        elif "agent_callback_id" in message:
            entry_id = message["agent_callback_id"]
            mythic_sync_log.debug(f"Adding callback: {message['agent_callback_id']}")
            gw_message = await self._mythic_callback_to_ghostwriter_message(message)
        else:
            mythic_sync_log.error(
                "Failed to create an entry for task, no `agent_task_id` or `agent_callback_id` found! Message "
                "contents: %s", message
            )

        if entry_id:
            result = None
            try:
                result = await self._execute_query(self.insert_query, gw_message)
                if result and "insert_oplogEntry" in result:
                    # JSON response example: `{'data': {'insert_oplogEntry': {'returning': [{'id': 192}]}}}`
                    rconn.set(entry_id, result["insert_oplogEntry"]["returning"][0]["id"])
                else:
                    mythic_sync_log.info(
                        "Did not receive a response with data from Ghostwriter's GraphQL API! Response: %s",
                        result
                    )
            except Exception:
                mythic_sync_log.exception(
                    "Encountered an exception while trying to create a new log entry! Response from Ghostwriter: %s",
                    result,
                )
                await self._post_error_notification()

    async def _update_entry(self, message: dict, entry_id: str) -> None:
        """
        Update an existing Ghostwriter ``OplogEntry`` entry for a task with more details from Mythic.
        Uses the ``update_query`` template and the operation name ``UpdateMythicSyncLog``.

        **Parameters**

        ``message``
            Dictionary produced by ``_mythic_task_to_ghostwriter_message()``
        ``entry_id``
            The ID of the log entry to be updated
        """
        mythic_sync_log.debug(f"Updating task: {message['agent_task_id']} - {message['id']} : {entry_id}")
        gw_message = await self._mythic_task_to_ghostwriter_message(message)
        gw_message["id"] = entry_id
        try:
            result = await self._execute_query(self.update_query, gw_message)
            if not result or "update_oplogEntry" not in result:
                mythic_sync_log.info(
                    "Did not receive a response with data from Ghostwriter's GraphQL API! Response: %s",
                    result
                )
        except Exception:
            mythic_sync_log.exception("Exception encountered while trying to update task log entry in Ghostwriter!")

    async def handle_task(self) -> None:
        """
        Start a subscription for Mythic tasks and handle them. Send new tasks to Ghostwriter
        with ``_create_entry()`` or send updates for existing tasks with ``_update_entry()``.
        """
        custom_return_attributes = """
        agent_task_id
        id
        display_id
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
            display_id
            user
            payload {
                payloadtype {
                    name
                }
            }
        }
        """
        mythic_sync_log.info("Starting subscription for tasks")
        async for data in mythic.subscribe_all_tasks_and_updates(
                mythic=self.mythic_instance, custom_return_attributes=custom_return_attributes,
        ):
            try:
                entry_id = rconn.get(data["agent_task_id"])
            except Exception:
                mythic_sync_log.exception(
                    "Encountered an exception while connecting to Redis to fetch data! Data returned by Mythic: %s",
                    data
                )
                await self._post_error_notification()
                continue
            if entry_id is not None:
                await self._update_entry(data, entry_id.decode())
            else:
                await self._create_entry(data)

    async def handle_callback(self) -> None:
        """
        Start a subscription for Mythic agent callbacks and send all new callbacks to Ghostwriter
        with ``_create_entry()``.
        """
        custom_return_attributes = """
        agent_callback_id
        init_callback
        integrity_level
        description
        host
        id
        display_id
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
                name
            }
        }
        """
        mythic_sync_log.info("Starting subscription for callbacks")
        async for data in mythic.subscribe_new_callbacks(
                mythic=self.mythic_instance, custom_return_attributes=custom_return_attributes, batch_size=1
        ):
            await self._create_entry(data[0])

    async def _wait_for_service(self) -> None:
        """Wait for an HTTP session to be established with Mythic."""
        while True:
            mythic_sync_log.info("Attempting to connect to %s", self.MYTHIC_URL)
            async with aiohttp.ClientSession() as session:
                async with session.get(self.MYTHIC_URL, ssl=False) as resp:
                    if resp.status != 200:
                        mythic_sync_log.warning(
                            "Expected 200 OK and received HTTP code %s while trying to connect to Mythic, trying again in %s seconds...",
                            resp.status, self.wait_timeout
                        )
                        await asyncio.sleep(self.wait_timeout)
                        continue
            return

    async def _wait_for_redis(self) -> None:
        """Wait for a connection to be established with Mythic's Redis container."""
        global rconn
        while True:
            try:
                rconn = redis.Redis(host=self.REDIS_HOSTNAME, port=self.REDIS_PORT, db=1)
                return
            except Exception:
                mythic_sync_log.exception(
                    "Encountered an exception while trying to connect to Redis, %s:%s, trying again in %s seconds...",
                    self.REDIS_HOSTNAME, self.REDIS_PORT, self.wait_timeout
                )
                await self._post_error_notification()
                await asyncio.sleep(self.wait_timeout)
                continue

    async def __wait_for_authentication(self) -> mythic_classes.Mythic:
        """Wait for authentication with Mythic to complete."""
        while True:
            # If ``MYTHIC_API_KEY`` is not set in the environment, then authenticate with user credentials
            if len(self.MYTHIC_API_KEY) == 0:
                mythic_sync_log.info(
                    "Authenticating to Mythic, https://%s:%s, with username and password",
                    self.MYTHIC_IP, self.MYTHIC_PORT
                )
                try:
                    mythic_instance = await mythic.login(
                        username=self.MYTHIC_USERNAME,
                        password=self.MYTHIC_PASSWORD,
                        server_ip=self.MYTHIC_IP,
                        server_port=self.MYTHIC_PORT,
                        ssl=True,
                        timeout=-1)
                except Exception:
                    mythic_sync_log.exception(
                        "Encountered an exception while trying to authenticate to Mythic, trying again in %s seconds...",
                        self.wait_timeout
                    )
                    await self._post_error_notification(
                        message="Mythic Sync encountered an exception while trying to authenticate to Mythic"
                    )
                    await asyncio.sleep(self.wait_timeout)
                    continue
                try:
                    await mythic.get_me(mythic=mythic_instance)
                except Exception:
                    mythic_sync_log.exception(
                        "Encountered an exception while trying to authenticate to Mythic, trying again in %s seconds...",
                        self.wait_timeout
                    )
                    await self._post_error_notification(
                        message="Mythic Sync encountered an exception while trying to authenticate to Mythic")
                    await asyncio.sleep(self.wait_timeout)
                    continue
            elif self.MYTHIC_USERNAME == "" and self.MYTHIC_PASSWORD == "":
                mythic_sync_log.error("You must supply a MYTHIC_USERNAME and MYTHIC_PASSWORD")
                sys.exit(1)
            else:
                mythic_sync_log.info(
                    "Authenticating to Mythic, https://%s:%s, with a specified API Key",
                    self.MYTHIC_IP, self.MYTHIC_PORT
                )
                try:
                    mythic_instance = await mythic.login(
                        apitoken=self.MYTHIC_API_KEY,
                        server_ip=self.MYTHIC_IP,
                        server_port=self.MYTHIC_PORT,
                        ssl=True)
                    await mythic.get_me(mythic=mythic_instance)
                except Exception:
                    mythic_sync_log.exception(
                        "Failed to authenticate with the Mythic API token, trying again in %s seconds...",
                        self.wait_timeout
                    )
                    await self._post_error_notification(
                        message="Mythic Sync encountered an exception while trying to authenticate to Mythic"
                    )
                    await asyncio.sleep(self.wait_timeout)
                    continue

            return mythic_instance


async def scripting():
    while True:
        mythic_sync = MythicSync()
        await mythic_sync.initialize()
        try:
            _ = await asyncio.gather(
                mythic_sync.handle_task(),
                mythic_sync.handle_callback(),
            )
        except Exception:
            mythic_sync_log.exception(
                "Encountered an exception while subscribing to tasks and responses, restarting..."
            )

asyncio.run(scripting())
