# Standard Libraries
import asyncio
import builtins
import ipaddress
import json
import logging
import os
import random
import sys
import time
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

VERSION = "3.1.0"

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
    max_retry_timeout = 300

    # Redis keys and polling interval for independently retried tag updates
    tag_retry_data_key = "mythic_sync:pending_tag_updates:data"
    tag_retry_schedule_key = "mythic_sync:pending_tag_updates:schedule"
    tag_retry_poll_interval = 5

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

    # Query for specific oplog entry
    entry_identifier_query = gql(
        """
        query checkEntryIdentifier($entry_identifier: String!, $oplog: bigint!){
            oplogEntry(where: {oplog: {_eq: $oplog}, entryIdentifier: {_eq: $entry_identifier}}, limit: 1){
                id
            }
        }
        """
    )

    # Query for the first log sent after initialization
    initial_query = gql(
        """
        mutation InitializeMythicSync ($oplogId: bigint!, $description: String!, $server: String!, $extraFields: jsonb!) {
            insert_oplogEntry(objects: {
                oplog: $oplogId,
                description: $description,
                sourceIp: $server,
                tool: "Mythic",
                extraFields: $extraFields
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
            $comments: String, $operatorName: String, $entry_identifier: String!, $extraFields: jsonb!
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
                comments: $comments,
                operatorName: $operatorName,
                entryIdentifier: $entry_identifier
                extraFields: $extraFields
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
            $description: String, $comments: String, $operatorName: String,
            $entry_identifier: String, $extraFields: jsonb
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
                comments: $comments,
                operatorName: $operatorName,
                entryIdentifier: $entry_identifier,
                extraFields: $extraFields
            }) {
                returning { id }
            }
        }
        """
    )

    # Query for tags on oplog entry
    query_oplog_entry_tags = gql(
        """
        query GetOplogEntryTags($oplog_entry_id: bigint!){
            tags(id: $oplog_entry_id, model: "oplog_entry"){
                tags
            }
        }
        """
    )

    # Mutation to create tagged entry
    set_tags_mutation = gql(
        """
        mutation AddTagToOplogEvent($oplog_entry_id: bigint!, $tags: [String!]!){
            setTags(id: $oplog_entry_id, model: "oplog_entry", tags: $tags){
                tags
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
    last_error_timestamp = datetime.utcnow() - timedelta(hours=1)
    last_error_delta = timedelta(minutes=30)
    session = None
    client = None
    transport = AIOHTTPTransport(url=GRAPHQL_URL, timeout=10, headers=headers)

    def __init__(self):
        self._notification_timestamps = {}

    async def initialize(self) -> None:
        """
        Function to initialize necessary connections with Mythic services. This must
        always be run before anything else.
        """
        self.client = Client(transport=self.transport, fetch_schema_from_transport=False, )
        self.session = await self.client.connect_async(reconnecting=True)
        await self._wait_for_redis()
        mythic_sync_log.info("Successfully connected to Redis")

        await self._wait_for_service()
        mythic_sync_log.info("Successfully connected to %s", self.MYTHIC_URL)

        mythic_sync_log.info("Trying to authenticate to Mythic")
        self.mythic_instance = await self.__wait_for_authentication()
        mythic_sync_log.info("Successfully authenticated to Mythic")

        await self._check_token()
        await self._create_initial_entry()

    async def _get_sorted_ips(self, ip: str) -> str:
        source_ips = json.loads(ip)
        # account for CIDR notation (ex: 192.168.0.123/24) in IPs list to make sure we only get the actual IP
        source_ips = [x.split("/")[0] for x in source_ips if x != ""]
        source_ipv4 = []
        for i in range(len(source_ips)):
            new_address = ipaddress.ip_address(source_ips[i])
            if isinstance(new_address, ipaddress.IPv4Address):
                source_ipv4.append(new_address)
        return ", ".join(str(x) for x in sorted(source_ipv4))

    @staticmethod
    def _get_query_context(query: DocumentNode, variable_values: dict = None) -> tuple[str, str]:
        """Return a GraphQL operation name and serialized representation of its variables."""
        operation_name = "unnamed operation"
        for definition in query.definitions:
            if definition.name is not None:
                operation_name = definition.name.value
                break

        variables = json.dumps(variable_values or {}, default=str, sort_keys=True)
        return operation_name, variables

    async def _wait_for_query_retry(self, operation_name: str, retry_delay: float) -> float:
        """Sleep with jitter before a retry and return the next capped base delay."""
        sleep_for = min(
            self.max_retry_timeout,
            random.uniform(retry_delay * 0.8, retry_delay * 1.2),
        )
        mythic_sync_log.warning(
            "Retrying Ghostwriter GraphQL operation '%s' in %.1f seconds",
            operation_name,
            sleep_for,
        )
        await asyncio.sleep(sleep_for)
        return min(self.max_retry_timeout, retry_delay * 2)

    async def _execute_query(
            self,
            query: DocumentNode,
            variable_values: dict = None,
            retry: bool = True,
    ) -> dict:
        """
        Execute a GraphQL query against the Ghostwriter server.

        **Parameters**

        ``query``
            The GraphQL query to execute
        ``variable_values``
            The parameters to pass to the query
        """
        operation_name, variables = self._get_query_context(query, variable_values)
        retry_delay = self.wait_timeout
        while True:
            try:
                result = await self.session.execute(query, variable_values=variable_values)
                mythic_sync_log.debug("Successfully executed query with result: %s", result)
                return result
            except (TimeoutError, builtins.TimeoutError):
                mythic_sync_log.error(
                    "Ghostwriter GraphQL operation '%s' timed out at %s with variables %s",
                    operation_name,
                    self.GHOSTWRITER_URL,
                    variables,
                )
                await self._post_error_notification(
                    f"MythicSync:\nGhostwriter GraphQL operation '{operation_name}' timed out at "
                    f"{self.GHOSTWRITER_URL} with variables {variables}",
                    source=f"mythic_sync_query_{operation_name}",
                )
                if not retry:
                    raise
            except TransportQueryError as exc:
                mythic_sync_log.error(
                    "Ghostwriter GraphQL operation '%s' failed with variables %s: %s",
                    operation_name,
                    variables,
                    exc,
                )
                payload = next(
                    (error for error in (exc.errors or []) if isinstance(error, dict)),
                    {},
                )
                code = payload.get("extensions", {}).get("code")
                if code == "access-denied":
                    message = (
                        f"Access denied for Ghostwriter GraphQL operation '{operation_name}' with variables "
                        f"{variables}. Check that the provided service token is valid and has the required "
                        "permissions."
                    )
                    source = "mythic_sync_access_denied"
                    retry_delay = max(retry_delay, 60)
                elif code == "postgres-error":
                    message = (
                        f"Ghostwriter's database rejected GraphQL operation '{operation_name}' with variables "
                        f"{variables}. Check if your configured log ID ({self.GHOSTWRITER_OPLOG_ID}) is correct."
                    )
                    source = "mythic_sync_reject"
                elif code == "ModelDoesNotExist":
                    message = (
                        "Ghostwriter could not find or authorize the model requested by GraphQL operation "
                        f"'{operation_name}' with variables {variables}. The referenced oplog entry may not "
                        "exist, or the service token may not have permission to access it."
                    )
                    source = "mythic_sync_model_not_found"
                    retry_delay = max(retry_delay, 60)
                else:
                    message = (
                        f"MythicSync:\nGhostwriter GraphQL operation '{operation_name}' failed with variables "
                        f"{variables}: {exc}"
                    )
                    source = f"mythic_sync_query_{operation_name}"
                await self._post_error_notification(message=message, source=source)
                if not retry:
                    raise
            except GraphQLError as exc:
                mythic_sync_log.exception(
                    "Ghostwriter GraphQL operation '%s' failed with variables %s: %s",
                    operation_name,
                    variables,
                    exc,
                )
                await self._post_error_notification(
                    message=f"MythicSync:\nGhostwriter GraphQL operation '{operation_name}' failed with "
                            f"variables {variables}: {exc}",
                    source=f"mythic_sync_query_{operation_name}",
                )
                if not retry:
                    raise
            except Exception as exc:
                mythic_sync_log.exception(
                    "Unexpected failure in Ghostwriter GraphQL operation '%s' with variables %s",
                    operation_name,
                    variables,
                )
                await self._post_error_notification(
                    message=f"MythicSync:\nUnexpected failure in Ghostwriter GraphQL operation "
                            f"'{operation_name}' with variables {variables}: {exc}",
                    source=f"mythic_sync_query_{operation_name}",
                )
                if not retry:
                    raise

            retry_delay = await self._wait_for_query_retry(operation_name, retry_delay)

    async def _check_token(self) -> None:
        """Send a `whoami` query to Ghostwriter to check authentication and token expiration."""
        whoami = await self._execute_query(self.whoami_query)

        # Check if the token will expire within 24 hours
        now = datetime.now(timezone.utc)
        if whoami["whoami"]["expires"] == "Never":
            expiry = "Never"
        else:
            expiry = datetime.fromisoformat(whoami["whoami"]["expires"])
            if expiry - now < timedelta(hours=24):
                mythic_sync_log.debug(f"The provided Ghostwriter API token expires in less than 24 hours ({expiry})!")
                await self._post_error_notification(
                    message=f"The provided Ghostwriter API token expires in less than 24 hours ({expiry})!",
                    source="mythic_sync_token_expiration",
                )
        await mythic.send_event_log_message(
            mythic=self.mythic_instance,
            message=f"Mythic Sync has successfully authenticated to Ghostwriter. Your configured token expires at: {expiry}",
            source="mythic_sync",
            level="info"
        )

    async def _create_initial_entry(self) -> None:
        """Send the initial log entry to Ghostwriter's Oplog."""
        mythic_sync_log.info("Sending the initial Ghostwriter log entry")
        variable_values = {
            "oplogId": self.GHOSTWRITER_OPLOG_ID,
            "description": f"Initial entry from mythic_sync at: {self.MYTHIC_IP}. If you're seeing this then oplog "
                           f"syncing is working for this C2 server!",
            "server": f"Mythic Server ({self.MYTHIC_IP})",
            "extraFields": {}
        }
        await self._execute_query(self.initial_query, variable_values)
        await mythic.send_event_log_message(
            mythic=self.mythic_instance,
            message="Mythic Sync successfully posted its initial log entry to Ghostwriter",
            source="mythic_sync",
            level="info"
        )
        return

    async def _post_error_notification(self, message: str = None, source: str = None) -> None:
        """Send an error notification to Mythic's notification center."""
        if message is None:
            message = "Mythic Sync logged an error and may need attention to continue syncing.\n" \
                      "Run this command to review the issue:\n\n" \
                      "  sudo ./mythic-cli logs mythic_sync"
        notification_source = "mythic_sync" if source is None else source
        now = datetime.now(timezone.utc)
        last_notification = self._notification_timestamps.get(notification_source)
        if last_notification is not None and now - last_notification < self.last_error_delta:
            mythic_sync_log.debug(
                "Suppressing duplicate Mythic notification from '%s': %s",
                notification_source,
                message,
            )
            return

        mythic_sync_log.info("Submitting an error notification to Mythic's notification center: %s", message)
        try:
            await mythic.send_event_log_message(mythic=self.mythic_instance,
                                                message=message,
                                                source=notification_source,
                                                level="warning")
        except Exception:
            mythic_sync_log.exception(
                "Failed to submit Mythic notification from '%s'",
                notification_source,
            )
            return
        self._notification_timestamps[notification_source] = now
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
            if message['command'] is not None:
                gw_message["command"] = f"{message['command']['cmd']} {message['original_params']}"
            else:
                gw_message["command"] = f"{message['command_name']} {message['original_params']}"
            gw_message["comments"] = message["comment"] if message["comment"] is not None else ""
            gw_message["operatorName"] = message["operator"]["username"] if message["operator"] is not None else ""
            gw_message["oplog"] = self.GHOSTWRITER_OPLOG_ID
            hostname = message["callback"]["host"]
            source_ip = await self._get_sorted_ips(message["callback"]["ip"])
            gw_message["sourceIp"] = f"{hostname} ({source_ip})"
            gw_message[
                "description"] = f"PID: {message['callback']['pid']}, Callback: {message['callback']['display_id']}"
            gw_message["userContext"] = message["callback"]["user"]
            gw_message["tool"] = message["callback"]["payload"]["payloadtype"]["name"]
            gw_message['entry_identifier'] = message["agent_task_id"]
            gw_message['tags'] = [f"mythic:{x['tagtype']['name']}" for x in message['tags']]
            gw_message['extraFields'] = {}
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
            gw_message["comments"] = f"New Callback {message['display_id']}"
            integrity = self.integrity_levels[message["integrity_level"]]
            opsys = message['os'].replace("\n", ", ")
            gw_message[
                "description"] = f"Computer: {message['host']}, Integrity Level: {integrity}, Process: {message['process_name']}, PID: {message['pid']}, User: {message['user']}, Domain: {message['domain']}, OS: {opsys}"
            gw_message["operatorName"] = message["operator"]["username"] if message["operator"] is not None else ""
            source_ip = await self._get_sorted_ips(message["ip"])
            gw_message["sourceIp"] = f"{message['host']} ({source_ip})"
            gw_message["userContext"] = message["user"]
            gw_message["tool"] = message["payload"]["payloadtype"]["name"]
            gw_message["oplog"] = self.GHOSTWRITER_OPLOG_ID
            gw_message['entry_identifier'] = message["agent_callback_id"]
            gw_message['extraFields'] = {}
            gw_message["command"] = ""
        except Exception:
            mythic_sync_log.exception(
                "Encountered an exception while processing Mythic's message into a message for Ghostwriter! Received message: %s",
                message
            )
        return gw_message

    def _queue_task_tags(self, tags: list, entry_id: str) -> None:
        """Persist the latest desired Mythic tags for asynchronous processing."""
        entry_id = str(entry_id)
        payload = json.dumps(
            {"attempt": 0, "entry_id": entry_id, "tags": tags},
            sort_keys=True,
        )
        pipeline = self.rconn.pipeline(transaction=True)
        pipeline.hset(self.tag_retry_data_key, entry_id, payload)
        pipeline.zadd(self.tag_retry_schedule_key, {entry_id: time.time()})
        pipeline.execute()

    async def _handle_task_tags(self, tags: list, entry_id: str, retry: bool = False) -> None:
        """Merge Mythic tags into one Ghostwriter oplog entry."""
        current_tags = await self._execute_query(
            self.query_oplog_entry_tags,
            {"oplog_entry_id": entry_id},
            retry=retry,
        )
        updated_tags = []
        for current_tag in current_tags['tags']['tags']:
            if current_tag.startswith("mythic:"):
                if current_tag in tags:
                    updated_tags.append(current_tag)
            else:
                updated_tags.append(current_tag)
        for current_tag in tags:
            if current_tag not in updated_tags:
                updated_tags.append(current_tag)
        await self._execute_query(
            self.set_tags_mutation,
            {"oplog_entry_id": entry_id, "tags": updated_tags},
            retry=retry,
        )

    async def _process_pending_tag_update(self, entry_id: str) -> None:
        """Attempt one queued tag update and reschedule it on any failure."""
        payload_raw = self.rconn.hget(self.tag_retry_data_key, entry_id)
        if payload_raw is None:
            self.rconn.zrem(self.tag_retry_schedule_key, entry_id)
            return

        payload = json.loads(payload_raw)
        try:
            await self._handle_task_tags(payload["tags"], payload["entry_id"], retry=False)
        except Exception:
            current_payload = self.rconn.hget(self.tag_retry_data_key, entry_id)
            if current_payload == payload_raw:
                attempt = payload.get("attempt", 0) + 1
                retry_delay = min(
                    self.max_retry_timeout,
                    self.wait_timeout * (2 ** min(attempt, 10)),
                )
                retry_delay = min(
                    self.max_retry_timeout,
                    random.uniform(retry_delay * 0.8, retry_delay * 1.2),
                )
                payload["attempt"] = attempt
                pipeline = self.rconn.pipeline(transaction=True)
                pipeline.hset(
                    self.tag_retry_data_key,
                    entry_id,
                    json.dumps(payload, sort_keys=True),
                )
                pipeline.zadd(
                    self.tag_retry_schedule_key,
                    {entry_id: time.time() + retry_delay},
                )
                pipeline.execute()
                mythic_sync_log.warning(
                    "Tag update for Ghostwriter oplog entry %s failed; retrying in %.1f seconds",
                    entry_id,
                    retry_delay,
                )
            return

        current_payload = self.rconn.hget(self.tag_retry_data_key, entry_id)
        if current_payload == payload_raw:
            pipeline = self.rconn.pipeline(transaction=True)
            pipeline.hdel(self.tag_retry_data_key, entry_id)
            pipeline.zrem(self.tag_retry_schedule_key, entry_id)
            pipeline.execute()

    async def retry_pending_tags(self) -> None:
        """Continuously process due tag updates without blocking log ingestion."""
        mythic_sync_log.info("Starting pending Ghostwriter tag update worker")
        while True:
            try:
                due_entries = self.rconn.zrangebyscore(
                    self.tag_retry_schedule_key,
                    0,
                    time.time(),
                    start=0,
                    num=1,
                )
                if due_entries:
                    entry_id = due_entries[0]
                    if isinstance(entry_id, bytes):
                        entry_id = entry_id.decode()
                    await self._process_pending_tag_update(str(entry_id))
                    continue
            except Exception:
                mythic_sync_log.exception("Failed while processing pending Ghostwriter tag updates")
                await self._post_error_notification(source="mythic_sync_tag_retry_worker")
            await asyncio.sleep(self.tag_retry_poll_interval)

    @staticmethod
    def _get_returning_entry_id(result: dict, mutation_name: str) -> str:
        """Return the first entry ID from a Ghostwriter mutation response, if present."""
        if not result or mutation_name not in result:
            return ""
        returning = result[mutation_name].get("returning", [])
        if not returning:
            return ""
        return str(returning[0]["id"])

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
        tags = gw_message.pop("tags", [])
        if entry_id != "" and 'entry_identifier' in gw_message:
            result = None
            try:
                query_result = await self._execute_query(self.entry_identifier_query, {
                    "oplog": gw_message["oplog"],
                    "entry_identifier": gw_message['entry_identifier'],
                })
                if query_result and "oplogEntry" in query_result and len(query_result["oplogEntry"]) > 0:
                    ghostwriter_entry_id = str(query_result["oplogEntry"][0]["id"])
                    mythic_sync_log.info(
                        f"Duplicate entry found based on entryIdentifier, {gw_message['entry_identifier']}, not sending")
                    # save off id of oplog entry with this gw_message['entry_identifier'] so we don't try to send it again
                    self.rconn.set(entry_id, ghostwriter_entry_id)
                    self._queue_task_tags(tags, ghostwriter_entry_id)
                    return
                result = await self._execute_query(self.insert_query, gw_message)
                ghostwriter_entry_id = self._get_returning_entry_id(result, "insert_oplogEntry")
                if ghostwriter_entry_id:
                    # JSON response example: `{'data': {'insert_oplogEntry': {'returning': [{'id': 192}]}}}`
                    self.rconn.set(entry_id, ghostwriter_entry_id)
                    self._queue_task_tags(tags, ghostwriter_entry_id)
                else:
                    raise RuntimeError(
                        "Ghostwriter did not return an inserted oplog entry ID. Response: %s" %
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
        tags = gw_message.pop("tags", [])
        try:
            result = await self._execute_query(self.update_query, gw_message)
            ghostwriter_entry_id = self._get_returning_entry_id(result, "update_oplogEntry")
            if not ghostwriter_entry_id:
                mythic_entry_id = message["agent_task_id"]
                stale_entry_id = gw_message.pop("id")
                mythic_sync_log.warning(
                    "Ghostwriter oplog entry %s cached for Mythic task %s no longer exists or is inaccessible; "
                    "reconciling with entryIdentifier %s",
                    stale_entry_id,
                    mythic_entry_id,
                    gw_message["entry_identifier"],
                )
                self.rconn.delete(mythic_entry_id)

                query_result = await self._execute_query(
                    self.entry_identifier_query,
                    {
                        "oplog": gw_message["oplog"],
                        "entry_identifier": gw_message["entry_identifier"],
                    },
                )
                existing_entries = query_result.get("oplogEntry", []) if query_result else []
                if existing_entries:
                    ghostwriter_entry_id = str(existing_entries[0]["id"])
                    gw_message["id"] = ghostwriter_entry_id
                    retry_result = await self._execute_query(self.update_query, gw_message)
                    updated_entry_id = self._get_returning_entry_id(retry_result, "update_oplogEntry")
                    if not updated_entry_id:
                        raise RuntimeError(
                            "Ghostwriter found oplog entry %s by entryIdentifier but did not update it. "
                            "Response: %s" % (ghostwriter_entry_id, retry_result)
                        )
                    ghostwriter_entry_id = updated_entry_id
                else:
                    insert_result = await self._execute_query(self.insert_query, gw_message)
                    ghostwriter_entry_id = self._get_returning_entry_id(
                        insert_result,
                        "insert_oplogEntry",
                    )
                    if not ghostwriter_entry_id:
                        raise RuntimeError(
                            "Ghostwriter did not return an ID while recreating stale oplog entry %s. "
                            "Response: %s" % (stale_entry_id, insert_result)
                        )

                self.rconn.set(mythic_entry_id, ghostwriter_entry_id)

            self._queue_task_tags(tags, ghostwriter_entry_id)
        except Exception:
            mythic_sync_log.exception("Exception encountered while trying to update task log entry in Ghostwriter!")
            await self._post_error_notification(source="mythic_sync_update_entry")

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
        command {
            cmd
        }
        operator {
            username
        }
        tags {
            tagtype {
                name
            }
        }
        callback {
            host
            ip
            pid
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
                entry_id = self.rconn.get(data["agent_task_id"])
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
        domain
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
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.MYTHIC_URL, ssl=False) as resp:
                        if resp.status != 200:
                            mythic_sync_log.warning(
                                "Expected 200 OK and received HTTP code %s while trying to connect to Mythic, trying again in %s seconds...",
                                resp.status, self.wait_timeout
                            )
                            await asyncio.sleep(self.wait_timeout)
                            continue
            except Exception as e:
                await asyncio.sleep(self.wait_timeout)
                mythic_sync_log.warning("failed to connect to Mythic: %s", e)
                continue
            return

    async def _wait_for_redis(self) -> None:
        """Wait for a connection to be established with Mythic's Redis container."""
        while True:
            try:
                self.rconn = redis.Redis(host=self.REDIS_HOSTNAME, port=self.REDIS_PORT, db=1)
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
                except Exception as e:
                    mythic_sync_log.error(
                        "Encountered an exception while trying to authenticate to Mythic, trying again in %s seconds...",
                        self.wait_timeout
                    )
                    await asyncio.sleep(self.wait_timeout)
                    continue
                try:
                    await mythic.get_me(mythic=mythic_instance)
                except Exception as e:
                    mythic_sync_log.error(
                        "Encountered an exception while trying to get user info from Mythic, trying again in %s seconds...",
                        self.wait_timeout
                    )
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
                except Exception as e:
                    mythic_sync_log.error(
                        "Failed to authenticate with the Mythic API token, trying again in %s seconds...",
                        self.wait_timeout
                    )
                    await asyncio.sleep(self.wait_timeout)
                    continue

            return mythic_instance


async def scripting():
    mythic_sync = MythicSync()
    while True:
        await mythic_sync.initialize()
        try:
            _ = await asyncio.gather(
                mythic_sync.handle_task(),
                mythic_sync.handle_callback(),
                mythic_sync.retry_pending_tags(),
            )
        except Exception:
            mythic_sync_log.exception(
                "Encountered an exception while subscribing to tasks and responses, restarting..."
            )
        finally:
            await mythic_sync.client.close_async()

if __name__ == "__main__":
    asyncio.run(scripting())
