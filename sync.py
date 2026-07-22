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

    # Polling interval for independently retried tag updates
    tag_retry_poll_interval = 5
    legacy_tag_retry_data_key = "mythic_sync:pending_tag_updates:data"
    legacy_tag_retry_schedule_key = "mythic_sync:pending_tag_updates:schedule"

    # Variables which identify a failed query without exposing commands or other sensitive content
    diagnostic_variable_names = {
        "entry_identifier",
        "id",
        "oplog",
        "oplog_entry_id",
        "oplogId",
    }

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
        mutation InitializeMythicSync (
            $oplogId: bigint!, $description: String!, $server: String!, $entry_identifier: String!,
            $extraFields: jsonb!
        ) {
            insert_oplogEntry(objects: {
                oplog: $oplogId,
                description: $description,
                sourceIp: $server,
                tool: "Mythic",
                entryIdentifier: $entry_identifier,
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
    REDIS_URL = os.environ.get("REDIS_URL") or ""
    REDIS_HOSTNAME = os.environ.get("REDIS_HOSTNAME", "127.0.0.1")
    REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
    REDIS_DB = int(os.environ.get("REDIS_DB", "1"))

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
    last_error_delta = timedelta(minutes=30)
    session = None
    client = None
    transport = AIOHTTPTransport(url=GRAPHQL_URL, timeout=10, headers=headers)

    def __init__(self):
        self._notification_timestamps = {}
        self.redis_namespace = f"mythic_sync:{self.GHOSTWRITER_OPLOG_ID}:{self.MYTHIC_IP}"
        self.tag_retry_data_key = f"{self.redis_namespace}:pending_tag_updates:data"
        self.tag_retry_schedule_key = f"{self.redis_namespace}:pending_tag_updates:schedule"
        self.tag_retry_dead_letter_key = f"{self.redis_namespace}:pending_tag_updates:dead_letter"

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

    async def _get_sorted_ips(self, ip: object) -> str:
        """Normalize a Mythic IP value into a sorted IPv4/IPv6 string."""
        if not ip:
            return ""

        source_ips = ip
        if isinstance(ip, str):
            try:
                source_ips = json.loads(ip)
            except json.JSONDecodeError:
                source_ips = [ip]
        if isinstance(source_ips, str):
            source_ips = [source_ips]
        if not isinstance(source_ips, (list, tuple, set)):
            raise ValueError(f"Unsupported Mythic IP value: {source_ips!r}")

        addresses = set()
        omitted_addresses = 0
        for source_ip in source_ips:
            source_ip = str(source_ip).strip()
            if not source_ip:
                continue
            try:
                address = ipaddress.ip_address(source_ip.split("/", 1)[0])
                if (
                        address.is_loopback
                        or address.is_unspecified
                        or address.is_multicast
                        or (address.version == 6 and address.is_link_local)
                ):
                    omitted_addresses += 1
                    continue
                addresses.add(address)
            except ValueError:
                mythic_sync_log.warning("Ignoring invalid IP address reported by Mythic: %r", source_ip)

        if omitted_addresses:
            mythic_sync_log.debug(
                "Omitted %s loopback, unspecified, multicast, or IPv6 link-local address(es) reported by Mythic",
                omitted_addresses,
            )

        return ", ".join(
            str(address) for address in sorted(addresses, key=lambda address: (address.version, int(address)))
        )

    @staticmethod
    def _parse_mythic_timestamp(value: str) -> str:
        """Normalize Mythic timestamps while retaining any timezone information."""
        if not value:
            return ""
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        return datetime.fromisoformat(normalized).isoformat()

    def _redis_entry_key(self, entry_identifier: str) -> str:
        """Return a Redis mapping key scoped to this Mythic server and Ghostwriter oplog."""
        return f"{self.redis_namespace}:entry:{entry_identifier}"

    def _get_cached_entry_id(self, entry_identifier: str):
        """Read a scoped entry mapping, migrating the legacy raw key when encountered."""
        scoped_key = self._redis_entry_key(entry_identifier)
        entry_id = self.rconn.get(scoped_key)
        if entry_id is not None:
            return entry_id

        legacy_entry_id = self.rconn.get(entry_identifier)
        if legacy_entry_id is not None:
            pipeline = self.rconn.pipeline(transaction=True)
            pipeline.set(scoped_key, legacy_entry_id)
            pipeline.delete(entry_identifier)
            pipeline.execute()
            mythic_sync_log.info("Migrated legacy Redis mapping for %s", entry_identifier)
        return legacy_entry_id

    def _set_cached_entry_id(self, entry_identifier: str, ghostwriter_entry_id: str) -> None:
        self.rconn.set(self._redis_entry_key(entry_identifier), ghostwriter_entry_id)

    def _delete_cached_entry_id(self, entry_identifier: str) -> None:
        pipeline = self.rconn.pipeline(transaction=True)
        pipeline.delete(self._redis_entry_key(entry_identifier))
        pipeline.delete(entry_identifier)
        pipeline.execute()

    def _migrate_legacy_tag_queue(self) -> int:
        """Move pre-namespace pending tag jobs into this deployment's scoped queue."""
        legacy_payloads = self.rconn.hgetall(self.legacy_tag_retry_data_key)
        if not legacy_payloads:
            return 0

        legacy_schedule = dict(
            self.rconn.zrange(self.legacy_tag_retry_schedule_key, 0, -1, withscores=True)
        )
        pipeline = self.rconn.pipeline(transaction=True)
        for entry_id, payload in legacy_payloads.items():
            pipeline.hset(self.tag_retry_data_key, entry_id, payload)
            pipeline.zadd(
                self.tag_retry_schedule_key,
                {entry_id: legacy_schedule.get(entry_id, time.time())},
            )
        pipeline.delete(self.legacy_tag_retry_data_key)
        pipeline.delete(self.legacy_tag_retry_schedule_key)
        pipeline.execute()
        mythic_sync_log.info("Migrated %s legacy pending tag update(s)", len(legacy_payloads))
        return len(legacy_payloads)

    @staticmethod
    def _get_query_context(query: DocumentNode, variable_values: dict = None) -> tuple[str, str]:
        """Return a GraphQL operation name and serialized representation of its variables."""
        operation_name = "unnamed operation"
        for definition in query.definitions:
            if definition.name is not None:
                operation_name = definition.name.value
                break

        diagnostic_variables = {
            key: value if key in MythicSync.diagnostic_variable_names else "<redacted>"
            for key, value in (variable_values or {}).items()
        }
        variables = json.dumps(diagnostic_variables, default=str, sort_keys=True)
        return operation_name, variables

    @staticmethod
    def _get_transport_error_code(exc: TransportQueryError) -> str | None:
        """Return the first GraphQL extension code attached to a transport error."""
        for error in exc.errors or []:
            if isinstance(error, dict):
                code = error.get("extensions", {}).get("code")
                if code:
                    return code
        return None

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
            retry_model_not_found: bool = True,
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
                code = self._get_transport_error_code(exc)
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
                if not retry or (code == "ModelDoesNotExist" and not retry_model_not_found):
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
            except asyncio.CancelledError:
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
            expiry_value = whoami["whoami"]["expires"]
            expiry_value = expiry_value[:-1] + "+00:00" if expiry_value.endswith("Z") else expiry_value
            expiry = datetime.fromisoformat(expiry_value)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
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
        """Send one idempotent initialization entry to Ghostwriter's oplog."""
        mythic_sync_log.info("Sending the initial Ghostwriter log entry")
        entry_identifier = f"mythic_sync:initial:{self.MYTHIC_IP}"
        existing_entry = await self._execute_query(
            self.entry_identifier_query,
            {
                "oplog": self.GHOSTWRITER_OPLOG_ID,
                "entry_identifier": entry_identifier,
            },
        )
        if existing_entry.get("oplogEntry", []):
            mythic_sync_log.info(
                "Ghostwriter initialization entry already exists for Mythic server %s",
                self.MYTHIC_IP,
            )
        else:
            variable_values = {
                "oplogId": self.GHOSTWRITER_OPLOG_ID,
                "description": f"Initial entry from mythic_sync at: {self.MYTHIC_IP}. If you're seeing this then "
                               "oplog syncing is working for this C2 server!",
                "server": f"Mythic Server ({self.MYTHIC_IP})",
                "entry_identifier": entry_identifier,
                "extraFields": {},
            }
            await self._execute_query(self.initial_query, variable_values)
        await mythic.send_event_log_message(
            mythic=self.mythic_instance,
            message="Mythic Sync successfully confirmed its initialization entry in Ghostwriter",
            source="mythic_sync",
            level="info"
        )
        return

    async def _post_error_notification(self, message: str = None, source: str = None) -> None:
        """Send an error notification to Mythic's notification center."""
        if self.mythic_instance is None:
            mythic_sync_log.debug(
                "Skipping Mythic error notification because Mythic authentication is not established"
            )
            return
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
        except asyncio.CancelledError:
            raise
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
        callback = message["callback"]
        hostname = callback["host"]
        source_ip = await self._get_sorted_ips(callback.get("ip"))
        command = message.get("command")
        command_name = command["cmd"] if command is not None else message["command_name"]

        gw_message = {
            "command": f"{command_name} {message.get('original_params', '')}".rstrip(),
            "comments": message.get("comment") or "",
            "operatorName": (message.get("operator") or {}).get("username", ""),
            "oplog": self.GHOSTWRITER_OPLOG_ID,
            "sourceIp": f"{hostname} ({source_ip})" if source_ip else hostname,
            "description": f"PID: {callback['pid']}, Callback: {callback['display_id']}",
            "userContext": callback["user"],
            "tool": callback["payload"]["payloadtype"]["name"],
            "entry_identifier": message["agent_task_id"],
            "tags": [f"mythic:{tag['tagtype']['name']}" for tag in message.get("tags", [])],
            "extraFields": {},
        }
        if message.get("status_timestamp_submitted"):
            gw_message["startDate"] = self._parse_mythic_timestamp(message["status_timestamp_submitted"])
        if message.get("status_timestamp_processed"):
            gw_message["endDate"] = self._parse_mythic_timestamp(message["status_timestamp_processed"])
        return gw_message

    async def _mythic_callback_to_ghostwriter_message(self, message: dict) -> dict:
        """
        Converts a Mythic callback event to the fields expected by Ghostwriter's GraphQL API and ``OplogEntry`` model.

        **Parameters**

        ``message``
            The message dictionary to be converted
        """
        source_ip = await self._get_sorted_ips(message.get("ip"))
        integrity_level = message.get("integrity_level")
        integrity = self.integrity_levels.get(integrity_level, f"Unknown ({integrity_level})")
        opsys = (message.get("os") or "").replace("\n", ", ")
        hostname = message["host"]
        return {
            "startDate": self._parse_mythic_timestamp(message["init_callback"]),
            "comments": f"New Callback {message['display_id']}",
            "description": (
                f"Computer: {hostname}, Integrity Level: {integrity}, Process: {message['process_name']}, "
                f"PID: {message['pid']}, User: {message['user']}, Domain: {message['domain']}, OS: {opsys}"
            ),
            "operatorName": (message.get("operator") or {}).get("username", ""),
            "sourceIp": f"{hostname} ({source_ip})" if source_ip else hostname,
            "userContext": message["user"],
            "tool": message["payload"]["payloadtype"]["name"],
            "oplog": self.GHOSTWRITER_OPLOG_ID,
            "entry_identifier": message["agent_callback_id"],
            "extraFields": {},
            "command": "",
        }

    def _queue_task_tags(self, tags: list, entry_id: str, entry_identifier: str) -> None:
        """Persist the latest desired Mythic tags for asynchronous processing."""
        entry_id = str(entry_id)
        payload = json.dumps(
            {
                "attempt": 0,
                "entry_id": entry_id,
                "entry_identifier": entry_identifier,
                "tags": tags,
            },
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

    def _remove_pending_tag_update(self, entry_id: str, expected_payload: bytes | str) -> bool:
        """Remove a pending job only when it has not been replaced by newer tag data."""
        if self.rconn.hget(self.tag_retry_data_key, entry_id) != expected_payload:
            return False
        pipeline = self.rconn.pipeline(transaction=True)
        pipeline.hdel(self.tag_retry_data_key, entry_id)
        pipeline.zrem(self.tag_retry_schedule_key, entry_id)
        pipeline.execute()
        return True

    def _dead_letter_pending_tag_update(
            self,
            entry_id: str,
            payload: dict,
            expected_payload: bytes | str,
            reason: str,
    ) -> bool:
        """Retain an irrecoverable tag job for diagnosis while removing it from active retries."""
        if self.rconn.hget(self.tag_retry_data_key, entry_id) != expected_payload:
            return False
        dead_letter = dict(payload)
        dead_letter["dead_lettered_at"] = datetime.now(timezone.utc).isoformat()
        dead_letter["reason"] = reason
        pipeline = self.rconn.pipeline(transaction=True)
        pipeline.hdel(self.tag_retry_data_key, entry_id)
        pipeline.zrem(self.tag_retry_schedule_key, entry_id)
        pipeline.hset(
            self.tag_retry_dead_letter_key,
            entry_id,
            json.dumps(dead_letter, sort_keys=True),
        )
        pipeline.execute()
        return True

    def _reschedule_pending_tag_update(
            self,
            entry_id: str,
            payload: dict,
            expected_payload: bytes | str,
    ) -> None:
        """Apply capped exponential backoff to a pending tag job."""
        if self.rconn.hget(self.tag_retry_data_key, entry_id) != expected_payload:
            return
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

    async def _reconcile_pending_tag_update(
            self,
            stale_entry_id: str,
            payload: dict,
            expected_payload: bytes | str,
    ) -> None:
        """Move a stale tag job to the current entry or retire it when the entry was deleted."""
        entry_identifier = payload.get("entry_identifier")
        if not entry_identifier:
            if self._dead_letter_pending_tag_update(
                    stale_entry_id,
                    payload,
                    expected_payload,
                    "legacy job has no entry identifier",
            ):
                mythic_sync_log.error(
                    "Dead-lettered legacy tag job for missing Ghostwriter entry %s because it has no entry identifier",
                    stale_entry_id,
                )
                await self._post_error_notification(source="mythic_sync_orphaned_tag_update")
            return

        query_result = await self._execute_query(
            self.entry_identifier_query,
            {
                "oplog": self.GHOSTWRITER_OPLOG_ID,
                "entry_identifier": entry_identifier,
            },
            retry=False,
            retry_model_not_found=False,
        )
        existing_entries = query_result.get("oplogEntry", []) if query_result else []
        if not existing_entries:
            if self._dead_letter_pending_tag_update(
                    stale_entry_id,
                    payload,
                    expected_payload,
                    "entry identifier no longer resolves in Ghostwriter",
            ):
                mythic_sync_log.error(
                    "Dead-lettered tag job for deleted or inaccessible Ghostwriter entry %s (entryIdentifier %s)",
                    stale_entry_id,
                    entry_identifier,
                )
                await self._post_error_notification(
                    message=(
                        "Mythic Sync stopped retrying a tag update for Ghostwriter entry "
                        f"{stale_entry_id} (entryIdentifier {entry_identifier}) because the entry no longer "
                        "resolves. The job remains in the Redis dead-letter hash for diagnosis."
                    ),
                    source="mythic_sync_orphaned_tag_update",
                )
            return

        current_entry_id = str(existing_entries[0]["id"])
        if current_entry_id == stale_entry_id:
            raise RuntimeError(
                "Ghostwriter resolved entryIdentifier %s to entry %s, but its tag API reported that entry missing"
                % (entry_identifier, stale_entry_id)
            )
        if self.rconn.hget(self.tag_retry_data_key, stale_entry_id) != expected_payload:
            return

        payload["attempt"] = 0
        payload["entry_id"] = current_entry_id
        pipeline = self.rconn.pipeline(transaction=True)
        pipeline.hdel(self.tag_retry_data_key, stale_entry_id)
        pipeline.zrem(self.tag_retry_schedule_key, stale_entry_id)
        pipeline.hset(self.tag_retry_data_key, current_entry_id, json.dumps(payload, sort_keys=True))
        pipeline.zadd(self.tag_retry_schedule_key, {current_entry_id: time.time()})
        pipeline.execute()
        self._set_cached_entry_id(entry_identifier, current_entry_id)
        mythic_sync_log.info(
            "Moved pending tag update from stale Ghostwriter entry %s to entry %s",
            stale_entry_id,
            current_entry_id,
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
        except TransportQueryError as exc:
            if self._get_transport_error_code(exc) == "ModelDoesNotExist":
                try:
                    await self._reconcile_pending_tag_update(entry_id, payload, payload_raw)
                    return
                except asyncio.CancelledError:
                    raise
                except Exception:
                    mythic_sync_log.exception(
                        "Failed to reconcile missing Ghostwriter entry %s for a pending tag update",
                        entry_id,
                    )
            self._reschedule_pending_tag_update(entry_id, payload, payload_raw)
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            self._reschedule_pending_tag_update(entry_id, payload, payload_raw)
            return

        self._remove_pending_tag_update(entry_id, payload_raw)

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
            except asyncio.CancelledError:
                raise
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
        try:
            if "agent_task_id" in message:
                entry_id = message["agent_task_id"]
                mythic_sync_log.debug(f"Adding task: {message['agent_task_id']}")
                gw_message = await self._mythic_task_to_ghostwriter_message(message)
            elif "agent_callback_id" in message:
                entry_id = message["agent_callback_id"]
                mythic_sync_log.debug(f"Adding callback: {message['agent_callback_id']}")
                gw_message = await self._mythic_callback_to_ghostwriter_message(message)
            else:
                raise ValueError(
                    "Message has no `agent_task_id` or `agent_callback_id`; received keys: "
                    f"{sorted(message)}"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            mythic_sync_log.exception("Failed to convert Mythic event %s for Ghostwriter", entry_id or "unknown")
            await self._post_error_notification(source="mythic_sync_conversion")
            raise
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
                    self._set_cached_entry_id(entry_id, ghostwriter_entry_id)
                    self._queue_task_tags(tags, ghostwriter_entry_id, gw_message["entry_identifier"])
                    return
                result = await self._execute_query(self.insert_query, gw_message)
                ghostwriter_entry_id = self._get_returning_entry_id(result, "insert_oplogEntry")
                if ghostwriter_entry_id:
                    # JSON response example: `{'data': {'insert_oplogEntry': {'returning': [{'id': 192}]}}}`
                    self._set_cached_entry_id(entry_id, ghostwriter_entry_id)
                    self._queue_task_tags(tags, ghostwriter_entry_id, gw_message["entry_identifier"])
                else:
                    raise RuntimeError(
                        "Ghostwriter did not return an inserted oplog entry ID. Response: %s" %
                        result
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                mythic_sync_log.exception(
                    "Encountered an exception while trying to create a new log entry! Response from Ghostwriter: %s",
                    result,
                )
                await self._post_error_notification()
                raise

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
        try:
            gw_message = await self._mythic_task_to_ghostwriter_message(message)
        except asyncio.CancelledError:
            raise
        except Exception:
            mythic_sync_log.exception(
                "Failed to convert Mythic task %s for a Ghostwriter update",
                message["agent_task_id"],
            )
            await self._post_error_notification(source="mythic_sync_conversion")
            raise
        gw_message["id"] = entry_id
        tags = gw_message.pop("tags", [])
        try:
            try:
                result = await self._execute_query(
                    self.update_query,
                    gw_message,
                    retry_model_not_found=False,
                )
            except TransportQueryError as exc:
                if self._get_transport_error_code(exc) != "ModelDoesNotExist":
                    raise
                result = {}
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
                self._delete_cached_entry_id(mythic_entry_id)

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

                self._set_cached_entry_id(mythic_entry_id, ghostwriter_entry_id)

            self._queue_task_tags(tags, ghostwriter_entry_id, gw_message["entry_identifier"])
        except asyncio.CancelledError:
            raise
        except Exception:
            mythic_sync_log.exception("Exception encountered while trying to update task log entry in Ghostwriter!")
            await self._post_error_notification(source="mythic_sync_update_entry")
            raise

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
                entry_id = self._get_cached_entry_id(data["agent_task_id"])
            except asyncio.CancelledError:
                raise
            except Exception:
                mythic_sync_log.exception(
                    "Encountered an exception while fetching the Redis mapping for Mythic task %s",
                    data.get("agent_task_id", "unknown"),
                )
                await self._post_error_notification()
                raise
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
            except asyncio.CancelledError:
                raise
            except Exception as e:
                await asyncio.sleep(self.wait_timeout)
                mythic_sync_log.warning("failed to connect to Mythic: %s", e)
                continue
            return

    async def _wait_for_redis(self) -> None:
        """Wait for Redis to accept commands and report the selected durable state."""
        while True:
            try:
                if self.REDIS_URL:
                    self.rconn = redis.Redis.from_url(
                        self.REDIS_URL,
                        socket_connect_timeout=5,
                        socket_timeout=5,
                    )
                    redis_target = "the configured REDIS_URL"
                else:
                    self.rconn = redis.Redis(
                        host=self.REDIS_HOSTNAME,
                        port=self.REDIS_PORT,
                        db=self.REDIS_DB,
                        socket_connect_timeout=5,
                        socket_timeout=5,
                    )
                    redis_target = f"{self.REDIS_HOSTNAME}:{self.REDIS_PORT} database {self.REDIS_DB}"
                self.rconn.ping()
                self._migrate_legacy_tag_queue()
                pending_tags = self.rconn.hlen(self.tag_retry_data_key)
                dead_letter_tags = self.rconn.hlen(self.tag_retry_dead_letter_key)
                mythic_sync_log.info(
                    "Connected to Redis at %s; %s tag update(s) pending, %s dead-lettered",
                    redis_target,
                    pending_tags,
                    dead_letter_tags,
                )
                if not self.REDIS_URL and self.REDIS_HOSTNAME.lower() in {"127.0.0.1", "localhost"}:
                    mythic_sync_log.warning(
                        "Using embedded Redis; mount stable persistent storage at /data before relying on "
                        "queued jobs to survive Mythic service recreation"
                    )
                if dead_letter_tags:
                    mythic_sync_log.warning(
                        "%s tag update(s) require operator review in Redis hash '%s'; inspect with HGETALL",
                        dead_letter_tags,
                        self.tag_retry_dead_letter_key,
                    )
                return
            except asyncio.CancelledError:
                raise
            except Exception:
                mythic_sync_log.exception(
                    "Encountered an exception while trying to connect to Redis at %s, trying again in %s seconds...",
                    "the configured REDIS_URL" if self.REDIS_URL else
                    f"{self.REDIS_HOSTNAME}:{self.REDIS_PORT} database {self.REDIS_DB}",
                    self.wait_timeout,
                )
                await self._post_error_notification()
                await asyncio.sleep(self.wait_timeout)
                continue

    async def __wait_for_authentication(self) -> mythic_classes.Mythic:
        """Wait for authentication with Mythic to complete."""
        while True:
            if self.MYTHIC_API_KEY:
                mythic_sync_log.info(
                    "Authenticating to Mythic, https://%s:%s, with a specified API key",
                    self.MYTHIC_IP,
                    self.MYTHIC_PORT,
                )
                try:
                    mythic_instance = await mythic.login(
                        apitoken=self.MYTHIC_API_KEY,
                        server_ip=self.MYTHIC_IP,
                        server_port=self.MYTHIC_PORT,
                        ssl=True,
                    )
                    await mythic.get_me(mythic=mythic_instance)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    mythic_sync_log.error(
                        "Failed to authenticate with the Mythic API key: %s; trying again in %s seconds...",
                        exc,
                        self.wait_timeout,
                    )
                    await asyncio.sleep(self.wait_timeout)
                    continue
            else:
                if not self.MYTHIC_USERNAME or not self.MYTHIC_PASSWORD:
                    raise RuntimeError(
                        "MYTHIC_API_KEY or both MYTHIC_USERNAME and MYTHIC_PASSWORD must be supplied"
                    )
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
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    mythic_sync_log.error(
                        "Encountered an exception while trying to authenticate to Mythic: %s; trying again in %s "
                        "seconds...",
                        exc,
                        self.wait_timeout
                    )
                    await asyncio.sleep(self.wait_timeout)
                    continue
                try:
                    await mythic.get_me(mythic=mythic_instance)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    mythic_sync_log.error(
                        "Encountered an exception while trying to get user info from Mythic: %s; trying again in "
                        "%s seconds...",
                        exc,
                        self.wait_timeout
                    )
                    await asyncio.sleep(self.wait_timeout)
                    continue

            return mythic_instance


async def scripting():
    mythic_sync = MythicSync()
    while True:
        await mythic_sync.initialize()
        tasks = [
            asyncio.create_task(mythic_sync.handle_task()),
            asyncio.create_task(mythic_sync.handle_callback()),
            asyncio.create_task(mythic_sync.retry_pending_tags()),
        ]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            raise
        except Exception:
            mythic_sync_log.exception(
                "Encountered an exception while subscribing to tasks and responses, restarting..."
            )
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await mythic_sync.client.close_async()

if __name__ == "__main__":
    asyncio.run(scripting())
