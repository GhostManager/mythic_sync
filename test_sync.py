import os
import unittest
from unittest.mock import AsyncMock, patch


os.environ.setdefault("MYTHIC_IP", "127.0.0.1")
os.environ.setdefault("MYTHIC_PORT", "7443")
os.environ.setdefault("GHOSTWRITER_API_KEY", "gwst_test")
os.environ.setdefault("GHOSTWRITER_URL", "http://ghostwriter")
os.environ.setdefault("GHOSTWRITER_OPLOG_ID", "12")

from sync import MythicSync  # noqa: E402


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.hashes = {}
        self.sorted_sets = {}

    @staticmethod
    def _bytes(value):
        if value is None or isinstance(value, bytes):
            return value
        return str(value).encode()

    @staticmethod
    def _key(value):
        return value.decode() if isinstance(value, bytes) else str(value)

    def set(self, key, value):
        self.values[self._key(key)] = self._bytes(value)

    def get(self, key):
        return self.values.get(self._key(key))

    def delete(self, key):
        key = self._key(key)
        self.values.pop(key, None)
        self.hashes.pop(key, None)
        self.sorted_sets.pop(key, None)

    def pipeline(self, transaction=True):
        return self

    def execute(self):
        return []

    def ping(self):
        return True

    def hset(self, name, key, value):
        self.hashes.setdefault(name, {})[self._key(key)] = self._bytes(value)

    def hget(self, name, key):
        return self.hashes.get(name, {}).get(self._key(key))

    def hgetall(self, name):
        return {
            key.encode(): value
            for key, value in self.hashes.get(name, {}).items()
        }

    def hlen(self, name):
        return len(self.hashes.get(name, {}))

    def hdel(self, name, key):
        self.hashes.get(name, {}).pop(self._key(key), None)

    def zadd(self, name, mapping):
        target = self.sorted_sets.setdefault(name, {})
        for key, score in mapping.items():
            target[self._key(key)] = score

    def zrem(self, name, key):
        self.sorted_sets.get(name, {}).pop(self._key(key), None)

    def zrangebyscore(self, name, minimum, maximum, start=0, num=None):
        matches = [
            key.encode()
            for key, score in sorted(self.sorted_sets.get(name, {}).items(), key=lambda item: item[1])
            if minimum <= score <= maximum
        ]
        return matches[start:] if num is None else matches[start:start + num]

    def zrange(self, name, start, end, withscores=False):
        matches = sorted(self.sorted_sets.get(name, {}).items(), key=lambda item: item[1])
        if end >= 0:
            matches = matches[start:end + 1]
        else:
            matches = matches[start:]
        if withscores:
            return [(key.encode(), score) for key, score in matches]
        return [key.encode() for key, _ in matches]


class MythicSyncTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.sync = MythicSync()
        self.sync.rconn = FakeRedis()
        self.sync._post_error_notification = AsyncMock()

    async def test_get_sorted_ips_returns_plain_sorted_string(self):
        result = await self.sync._get_sorted_ips(
            '["10.0.0.20/24", "", "invalid", "10.0.0.3", "2001:db8::1"]'
        )

        self.assertEqual(result, "10.0.0.3, 10.0.0.20, 2001:db8::1")

    async def test_get_sorted_ips_accepts_a_single_plain_ip(self):
        self.assertEqual(await self.sync._get_sorted_ips("10.0.0.1/24"), "10.0.0.1")

    def test_parse_mythic_timestamp_accepts_common_variants(self):
        self.assertEqual(
            self.sync._parse_mythic_timestamp("2026-07-18T12:34:56Z"),
            "2026-07-18T12:34:56+00:00",
        )
        self.assertEqual(
            self.sync._parse_mythic_timestamp("2026-07-18T12:34:56.123456"),
            "2026-07-18T12:34:56.123456",
        )

    def test_query_context_redacts_sensitive_values(self):
        operation, variables = self.sync._get_query_context(self.sync.update_query, {
            "id": "42",
            "oplog": "12",
            "command": "secret command",
            "comments": "sensitive comment",
        })

        self.assertEqual(operation, "UpdateMythicSyncLog")
        self.assertIn('"id": "42"', variables)
        self.assertIn('"oplog": "12"', variables)
        self.assertNotIn("secret command", variables)
        self.assertNotIn("sensitive comment", variables)

    async def test_query_retries_with_backoff_then_resets_on_success(self):
        self.sync.session = AsyncMock()
        self.sync.session.execute.side_effect = [TimeoutError(), {"whoami": {"expires": "Never"}}]

        with patch("sync.random.uniform", return_value=5), patch(
                "sync.asyncio.sleep", new_callable=AsyncMock
        ) as sleep:
            result = await self.sync._execute_query(self.sync.whoami_query)

        self.assertEqual(result, {"whoami": {"expires": "Never"}})
        sleep.assert_awaited_once_with(5)
        self.assertEqual(self.sync.session.execute.await_count, 2)

    async def test_token_expiration_accepts_z_timezone(self):
        self.sync._execute_query = AsyncMock(return_value={
            "whoami": {"expires": "2099-01-01T00:00:00Z"},
        })

        with patch("sync.mythic.send_event_log_message", new=AsyncMock()):
            await self.sync._check_token()

    async def test_stale_cached_id_is_repaired_from_entry_identifier(self):
        self.sync.rconn.set("task-1", "41")
        self.sync._mythic_task_to_ghostwriter_message = AsyncMock(return_value={
            "entry_identifier": "task-1",
            "oplog": "12",
            "tags": ["mythic:test"],
        })
        self.sync._execute_query = AsyncMock(side_effect=[
            {"update_oplogEntry": {"returning": []}},
            {"oplogEntry": [{"id": "99"}]},
            {"update_oplogEntry": {"returning": [{"id": "99"}]}},
        ])

        await self.sync._update_entry({"agent_task_id": "task-1", "id": "mythic-row"}, "41")

        self.assertEqual(self.sync.rconn.get(self.sync._redis_entry_key("task-1")), b"99")
        self.assertIsNone(self.sync.rconn.get("task-1"))
        self.assertIsNotNone(self.sync.rconn.hget(self.sync.tag_retry_data_key, "99"))

    async def test_deleted_entry_is_recreated_from_current_task(self):
        self.sync.rconn.set("task-1", "41")
        self.sync._mythic_task_to_ghostwriter_message = AsyncMock(return_value={
            "entry_identifier": "task-1",
            "oplog": "12",
            "tags": [],
        })
        self.sync._execute_query = AsyncMock(side_effect=[
            {"update_oplogEntry": {"returning": []}},
            {"oplogEntry": []},
            {"insert_oplogEntry": {"returning": [{"id": "77"}]}},
        ])

        await self.sync._update_entry({"agent_task_id": "task-1", "id": "mythic-row"}, "41")

        self.assertEqual(self.sync.rconn.get(self.sync._redis_entry_key("task-1")), b"77")
        self.assertIsNone(self.sync.rconn.get("task-1"))
        self.assertIsNotNone(self.sync.rconn.hget(self.sync.tag_retry_data_key, "77"))

    async def test_failed_tag_update_remains_queued_without_blocking_entry(self):
        self.sync._queue_task_tags(["mythic:test"], "99")
        self.sync._handle_task_tags = AsyncMock(side_effect=RuntimeError("temporary failure"))

        with patch("sync.random.uniform", return_value=10):
            await self.sync._process_pending_tag_update("99")

        payload = self.sync.rconn.hget(self.sync.tag_retry_data_key, "99")
        self.assertIsNotNone(payload)
        self.assertIn(b'"attempt": 1', payload)
        self.assertIn("99", self.sync.rconn.sorted_sets[self.sync.tag_retry_schedule_key])

    async def test_successful_tag_update_is_removed_from_queue(self):
        self.sync._queue_task_tags(["mythic:test"], "99")
        self.sync._handle_task_tags = AsyncMock()

        await self.sync._process_pending_tag_update("99")

        self.assertIsNone(self.sync.rconn.hget(self.sync.tag_retry_data_key, "99"))
        self.assertNotIn("99", self.sync.rconn.sorted_sets[self.sync.tag_retry_schedule_key])

    def test_legacy_redis_mapping_is_migrated_to_scoped_key(self):
        self.sync.rconn.set("task-1", "41")

        entry_id = self.sync._get_cached_entry_id("task-1")

        self.assertEqual(entry_id, b"41")
        self.assertIsNone(self.sync.rconn.get("task-1"))
        self.assertEqual(self.sync.rconn.get(self.sync._redis_entry_key("task-1")), b"41")

    def test_legacy_tag_queue_is_migrated_to_scoped_keys(self):
        self.sync.rconn.hset(
            self.sync.legacy_tag_retry_data_key,
            "99",
            '{"attempt": 1, "entry_id": "99", "tags": []}',
        )
        self.sync.rconn.zadd(self.sync.legacy_tag_retry_schedule_key, {"99": 123.0})

        migrated = self.sync._migrate_legacy_tag_queue()

        self.assertEqual(migrated, 1)
        self.assertIsNotNone(self.sync.rconn.hget(self.sync.tag_retry_data_key, "99"))
        self.assertEqual(self.sync.rconn.sorted_sets[self.sync.tag_retry_schedule_key]["99"], 123.0)
        self.assertEqual(self.sync.rconn.hlen(self.sync.legacy_tag_retry_data_key), 0)

    async def test_initial_entry_is_not_duplicated(self):
        self.sync._execute_query = AsyncMock(return_value={"oplogEntry": [{"id": "1"}]})

        with patch("sync.mythic.send_event_log_message", new=AsyncMock()):
            await self.sync._create_initial_entry()

        self.sync._execute_query.assert_awaited_once_with(
            self.sync.entry_identifier_query,
            {
                "oplog": self.sync.GHOSTWRITER_OPLOG_ID,
                "entry_identifier": f"mythic_sync:initial:{self.sync.MYTHIC_IP}",
            },
        )

    async def test_api_key_authentication_does_not_require_user_credentials(self):
        self.sync.MYTHIC_API_KEY = "mythic-api-key"
        self.sync.MYTHIC_USERNAME = ""
        self.sync.MYTHIC_PASSWORD = ""
        mythic_instance = object()

        with patch("sync.mythic.login", new=AsyncMock(return_value=mythic_instance)) as login, patch(
                "sync.mythic.get_me", new=AsyncMock()
        ):
            result = await self.sync._MythicSync__wait_for_authentication()

        self.assertIs(result, mythic_instance)
        self.assertEqual(login.await_args.kwargs["apitoken"], "mythic-api-key")

    async def test_wait_for_redis_requires_a_successful_ping(self):
        redis_connection = FakeRedis()

        with patch("sync.redis.Redis", return_value=redis_connection) as redis_client:
            await self.sync._wait_for_redis()

        self.assertIs(self.sync.rconn, redis_connection)
        self.assertEqual(redis_client.call_args.kwargs["db"], self.sync.REDIS_DB)

    async def test_create_entry_propagates_unexpected_failures(self):
        self.sync._mythic_task_to_ghostwriter_message = AsyncMock(return_value={
            "entry_identifier": "task-1",
            "oplog": "12",
            "tags": [],
        })
        self.sync._execute_query = AsyncMock(side_effect=RuntimeError("Redis or response failure"))

        with self.assertRaisesRegex(RuntimeError, "Redis or response failure"):
            await self.sync._create_entry({"agent_task_id": "task-1"})

        self.sync._post_error_notification.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
