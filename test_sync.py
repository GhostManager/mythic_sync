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

    def set(self, key, value):
        self.values[str(key)] = self._bytes(value)

    def get(self, key):
        return self.values.get(str(key))

    def delete(self, key):
        self.values.pop(str(key), None)

    def pipeline(self, transaction=True):
        return self

    def execute(self):
        return []

    def hset(self, name, key, value):
        self.hashes.setdefault(name, {})[str(key)] = self._bytes(value)

    def hget(self, name, key):
        return self.hashes.get(name, {}).get(str(key))

    def hdel(self, name, key):
        self.hashes.get(name, {}).pop(str(key), None)

    def zadd(self, name, mapping):
        target = self.sorted_sets.setdefault(name, {})
        for key, score in mapping.items():
            target[str(key)] = score

    def zrem(self, name, key):
        self.sorted_sets.get(name, {}).pop(str(key), None)

    def zrangebyscore(self, name, minimum, maximum, start=0, num=None):
        matches = [
            key.encode()
            for key, score in sorted(self.sorted_sets.get(name, {}).items(), key=lambda item: item[1])
            if minimum <= score <= maximum
        ]
        return matches[start:] if num is None else matches[start:start + num]


class MythicSyncTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.sync = MythicSync()
        self.sync.rconn = FakeRedis()
        self.sync._post_error_notification = AsyncMock()

    async def test_get_sorted_ips_returns_plain_sorted_string(self):
        result = await self.sync._get_sorted_ips(
            '["10.0.0.20/24", "", "10.0.0.3", "2001:db8::1"]'
        )

        self.assertEqual(result, "10.0.0.3, 10.0.0.20")

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

        self.assertEqual(self.sync.rconn.get("task-1"), b"99")
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

        self.assertEqual(self.sync.rconn.get("task-1"), b"77")
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


if __name__ == "__main__":
    unittest.main()
