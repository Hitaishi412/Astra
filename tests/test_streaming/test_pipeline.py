"""
End-to-end tests for the streaming layer (Block 6).

Strategy:
    1. Force the InMemoryBackend (so tests don't depend on Redis being up)
    2. Test publish → subscribe round trips
    3. Test the consumer dispatch
    4. Test injector functions
"""

from __future__ import annotations

import asyncio
import json

import pytest

from streaming.backend import (
    InMemoryBackend,
    RedisBackend,
    StreamingBackend,
    get_backend,
    reset_backend,
)
from streaming.channels import (
    StreamType,
    channel_for,
    deserialize,
    envelope,
    parse_channel,
    serialize,
)
from streaming.consumer import StreamConsumer
from streaming.injector import inject_alert, inject_burst, inject_attack_status
from streaming.publisher import (
    publish,
    publish_alert,
    publish_attack_status,
    publish_log,
    publish_score,
)


# ════════════════════════════════════════════════════════════════════════════
# CHANNEL TESTS
# ════════════════════════════════════════════════════════════════════════════
class TestChannels:
    def test_channel_for_logs(self):
        assert channel_for("abc", StreamType.LOGS) == "astra:abc:logs"

    def test_channel_for_alerts(self):
        assert channel_for("abc", StreamType.ALERTS) == "astra:abc:alerts"

    def test_parse_channel_roundtrip(self):
        ch = channel_for("xyz", StreamType.SCORES)
        sid, stream = parse_channel(ch)
        assert sid == "xyz"
        assert stream == "scores"

    def test_parse_invalid_channel(self):
        assert parse_channel("not-a-channel") is None
        assert parse_channel("foo:bar") is None

    def test_envelope_shape(self):
        env = envelope(StreamType.LOGS, {"message": "hi"})
        assert env["stream"] == "logs"
        assert env["payload"] == {"message": "hi"}
        assert "timestamp" in env

    def test_serialize_deserialize_roundtrip(self):
        env = envelope(StreamType.ALERTS, {"id": "a1", "title": "test"})
        wire = serialize(env)
        assert isinstance(wire, str)
        decoded = deserialize(wire)
        assert decoded["stream"] == "alerts"
        assert decoded["payload"]["id"] == "a1"


# ════════════════════════════════════════════════════════════════════════════
# IN-MEMORY BACKEND TESTS
# ════════════════════════════════════════════════════════════════════════════
class TestInMemoryBackend:
    @pytest.mark.asyncio
    async def test_pub_sub_roundtrip(self):
        backend = InMemoryBackend()

        received = []
        ch = "astra:test:logs"

        async def reader():
            async for channel, msg in backend.subscribe(ch):
                received.append(msg)
                if len(received) >= 3:
                    break

        # Start the reader, then publish 3 messages
        reader_task = asyncio.create_task(reader())
        await asyncio.sleep(0.05)  # let subscription register

        for i in range(3):
            n = await backend.publish(ch, f"msg-{i}")
            assert n == 1  # one subscriber

        await asyncio.wait_for(reader_task, timeout=2.0)
        assert received == ["msg-0", "msg-1", "msg-2"]
        await backend.close()

    @pytest.mark.asyncio
    async def test_no_subscribers_returns_zero(self):
        backend = InMemoryBackend()
        n = await backend.publish("astra:test:nobody", "hello")
        assert n == 0
        await backend.close()

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self):
        backend = InMemoryBackend()
        ch = "astra:test:multi"

        results_a, results_b = [], []

        async def reader_a():
            async for _, msg in backend.subscribe(ch):
                results_a.append(msg)
                if len(results_a) >= 2:
                    break

        async def reader_b():
            async for _, msg in backend.subscribe(ch):
                results_b.append(msg)
                if len(results_b) >= 2:
                    break

        ta = asyncio.create_task(reader_a())
        tb = asyncio.create_task(reader_b())
        await asyncio.sleep(0.05)

        n = await backend.publish(ch, "first")
        assert n == 2  # both subscribers
        await backend.publish(ch, "second")

        await asyncio.wait_for(asyncio.gather(ta, tb), timeout=2.0)
        assert results_a == ["first", "second"]
        assert results_b == ["first", "second"]
        await backend.close()

    @pytest.mark.asyncio
    async def test_healthcheck(self):
        backend = InMemoryBackend()
        assert await backend.healthcheck() is True
        await backend.close()
        assert await backend.healthcheck() is False


# ════════════════════════════════════════════════════════════════════════════
# PUBLISHER + INJECTOR TESTS  (using in-memory backend)
# ════════════════════════════════════════════════════════════════════════════
class TestPublishers:
    @pytest.mark.asyncio
    async def test_publish_log_routes_to_logs_channel(self):
        reset_backend()
        backend = get_backend(force_memory=True)

        received = []
        ch = channel_for("s1", StreamType.LOGS)

        async def reader():
            async for _, msg in backend.subscribe(ch):
                received.append(deserialize(msg))
                break

        task = asyncio.create_task(reader())
        await asyncio.sleep(0.05)

        await publish_log("s1", {"id": "log1", "message": "test"})

        await asyncio.wait_for(task, timeout=2.0)
        assert len(received) == 1
        assert received[0]["stream"] == "logs"
        assert received[0]["payload"]["id"] == "log1"

        await backend.close()
        reset_backend()

    @pytest.mark.asyncio
    async def test_publish_alert_routes_to_alerts_channel(self):
        reset_backend()
        backend = get_backend(force_memory=True)

        received = []

        async def reader():
            async for _, msg in backend.subscribe(channel_for("s2", StreamType.ALERTS)):
                received.append(deserialize(msg))
                break

        task = asyncio.create_task(reader())
        await asyncio.sleep(0.05)

        await publish_alert("s2", {"id": "alert1", "severity": "high"})

        await asyncio.wait_for(task, timeout=2.0)
        assert received[0]["stream"] == "alerts"

        await backend.close()
        reset_backend()


class TestInjector:
    @pytest.mark.asyncio
    async def test_inject_burst_publishes_correctly(self):
        reset_backend()
        backend = get_backend(force_memory=True)

        received = []
        ch = channel_for("inj1", StreamType.LOGS)

        async def reader():
            async for _, msg in backend.subscribe(ch):
                received.append(deserialize(msg))
                if len(received) >= 5:
                    break

        task = asyncio.create_task(reader())
        await asyncio.sleep(0.05)

        await inject_burst("inj1", count=5, malicious_ratio=0.4)

        await asyncio.wait_for(task, timeout=2.0)
        assert len(received) == 5
        # All should have a stream of "logs"
        assert all(r["stream"] == "logs" for r in received)
        # All payloads should have session_id
        assert all(r["payload"]["session_id"] == "inj1" for r in received)

        await backend.close()
        reset_backend()

    @pytest.mark.asyncio
    async def test_inject_alert_publishes_alert(self):
        reset_backend()
        backend = get_backend(force_memory=True)

        received = []
        ch = channel_for("inj2", StreamType.ALERTS)

        async def reader():
            async for _, msg in backend.subscribe(ch):
                received.append(deserialize(msg))
                break

        task = asyncio.create_task(reader())
        await asyncio.sleep(0.05)

        await inject_alert("inj2")

        await asyncio.wait_for(task, timeout=2.0)
        assert len(received) == 1
        assert received[0]["stream"] == "alerts"
        assert "title" in received[0]["payload"]

        await backend.close()
        reset_backend()


# ════════════════════════════════════════════════════════════════════════════
# CONSUMER TESTS
# ════════════════════════════════════════════════════════════════════════════
class TestStreamConsumer:
    @pytest.mark.asyncio
    async def test_consumer_dispatches_to_handler(self):
        reset_backend()
        backend = get_backend(force_memory=True)

        received_logs: list[dict] = []

        async def log_handler(msg: dict):
            received_logs.append(msg)

        consumer = StreamConsumer(session_id="cs1")
        consumer.on(StreamType.LOGS, log_handler)
        await consumer.start()
        await asyncio.sleep(0.05)  # let subscription start

        # Publish 3 logs
        for i in range(3):
            await publish_log("cs1", {"id": f"log{i}", "message": f"hello {i}"})

        # Wait for handler to process
        for _ in range(20):
            if len(received_logs) >= 3:
                break
            await asyncio.sleep(0.05)

        await consumer.stop()
        await backend.close()
        reset_backend()

        assert len(received_logs) == 3
        assert received_logs[0]["stream"] == "logs"
        assert received_logs[2]["payload"]["id"] == "log2"

    @pytest.mark.asyncio
    async def test_consumer_only_receives_subscribed_streams(self):
        reset_backend()
        backend = get_backend(force_memory=True)

        log_msgs: list[dict] = []

        async def log_handler(msg: dict):
            log_msgs.append(msg)

        consumer = StreamConsumer(session_id="cs2")
        consumer.on(StreamType.LOGS, log_handler)  # only LOGS
        await consumer.start()
        await asyncio.sleep(0.05)

        # Publish to a different stream — handler should NOT fire
        await publish_alert("cs2", {"id": "a1", "title": "test"})
        await asyncio.sleep(0.1)

        # Publish to LOGS — handler SHOULD fire
        await publish_log("cs2", {"id": "log1", "message": "hi"})
        for _ in range(20):
            if log_msgs:
                break
            await asyncio.sleep(0.05)

        await consumer.stop()
        await backend.close()
        reset_backend()

        assert len(log_msgs) == 1
        assert log_msgs[0]["stream"] == "logs"
