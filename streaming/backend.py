"""
streaming/backend.py
─────────────────────
Pluggable streaming backend.

Two implementations:
  - RedisBackend     — production: real Redis pub/sub
  - InMemoryBackend  — testing: asyncio queues, single process only

The factory `get_backend()` reads config and picks the right one, so the
rest of the codebase never imports redis directly.

Usage:
    backend = get_backend()
    await backend.publish("astra:abc:logs", "{json...}")

    async for channel, message in backend.subscribe("astra:abc:logs"):
        process(channel, message)
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import AsyncGenerator, Optional

from config.settings import get_settings


logger = logging.getLogger("astra.streaming")


# ════════════════════════════════════════════════════════════════════════════
# ABSTRACT INTERFACE
# ════════════════════════════════════════════════════════════════════════════
class StreamingBackend(ABC):
    """Abstract pub/sub backend. Both implementations conform to this."""

    @abstractmethod
    async def publish(self, channel: str, message: str) -> int:
        """
        Publish a message to a channel.
        Returns the number of subscribers that received it (best-effort).
        """
        ...

    @abstractmethod
    async def subscribe(self, *channels: str) -> AsyncGenerator[tuple[str, str], None]:
        """
        Async generator yielding (channel, message) tuples for each
        message received on the subscribed channels.
        """
        ...

    @abstractmethod
    async def close(self) -> None:
        """Clean up resources."""
        ...

    @abstractmethod
    async def healthcheck(self) -> bool:
        """Return True if backend is reachable."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


# ════════════════════════════════════════════════════════════════════════════
# IN-MEMORY BACKEND  (single-process, async-only)
# ════════════════════════════════════════════════════════════════════════════
class InMemoryBackend(StreamingBackend):
    """
    Pure-Python pub/sub using asyncio.Queue.
    Works only within a single process — fine for tests and dev.
    Each subscribe() call gets its own queue.

    The subscriber's queue receives (channel, message) tuples so consumers
    can correctly distinguish which channel each message came from when
    subscribed to multiple channels at once.
    """

    def __init__(self):
        # channel → list of subscriber queues
        self._subs: dict[str, list[asyncio.Queue]] = defaultdict(list)
        self._closed = False

    @property
    def name(self) -> str:
        return "memory"

    async def publish(self, channel: str, message: str) -> int:
        if self._closed:
            return 0
        queues = self._subs.get(channel, [])
        for q in queues:
            try:
                q.put_nowait((channel, message))
            except asyncio.QueueFull:
                logger.warning(f"[memory] Queue full on {channel}; dropping message")
        return len(queues)

    async def subscribe(self, *channels: str) -> AsyncGenerator[tuple[str, str], None]:
        if not channels:
            return
        # Create one queue and register it on every requested channel
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        for ch in channels:
            self._subs[ch].append(q)

        try:
            while not self._closed:
                channel, msg = await q.get()
                yield channel, msg
        finally:
            for ch in channels:
                if q in self._subs[ch]:
                    self._subs[ch].remove(q)

    async def close(self) -> None:
        self._closed = True
        self._subs.clear()

    async def healthcheck(self) -> bool:
        return not self._closed


# ════════════════════════════════════════════════════════════════════════════
# REDIS BACKEND  (production)
# ════════════════════════════════════════════════════════════════════════════
class RedisBackend(StreamingBackend):
    """Real Redis pub/sub backend using redis.asyncio."""

    def __init__(self, url: str = "redis://localhost:6379/0"):
        self.url = url
        self._client = None  # Lazy init
        self._closed = False

    @property
    def name(self) -> str:
        return "redis"

    async def _get_client(self):
        if self._client is None:
            import redis.asyncio as redis_async
            self._client = redis_async.from_url(self.url, decode_responses=True)
        return self._client

    async def publish(self, channel: str, message: str) -> int:
        client = await self._get_client()
        return await client.publish(channel, message)

    async def subscribe(self, *channels: str) -> AsyncGenerator[tuple[str, str], None]:
        if not channels:
            return
        client = await self._get_client()
        pubsub = client.pubsub()
        await pubsub.subscribe(*channels)
        try:
            async for raw in pubsub.listen():
                if raw["type"] != "message":
                    continue
                channel = raw["channel"]
                if isinstance(channel, bytes):
                    channel = channel.decode("utf-8")
                data = raw["data"]
                if isinstance(data, bytes):
                    data = data.decode("utf-8")
                yield channel, data
                if self._closed:
                    break
        finally:
            try:
                await pubsub.unsubscribe(*channels)
                await pubsub.close()
            except Exception:
                pass

    async def close(self) -> None:
        self._closed = True
        if self._client is not None:
            try:
                await self._client.close()
            except Exception:
                pass
            self._client = None

    async def healthcheck(self) -> bool:
        try:
            client = await self._get_client()
            pong = await client.ping()
            return bool(pong)
        except Exception as e:
            logger.warning(f"[redis] healthcheck failed: {e}")
            return False


# ════════════════════════════════════════════════════════════════════════════
# FACTORY  +  global singleton
# ════════════════════════════════════════════════════════════════════════════
_backend_instance: Optional[StreamingBackend] = None


def get_backend(force_memory: bool = False) -> StreamingBackend:
    """
    Return the configured streaming backend (singleton).

    Picks Redis if redis.enabled=true in config, otherwise falls back to
    in-memory. Set force_memory=True for tests.
    """
    global _backend_instance
    if _backend_instance is not None:
        return _backend_instance

    if force_memory:
        _backend_instance = InMemoryBackend()
        logger.info("[streaming] Using InMemoryBackend (forced)")
        return _backend_instance

    settings = get_settings()
    redis_enabled = getattr(settings, "redis_enabled", False)
    redis_url = getattr(settings, "redis_url", "redis://localhost:6379/0")

    if redis_enabled:
        _backend_instance = RedisBackend(url=redis_url)
        logger.info(f"[streaming] Using RedisBackend at {redis_url}")
    else:
        _backend_instance = InMemoryBackend()
        logger.info("[streaming] Using InMemoryBackend (Redis disabled in config)")

    return _backend_instance


async def close_backend() -> None:
    """Tear down the global backend (for shutdown)."""
    global _backend_instance
    if _backend_instance is not None:
        await _backend_instance.close()
        _backend_instance = None


def reset_backend() -> None:
    """Reset the singleton (test-only)."""
    global _backend_instance
    _backend_instance = None
