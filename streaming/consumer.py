"""
streaming/consumer.py
──────────────────────
Standalone consumer for backend services that need to *react* to streams
(not just forward them to a WebSocket).

Use cases:
  - Detection pipeline subscribes to logs channel → produces alerts
  - Scoring engine subscribes to alerts channel → updates scores
  - Persistence service subscribes to all channels → writes to DB

This is separate from streaming/manager.py:
  - manager.py forwards messages to WebSocket clients (frontend-facing)
  - consumer.py runs server-side handlers that process messages

Usage:
    consumer = StreamConsumer(session_id="abc")
    consumer.on(StreamType.LOGS, my_log_handler)
    consumer.on(StreamType.ALERTS, my_alert_handler)
    await consumer.start()  # runs in background until stopped
    ...
    await consumer.stop()
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Optional

from streaming.backend import get_backend
from streaming.channels import StreamType, channel_for, deserialize


logger = logging.getLogger("astra.consumer")


# Type alias for handler functions
Handler = Callable[[dict[str, Any]], Awaitable[None]]


class StreamConsumer:
    """
    Subscribe to streams for a session and dispatch messages to handlers.

    Each handler receives the full message envelope (with timestamp + payload).
    Handlers run sequentially — if you need parallelism, fan out inside the
    handler.
    """

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._handlers: dict[str, list[Handler]] = {}
        self._task: Optional[asyncio.Task] = None
        self._stopping = False

    # ── Registration ────────────────────────────────────────────────────────
    def on(self, stream: StreamType, handler: Handler) -> None:
        """Register a handler for a stream type."""
        self._handlers.setdefault(stream.value, []).append(handler)

    def off(self, stream: StreamType, handler: Optional[Handler] = None) -> None:
        """Remove a specific handler or all handlers for a stream."""
        if handler is None:
            self._handlers.pop(stream.value, None)
        else:
            handlers = self._handlers.get(stream.value, [])
            if handler in handlers:
                handlers.remove(handler)

    # ── Lifecycle ───────────────────────────────────────────────────────────
    async def start(self) -> None:
        """Start the consumer in the background."""
        if self._task and not self._task.done():
            return  # Already running
        self._stopping = False
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Stop the consumer."""
        self._stopping = True
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    # ── Internal loop ───────────────────────────────────────────────────────
    async def _run(self) -> None:
        """The subscription loop — runs until stop() is called."""
        if not self._handlers:
            logger.warning(f"[consumer] No handlers registered for session={self.session_id}")
            return

        backend = get_backend()
        channels = [
            channel_for(self.session_id, StreamType(stream_name))
            for stream_name in self._handlers
        ]

        logger.info(f"[consumer] subscribing session={self.session_id} channels={channels}")

        try:
            async for channel, raw_msg in backend.subscribe(*channels):
                if self._stopping:
                    break
                try:
                    msg = deserialize(raw_msg)
                except Exception as e:
                    logger.warning(f"[consumer] bad message on {channel}: {e}")
                    continue

                stream_name = msg.get("stream") or channel.split(":")[-1]
                handlers = self._handlers.get(stream_name, [])
                for h in handlers:
                    try:
                        await h(msg)
                    except Exception as e:
                        logger.exception(f"[consumer] handler {h.__name__} failed: {e}")
        except asyncio.CancelledError:
            logger.debug(f"[consumer] cancelled session={self.session_id}")
            raise
        except Exception as e:
            logger.exception(f"[consumer] crashed session={self.session_id}: {e}")
