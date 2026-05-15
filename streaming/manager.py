"""
streaming/manager.py
─────────────────────
WebSocket connection manager.

Tracks every connected dashboard client and the (session_id, streams) they're
subscribed to. Exposes a clean API for routers:

    await ws_manager.connect(websocket, session_id="abc", streams=[LOGS, ALERTS])
    ...
    await ws_manager.disconnect(websocket)

The manager runs a single background task per session that consumes from the
streaming backend and fans messages out to all clients of that session.
This is the "Redis → WebSocket bridge" — one consumer regardless of how many
dashboards are connected to the same session.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect

from streaming.backend import get_backend
from streaming.channels import StreamType, channel_for


logger = logging.getLogger("astra.ws")


class _SessionRoom:
    """One room per active session. Holds clients + the consumer task."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        # client_id → (websocket, set of stream types the client wants)
        self.clients: dict[int, tuple[WebSocket, set[str]]] = {}
        self.consumer_task: Optional[asyncio.Task] = None

    @property
    def is_empty(self) -> bool:
        return len(self.clients) == 0


class ConnectionManager:
    """
    Single source of truth for active WebSocket connections.

    There's one ConnectionManager instance for the whole app — it handles all
    sessions and all stream types. Per-session rooms are created on demand.
    """

    def __init__(self):
        self._rooms: dict[str, _SessionRoom] = {}
        self._lock = asyncio.Lock()

    # ════════════════════════════════════════════════════════════════════════
    # CONNECT / DISCONNECT
    # ════════════════════════════════════════════════════════════════════════
    async def connect(
        self,
        websocket: WebSocket,
        session_id: str,
        streams: list[StreamType],
    ) -> None:
        """Accept a new WebSocket and add it to the session room."""
        await websocket.accept()

        async with self._lock:
            room = self._rooms.get(session_id)
            if room is None:
                room = _SessionRoom(session_id)
                self._rooms[session_id] = room

            room.clients[id(websocket)] = (websocket, {s.value for s in streams})

            # Lazy-start the consumer for this session
            if room.consumer_task is None or room.consumer_task.done():
                room.consumer_task = asyncio.create_task(
                    self._run_consumer(session_id, streams)
                )

        logger.info(
            f"[ws] connected session={session_id} streams={[s.value for s in streams]} "
            f"total_clients={len(room.clients)}"
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a websocket from whatever room it was in."""
        ws_to_close: Optional[WebSocket] = None
        task_to_cancel: Optional[asyncio.Task] = None

        async with self._lock:
            for sid, room in list(self._rooms.items()):
                if id(websocket) in room.clients:
                    ws_to_close, _ = room.clients[id(websocket)]
                    del room.clients[id(websocket)]
                    logger.info(
                        f"[ws] disconnected session={sid} remaining={len(room.clients)}"
                    )
                    if room.is_empty:
                        # Defer cancellation/cleanup to outside the lock
                        task_to_cancel = room.consumer_task
                        del self._rooms[sid]
                    break

        # Do the actual close + cancel outside the lock to avoid blocking other
        # disconnects and to avoid re-entering the lock if close() has callbacks.
        if task_to_cancel and not task_to_cancel.done():
            task_to_cancel.cancel()
        if ws_to_close is not None:
            try:
                await ws_to_close.close()
            except Exception:
                pass  # Already closed by client, that's fine

    # ════════════════════════════════════════════════════════════════════════
    # CONSUMER LOOP  (one per active session)
    # ════════════════════════════════════════════════════════════════════════
    async def _run_consumer(
        self,
        session_id: str,
        streams: list[StreamType],
    ) -> None:
        """
        Subscribe to all relevant channels for a session and fan out to clients.

        We subscribe ONCE per session (not per client), so a session with
        10 connected dashboards still reads the streams once.
        """
        backend = get_backend()
        channels = [channel_for(session_id, s) for s in streams]

        try:
            async for channel, message in backend.subscribe(*channels):
                # Determine which stream this channel maps to
                stream_name = channel.split(":")[-1] if ":" in channel else None

                # Snapshot clients to avoid mutation during iteration.
                # We don't hold the lock during send() — sends can be slow,
                # and disconnect() needs the lock to remove dead clients.
                room = self._rooms.get(session_id)
                if room is None:
                    break
                snapshot = list(room.clients.values())

                dead_websockets: list[WebSocket] = []
                for ws, wanted in snapshot:
                    if stream_name and stream_name not in wanted:
                        continue
                    try:
                        await ws.send_text(message)
                    except WebSocketDisconnect:
                        dead_websockets.append(ws)
                    except Exception as e:
                        logger.debug(f"[ws] send failed, marking dead: {e}")
                        dead_websockets.append(ws)

                # Clean up dead websockets after the iteration so we don't
                # mutate the dict while looping over the snapshot.
                for ws in dead_websockets:
                    asyncio.create_task(self.disconnect(ws))
        except asyncio.CancelledError:
            logger.debug(f"[ws] consumer for session={session_id} cancelled")
            raise
        except Exception as e:
            logger.exception(f"[ws] consumer crashed for session={session_id}: {e}")

    # ════════════════════════════════════════════════════════════════════════
    # HELPERS
    # ════════════════════════════════════════════════════════════════════════
    def stats(self) -> dict:
        """Return current connection stats."""
        return {
            "rooms": len(self._rooms),
            "total_clients": sum(len(r.clients) for r in self._rooms.values()),
            "by_session": {
                sid: len(room.clients) for sid, room in self._rooms.items()
            },
        }

    async def shutdown(self) -> None:
        """Close all rooms and tasks (called on app shutdown)."""
        async with self._lock:
            rooms = list(self._rooms.values())
            self._rooms.clear()

        # Cancel + close outside the lock
        for room in rooms:
            if room.consumer_task and not room.consumer_task.done():
                room.consumer_task.cancel()
            for ws, _ in room.clients.values():
                try:
                    await ws.close()
                except Exception:
                    pass


# ════════════════════════════════════════════════════════════════════════════
# Global singleton
# ════════════════════════════════════════════════════════════════════════════
_ws_manager: Optional[ConnectionManager] = None


def get_ws_manager() -> ConnectionManager:
    global _ws_manager
    if _ws_manager is None:
        _ws_manager = ConnectionManager()
    return _ws_manager
