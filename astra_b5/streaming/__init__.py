"""ASTRA streaming layer — Block 6."""

from streaming.backend import (
    StreamingBackend,
    InMemoryBackend,
    RedisBackend,
    get_backend,
    close_backend,
    reset_backend,
)
from streaming.channels import StreamType, channel_for, envelope, serialize, deserialize
from streaming.publisher import (
    publish,
    publish_log,
    publish_alert,
    publish_attack_status,
    publish_score,
    publish_control,
    publish_heartbeat,
    publish_logs_bulk,
)
from streaming.manager import ConnectionManager, get_ws_manager
from streaming.consumer import StreamConsumer

__all__ = [
    "StreamingBackend",
    "InMemoryBackend",
    "RedisBackend",
    "get_backend",
    "close_backend",
    "reset_backend",
    "StreamType",
    "channel_for",
    "envelope",
    "serialize",
    "deserialize",
    "publish",
    "publish_log",
    "publish_alert",
    "publish_attack_status",
    "publish_score",
    "publish_control",
    "publish_heartbeat",
    "publish_logs_bulk",
    "ConnectionManager",
    "get_ws_manager",
    "StreamConsumer",
]
