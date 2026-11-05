"""Scanner adapters.

An adapter turns one scanner's output into normalised records. The scorer never sees a
scanner's own fields. To add a scanner, write a module here with a class that implements
`Adapter` (see base.py) and register it in ADAPTERS below.
"""
from .base import Adapter, Record
from .qrp_mcp import QrpMcpAdapter

ADAPTERS: dict[str, type[Adapter]] = {
    QrpMcpAdapter.name: QrpMcpAdapter,
}

__all__ = ["ADAPTERS", "Adapter", "Record"]
