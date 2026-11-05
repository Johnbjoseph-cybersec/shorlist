"""Scanner adapters.

An adapter turns one scanner's output into normalised records. The scorer never sees a
scanner's own fields. To add a scanner, write a module here with a class that implements
`Adapter` (see base.py) and register it in ADAPTERS below.
"""
from .base import Adapter, Record
from .cbomkit_theia import CbomkitTheiaAdapter
from .cdxgen import CdxgenAdapter
from .cipheriq import CipherIQAdapter, CipherIQServicesAdapter
from .cryptoscan import CryptoScanAdapter
from .qrp_mcp import QrpMcpAdapter
from .qscan import QscanAdapter
from .semgrep import SemgrepAdapter

ADAPTERS: dict[str, type[Adapter]] = {
    a.name: a for a in (QrpMcpAdapter, CryptoScanAdapter, CbomkitTheiaAdapter, CipherIQAdapter,
                        CipherIQServicesAdapter, CdxgenAdapter, QscanAdapter, SemgrepAdapter)
}

__all__ = ["ADAPTERS", "Adapter", "Record"]
