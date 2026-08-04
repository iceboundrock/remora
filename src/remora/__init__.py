"""Remora: a type-safe, IDE-friendly Python DSL for Wireshark/tshark capture analysis."""

from pkgutil import extend_path

# Extras distributions (remora-wireless, ...) ship their own ``remora/proto``
# directory under a separate sys.path root. ``remora.proto``'s own extend_path
# searches *this* package's ``__path__`` (pkgutil walks the parent package, not
# sys.path), so the top-level merge has to happen first — and before the
# ``remora.proto`` import below, which is what triggers it.
__path__ = extend_path(__path__, __name__)

from remora.capture import Capture
from remora.proto import DNS, ETH, IP, TCP, UDP

__version__ = "0.1.0"

__all__ = ["DNS", "ETH", "IP", "TCP", "UDP", "Capture", "__version__"]
