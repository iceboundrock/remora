"""Generated protocol classes — the codegen.toml core set.

Extras-only protocols (codegen.toml ``[extras]``) resolve through
``__getattr__``: installed extras import transparently; missing ones raise an
ImportError naming the extra to install. ``__path__`` is pkgutil-extended so
extras distributions merge into this package from any sys.path root (wheel
installs share the directory; editable installs contribute their own).
"""

from pkgutil import extend_path

from remora.proto._extras import EXTRAS_MODULES
from remora.proto.arp import ARP
from remora.proto.dhcp import DHCP
from remora.proto.dhcpv6 import DHCPV6
from remora.proto.dns import DNS
from remora.proto.eth import ETH
from remora.proto.ftp import FTP
from remora.proto.gre import GRE
from remora.proto.http import HTTP
from remora.proto.http2 import HTTP2
from remora.proto.icmp import ICMP
from remora.proto.icmpv6 import ICMPV6
from remora.proto.igmp import IGMP
from remora.proto.imap import IMAP
from remora.proto.ip import IP
from remora.proto.ipv6 import IPV6
from remora.proto.llc import LLC
from remora.proto.ntp import NTP
from remora.proto.pop import POP
from remora.proto.quic import QUIC
from remora.proto.rtp import RTP
from remora.proto.sctp import SCTP
from remora.proto.sip import SIP
from remora.proto.smtp import SMTP
from remora.proto.snmp import SNMP
from remora.proto.ssh import SSH
from remora.proto.stp import STP
from remora.proto.tcp import TCP
from remora.proto.tls import TLS
from remora.proto.udp import UDP
from remora.proto.vlan import VLAN

__path__ = extend_path(__path__, __name__)

__all__ = [
    "ARP",
    "DHCP",
    "DHCPV6",
    "DNS",
    "ETH",
    "FTP",
    "GRE",
    "HTTP",
    "HTTP2",
    "ICMP",
    "ICMPV6",
    "IGMP",
    "IMAP",
    "IP",
    "IPV6",
    "LLC",
    "NTP",
    "POP",
    "QUIC",
    "RTP",
    "SCTP",
    "SIP",
    "SMTP",
    "SNMP",
    "SSH",
    "STP",
    "TCP",
    "TLS",
    "UDP",
    "VLAN",
]


def __getattr__(name: str) -> object:
    module_name = name.lower()
    extra = EXTRAS_MODULES.get(module_name)
    if extra is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    try:
        module = importlib.import_module(f"{__name__}.{module_name}")
    except ModuleNotFoundError:
        raise ImportError(
            f"Protocol {module_name!r} is in the {extra!r} extra, which is not "
            f"installed. Install it with: pip install 'remora[{extra}]'"
        ) from None
    if name == module_name:
        return module
    return getattr(module, name)
