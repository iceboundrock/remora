# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

"""Extras-only protocol modules: module name -> extra that ships it.

Consumed by remora.proto.__getattr__ to import installed extras and to
name the missing extra in ImportError. Generated from codegen.toml.
"""

EXTRAS_MODULES: dict[str, str] = {
    "diameter": "telecom",
    "dnp3": "industrial",
    "gtp": "telecom",
    "mbtcp": "industrial",
    "modbus": "industrial",
    "radiotap": "wireless",
    "wlan": "wireless",
}
