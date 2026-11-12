# remora-fingerprint: v1
# tshark: 4.6.9
# dump-sha256: cc1997a091bc54fed0977474101bcff6e86a8f39122e1e6da416c24516dab324
# env: plugins=sha256:8654174b828b
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
