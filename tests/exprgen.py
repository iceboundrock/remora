"""Seeded random Expr-tree generator for dfilter validation (issue #18).

Generates trees only over shapes the dfilter backend supports (no
datetime/timedelta literals, no empty bytes) using real tshark field names, so
every compiled filter must be accepted by a real tshark parser. Determinism:
same seed, same corpus — required so a CI failure reproduces locally.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from ipaddress import IPv4Address, IPv6Address

from dfilter_corpus import DST, HOST, PAYLOAD, PORT, RESPTIME, SRC, SRC6, SYN, StubField
from remora.expr import And, CompareOp, Comparison, Expr, LiteralValue, Not, Or, Presence

DEFAULT_SEED = 20260802
DEFAULT_COUNT = 200

_MAX_DEPTH = 4
_LEAF_PROBABILITY = 0.35
_PRESENCE_PROBABILITY = 0.15

SEQ = StubField("tcp.seq", "FT_UINT32")
ULEN = StubField("udp.length", "FT_UINT16")

_ORDERED = (CompareOp.EQ, CompareOp.LT, CompareOp.LE, CompareOp.GT, CompareOp.GE)
_EQ_ONLY = (CompareOp.EQ,)

_TRICKY_STRINGS = (
    "example.com",
    'say "hi"',
    "a\\b",
    "café.example",
    "a\nb\tc\rd",
    "\x1b[0m",
    "",
)

_SPECIAL_FLOATS = (0.0, 0.25, 1e-05, 1e21)


def _gen_string(rng: random.Random) -> str:
    if rng.random() < 0.4:
        return rng.choice(_TRICKY_STRINGS)
    length = rng.randrange(1, 12)
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789.-") for _ in range(length))


def _gen_float(rng: random.Random) -> float:
    if rng.random() < 0.3:
        return rng.choice(_SPECIAL_FLOATS)
    return round(rng.uniform(0.0, 1000.0), 6)


def _gen_bytes(rng: random.Random) -> bytes:
    return rng.randbytes(rng.randrange(1, 9))


_FieldSpec = tuple[StubField, tuple[CompareOp, ...], Callable[[random.Random], LiteralValue]]

#: (field, allowed comparison ops, literal generator)
_FIELD_SPECS: tuple[_FieldSpec, ...] = (
    (SRC, _ORDERED, lambda rng: IPv4Address(rng.getrandbits(32))),
    (DST, _ORDERED, lambda rng: IPv4Address(rng.getrandbits(32))),
    (SRC6, _ORDERED, lambda rng: IPv6Address(rng.getrandbits(128))),
    (PORT, _ORDERED, lambda rng: rng.randrange(65536)),
    (SEQ, _ORDERED, lambda rng: rng.randrange(2**32)),
    (ULEN, _ORDERED, lambda rng: rng.randrange(65536)),
    (HOST, _ORDERED, _gen_string),
    (PAYLOAD, _ORDERED, _gen_bytes),
    (SYN, _EQ_ONLY, lambda rng: rng.random() < 0.5),
    (RESPTIME, _ORDERED, _gen_float),
)


def _gen_leaf(rng: random.Random) -> Expr:
    field, ops, literal_gen = rng.choice(_FIELD_SPECS)
    if rng.random() < _PRESENCE_PROBABILITY:
        return Presence(field)
    return Comparison(rng.choice(ops), field, literal_gen(rng))


def gen_expr(rng: random.Random, depth: int = 0) -> Expr:
    """Generate one random Expr tree, at most ``_MAX_DEPTH`` connectives deep."""
    if depth >= _MAX_DEPTH or rng.random() < _LEAF_PROBABILITY:
        return _gen_leaf(rng)
    kind = rng.random()
    if kind < 0.4:
        return And(gen_expr(rng, depth + 1), gen_expr(rng, depth + 1))
    if kind < 0.8:
        return Or(gen_expr(rng, depth + 1), gen_expr(rng, depth + 1))
    return Not(gen_expr(rng, depth + 1))


def gen_corpus(seed: int = DEFAULT_SEED, count: int = DEFAULT_COUNT) -> list[Expr]:
    """Generate ``count`` random trees from ``seed``, deterministically."""
    rng = random.Random(seed)
    return [gen_expr(rng) for _ in range(count)]
