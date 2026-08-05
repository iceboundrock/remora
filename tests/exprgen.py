"""Seeded random Expr-tree generator for dfilter validation (issue #18).

Generates trees only over shapes the dfilter backend supports (no
datetime/timedelta literals, no empty bytes; the extended-operator leaves —
membership sets/ranges, contains, matches — are drawn only over field/literal
kinds the backend can render) using real tshark field names, so every compiled
filter must be accepted by a real tshark parser. Determinism: same seed, same
corpus — required so a CI failure reproduces locally.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from ipaddress import IPv4Address, IPv6Address

from dfilter_corpus import DST, HOST, PAYLOAD, PORT, RESPTIME, SRC, SRC6, SYN, StubField
from remora.expr import (
    And,
    CompareOp,
    Comparison,
    Expr,
    LiteralValue,
    Not,
    Or,
    Presence,
    ValueRange,
)

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


# Membership sets over orderable/int/str/IP fields only (bool/bytes/float
# sets add no coverage and float sets risk representation mismatches).
# Identity, never `in`/`==`: FieldExprOps.__eq__ builds an Expr, so tuple
# membership on fields would raise inside the operator instead of comparing.
_EXCLUDED_FROM_SETS = (SYN, PAYLOAD, RESPTIME)
_SET_SPECS: tuple[_FieldSpec, ...] = tuple(
    spec for spec in _FIELD_SPECS if not any(spec[0] is f for f in _EXCLUDED_FROM_SETS)
)
#: Fields that may also get an inclusive ValueRange element.
_RANGE_FIELDS = (PORT, SEQ, ULEN)

# Fixed pool of patterns valid in both PCRE (tshark) and Python re.
_REGEX_POOL = ("example", "^ex", "com$", "a.c", "foo|bar", "[a-z0-9]+", "ab{2,3}c")


def _gen_membership(rng: random.Random) -> Expr:
    field, _, literal_gen = rng.choice(_SET_SPECS)
    items: list[object] = [literal_gen(rng) for _ in range(rng.randrange(1, 4))]
    if any(field is f for f in _RANGE_FIELDS) and rng.random() < 0.5:
        lo = rng.randrange(60000)
        items.append(ValueRange(lo, lo + rng.randrange(1, 1000)))
    return field.in_(items)


def _gen_contains(rng: random.Random) -> Expr:
    if rng.random() < 0.5:
        needle = ""
        while not needle:
            needle = _gen_string(rng)
        return HOST.contains(needle)
    return PAYLOAD.contains(_gen_bytes(rng))


def _gen_matches(rng: random.Random) -> Expr:
    return HOST.matches(rng.choice(_REGEX_POOL))


def _gen_leaf(rng: random.Random) -> Expr:
    roll = rng.random()
    if roll < _PRESENCE_PROBABILITY:
        field, _, _ = rng.choice(_FIELD_SPECS)
        return Presence(field)
    if roll < 0.30:
        return _gen_membership(rng)
    if roll < 0.38:
        return _gen_contains(rng)
    if roll < 0.46:
        return _gen_matches(rng)
    field, ops, literal_gen = rng.choice(_FIELD_SPECS)
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
