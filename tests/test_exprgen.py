"""Unit tests for the seeded random Expr-tree generator (no tshark needed)."""

from __future__ import annotations

from exprgen import DEFAULT_COUNT, DEFAULT_SEED, gen_corpus
from remora.compile.dfilter import compile_dfilter


class TestDeterminism:
    def test_same_seed_same_corpus(self) -> None:
        first = [compile_dfilter(e) for e in gen_corpus(seed=123, count=50)]
        second = [compile_dfilter(e) for e in gen_corpus(seed=123, count=50)]
        assert first == second

    def test_different_seed_different_corpus(self) -> None:
        first = [compile_dfilter(e) for e in gen_corpus(seed=1, count=50)]
        second = [compile_dfilter(e) for e in gen_corpus(seed=2, count=50)]
        assert first != second


class TestDefaultCorpus:
    def test_produces_at_least_200_trees(self) -> None:
        assert DEFAULT_COUNT >= 200
        assert len(gen_corpus()) == DEFAULT_COUNT

    def test_every_tree_compiles_to_a_dfilter(self) -> None:
        # The generator must only build shapes the dfilter backend supports:
        # no datetime/timedelta literals, no empty bytes.
        for tree in gen_corpus():
            compiled = compile_dfilter(tree)
            assert compiled

    def test_corpus_has_variety(self) -> None:
        compiled = {compile_dfilter(e) for e in gen_corpus(seed=DEFAULT_SEED, count=200)}
        assert len(compiled) >= 150
