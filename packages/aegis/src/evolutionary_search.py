"""Evolutionary / genetic fuzzer (task plan 20).

Bounded population and generations, deterministic seed, mutation/crossover,
corpus de-duplication, and lineage. Fitness is a HEURISTIC score - explicitly not
proof of an exploit (real evidence requires sandbox observation). Never runs on
the runtime hot path.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, Optional

GENES = ("technique", "context", "structure", "encoding", "state",
         "capability", "timing", "chain_depth", "privilege", "memory")
_ALLELES = {
    "technique": ("prompt_injection", "ssrf", "capability_spoofing", "cache_poisoning"),
    "context": ("baseline", "roleplay", "nested"),
    "structure": ("flat", "wrapped", "split"),
    "encoding": ("plain", "base64", "homoglyph"),
    "state": ("fresh", "primed"),
    "capability": ("mcp.invoke", "database.read", "network.egress"),
    "timing": ("immediate", "delayed"),
    "chain_depth": (1, 2, 3),
    "privilege": ("low", "elevated"),
    "memory": ("empty", "seeded"),
}


@dataclass(frozen=True)
class Genome:
    genome_id: str
    genes: dict
    parents: tuple[str, ...] = field(default_factory=tuple)


def _signature(genes: dict) -> tuple:
    return tuple(genes[g] for g in GENES)


def default_fitness(genes: dict) -> float:
    """Heuristic only (boundary/evasion/chain proxies). NOT exploit evidence."""
    score = 0.0
    if genes["encoding"] != "plain":
        score += 0.2
    if genes["context"] != "baseline":
        score += 0.2
    score += 0.1 * (genes["chain_depth"] - 1)
    if genes["privilege"] == "elevated":
        score += 0.2
    return round(min(score, 1.0), 4)


class GeneticFuzzer:
    def __init__(self, *, seed: int = 0, population_size: int = 12, generations: int = 5,
                 fitness: Optional[Callable[[dict], float]] = None) -> None:
        self._rng = random.Random(seed)
        self._pop = population_size
        self._gens = generations
        self._fitness = fitness or default_fitness
        self.corpus: dict[tuple, Genome] = {}
        self._counter = 0

    def _new_id(self) -> str:
        self._counter += 1
        return f"g{self._counter}"

    def _random_genes(self) -> dict:
        return {g: self._rng.choice(_ALLELES[g]) for g in GENES}

    def _register(self, genes: dict, parents=()) -> Genome:
        sig = _signature(genes)
        if sig in self.corpus:  # de-duplication
            return self.corpus[sig]
        genome = Genome(self._new_id(), genes, tuple(parents))
        self.corpus[sig] = genome
        return genome

    def _crossover(self, a: Genome, b: Genome) -> dict:
        return {g: (a.genes[g] if self._rng.random() < 0.5 else b.genes[g]) for g in GENES}

    def _mutate(self, genes: dict) -> dict:
        g = self._rng.choice(GENES)
        return {**genes, g: self._rng.choice(_ALLELES[g])}

    def run(self) -> list[Genome]:
        population = [self._register(self._random_genes()) for _ in range(self._pop)]
        for _ in range(self._gens):
            population.sort(key=lambda gn: self._fitness(gn.genes), reverse=True)
            survivors = population[: max(2, self._pop // 2)]
            children = []
            while len(survivors) + len(children) < self._pop:
                a, b = self._rng.choice(survivors), self._rng.choice(survivors)
                child_genes = self._mutate(self._crossover(a, b))
                children.append(self._register(child_genes, parents=(a.genome_id, b.genome_id)))
            population = survivors + children
        population.sort(key=lambda gn: self._fitness(gn.genes), reverse=True)
        return population

    def promote_candidates(self, threshold: float = 0.6) -> list[dict]:
        """Heuristic-high genomes. Marked as NOT evidence; real promotion needs
        sandbox-observed exploitation before entering the regression corpus."""
        from enums import RedTeamReason
        out = []
        for genome in self.corpus.values():
            if self._fitness(genome.genes) >= threshold:
                out.append({"genome_id": genome.genome_id, "genes": genome.genes,
                            "note": RedTeamReason.HEURISTIC_ONLY_NOT_EVIDENCE.value})
        return out
