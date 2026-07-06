"""
Sentinel's grounded knowledge layer — the deterministic "brain" the AI
advisor is constrained to reason over, instead of recalling from training
data. Each domain (DMARC, TLS, certs, DNS) exports a flat list of Fact
entries; select_facts() does rule-based retrieval (keyword/context match,
not embeddings) since this knowledge set is small, finite, and well
understood — vector search would trade determinism for a capability this
domain doesn't need.

Design principle (matches recommendation_engine.py elsewhere in this
codebase): the knowledge layer is pure data, no LLM calls, fully
unit-testable. The LLM only ever narrates facts selected here — it never
supplies facts of its own. citations returned alongside an AI response are
the ids of facts actually injected into that prompt, not something parsed
back out of the model's free-text reply — we already know exactly what
knowledge we gave it, so that's the ground truth, not a guess.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Fact:
    id: str                          # "dmarc.tree_walk" — stable, citable
    statement: str                   # the fact itself, plain English
    rfc: str | None = None           # real citation, e.g. "RFC 7489 §3.2"
    triggers: tuple[str, ...] = ()   # keywords/contexts that make this relevant


from app.knowledge.dmarc import FACTS as _DMARC_FACTS
from app.knowledge.tls import FACTS as _TLS_FACTS
from app.knowledge.certs import FACTS as _CERT_FACTS
from app.knowledge.dns import FACTS as _DNS_FACTS

ALL_FACTS: list[Fact] = [*_DMARC_FACTS, *_TLS_FACTS, *_CERT_FACTS, *_DNS_FACTS]

_BY_ID: dict[str, Fact] = {f.id: f for f in ALL_FACTS}

# Always-relevant facts per screen — shown regardless of the specific
# question, since they're the load-bearing concepts for that topic.
_SCREEN_DEFAULTS: dict[str, tuple[str, ...]] = {
    "dmarc": ("dmarc.tree_walk", "dmarc.alignment_basic"),
    "tls": ("tls.mta_sts_modes",),
    "certs": ("certs.chain_validation",),
    "dns": ("dns.propagation_delay",),
}


def get_fact(fact_id: str) -> Fact | None:
    return _BY_ID.get(fact_id)


def select_facts(screen: str, user_message: str = "", max_facts: int = 6) -> list[Fact]:
    """
    Rule-based retrieval: keyword-match the question against each fact's
    triggers, plus always include the screen's default facts. Returns at
    most max_facts, screen defaults first (most likely to matter), then
    keyword matches ordered by how the facts are declared (stable, not
    score-ranked — there's no need for a relevance score over a set this
    small and well-scoped).
    """
    msg = user_message.lower()
    selected: list[Fact] = []
    seen: set[str] = set()

    for fact_id in _SCREEN_DEFAULTS.get(screen, ()):
        fact = _BY_ID.get(fact_id)
        if fact and fact.id not in seen:
            selected.append(fact)
            seen.add(fact.id)

    for fact in ALL_FACTS:
        if len(selected) >= max_facts:
            break
        if fact.id in seen:
            continue
        if any(trigger in msg for trigger in fact.triggers):
            selected.append(fact)
            seen.add(fact.id)

    return selected[:max_facts]


def format_facts_block(facts: list[Fact]) -> str:
    """Render selected facts as a citable block for the system prompt."""
    if not facts:
        return ""
    lines = []
    for f in facts:
        cite = f" [{f.rfc}]" if f.rfc else ""
        lines.append(f"- ({f.id}) {f.statement}{cite}")
    return "\n".join(lines)
