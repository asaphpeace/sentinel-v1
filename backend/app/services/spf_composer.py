"""
SPF record composition — PAIN_POINT_RESOLUTION_PLAN.md Pain 1's critical
fix. SPF allows exactly one record per domain. Showing a customer "add
this exact record" once per platform, in isolation, is how real DMARC
setups break — the second platform's instructions silently tell the
customer to overwrite (or duplicate, which is just as invalid) the first
platform's record.

This module is the single place allowed to produce SPF record text.
Every UI surface that touches SPF (PlatformSetupModal, the platform
health matrix, the onboarding wizard) must route through compose_spf_record()
with the full current set of declared+detected platforms — never propose
a one-platform record on its own.

Two layers:
  - compose_spf_record() — pure, no I/O, fully unit-testable. Merges
    existing record mechanisms (fetched separately) with new ones, and
    estimates the lookup count from each mechanism's static lookup_cost.
  - compose_spf_record_live() — the real thing an endpoint should call:
    fetches the domain's ACTUAL current SPF record, then computes the
    REAL total lookup count by recursively resolving every include: in
    the merged record (not a static per-mechanism guess), since RFC 7208
    §4.6.4's 10-lookup limit counts the whole resolved chain, not just
    the top-level mechanisms. A generic "1 lookup per include" estimate
    is exactly what would let a customer publish a record that looks fine
    locally but is actually over budget once a nested include is counted.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import dns.exception

from app.knowledge.platforms import SpfMechanism
from app.services.dns_resolver import resolver

log = logging.getLogger(__name__)

SPF_LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4 — see app/knowledge/dmarc.py's dmarc.spf_lookup_limit fact
_MAX_RECURSION_DEPTH = 10   # RFC 7208 itself caps total lookups at 10 — no legitimate chain goes deeper
_MAX_RESOLVED_INCLUDES = 25  # hard ceiling so a misconfigured/cyclic chain can't hang a request


@dataclass(frozen=True)
class ComposedSpfRecord:
    record: str                  # the full proposed TXT value, e.g. "v=spf1 include:... ~all"
    mechanisms: tuple[str, ...]  # the distinct mechanism strings included, in order
    total_lookups: int
    lookup_limit: int = SPF_LOOKUP_LIMIT
    over_limit: bool = False
    near_limit: bool = False     # >= 80% of the limit — warn before it's actually broken
    warnings: tuple[str, ...] = field(default_factory=tuple)
    existing_record_found: bool = False   # whether a live record existed before this proposal
    real_lookup_count: bool = False       # True once a live recursive count has replaced the static estimate


def compose_spf_record(
    new_mechanisms: list[SpfMechanism],
    *,
    existing_mechanisms: list[str] = (),
    all_qualifier: str = "~all",
) -> ComposedSpfRecord:
    """
    Merge a domain's existing SPF mechanisms (already published, fetched
    separately — see compose_spf_record_live) with new platform mechanisms
    into one record. Mechanisms are de-duplicated by their exact string
    while preserving first-seen order (existing first, so re-running this
    after adding one more platform doesn't reshuffle what's already
    published), since SPF evaluates left to right.

    total_lookups here is a static estimate (each new mechanism's
    lookup_cost, each existing mechanism counted as 1) — accurate enough
    for the pure/offline case, but compose_spf_record_live() overlays the
    real recursively-resolved count for anything actually shown to a user.
    """
    seen: set[str] = set()
    ordered: list[tuple[str, int]] = []  # (mechanism string, estimated cost)

    for raw in existing_mechanisms:
        if raw and raw not in seen:
            seen.add(raw)
            ordered.append((raw, 1 if _is_lookup_mechanism(raw) else 0))

    for m in new_mechanisms:
        if m.mechanism not in seen:
            seen.add(m.mechanism)
            ordered.append((m.mechanism, m.lookup_cost))

    total_lookups = sum(cost for _, cost in ordered)
    parts = ["v=spf1"] + [mech for mech, _ in ordered] + [all_qualifier]
    record = " ".join(parts)

    over_limit = total_lookups > SPF_LOOKUP_LIMIT
    near_limit = not over_limit and total_lookups >= int(SPF_LOOKUP_LIMIT * 0.8)

    warnings: list[str] = []
    if over_limit:
        warnings.append(
            f"This record needs an estimated {total_lookups} DNS lookups, over the 10-lookup limit "
            f"(RFC 7208 §4.6.4). Receivers will treat this as a permanent SPF error, which most treat "
            f"as an SPF fail — remove or flatten an include before publishing."
        )
    elif near_limit:
        warnings.append(
            f"This record needs an estimated {total_lookups} of the maximum 10 DNS lookups — getting "
            f"close. Adding another platform with its own include could push this over the limit."
        )

    return ComposedSpfRecord(
        record=record,
        mechanisms=tuple(mech for mech, _ in ordered),
        total_lookups=total_lookups,
        over_limit=over_limit,
        near_limit=near_limit,
        warnings=tuple(warnings),
        existing_record_found=bool(existing_mechanisms),
    )


# ── Live fetch + real recursive lookup counting ──────────────────────────────

async def fetch_spf_record(domain_name: str) -> str | None:
    """
    The domain's actual current SPF record, if any. A domain can have
    multiple TXT records at the root for unrelated purposes (verification
    tokens, etc.) — this returns only the one that starts with v=spf1.
    """
    try:
        answers = await resolver.resolve(domain_name, "TXT")
    except dns.exception.DNSException:
        return None

    for rdata in answers:
        value = "".join(s.decode() for s in rdata.strings)
        if value.strip().lower().startswith("v=spf1"):
            return value.strip()
    return None


def parse_spf_record(record: str) -> tuple[list[str], str]:
    """Splits a raw SPF record into (mechanisms excluding v=spf1/all, the all qualifier)."""
    tokens = record.strip().split()
    mechanisms: list[str] = []
    all_qualifier = "~all"
    for tok in tokens:
        if tok.lower() == "v=spf1":
            continue
        bare = tok.lstrip("+-~?")
        if bare.lower() == "all":
            all_qualifier = tok
            continue
        mechanisms.append(tok)
    return mechanisms, all_qualifier


def _is_lookup_mechanism(token: str) -> bool:
    """
    Which SPF mechanism/modifier types consume a DNS lookup per RFC 7208
    §4.6.4: include, a, mx, ptr, exists, redirect. Deliberately checks word
    boundaries — "a" must not match "all", "mx" must not match a literal
    "mx" inside something else, etc.
    """
    bare = token.lstrip("+-~?")
    lower = bare.lower()
    if lower in ("all",):
        return False
    if lower.startswith("include:") or lower.startswith("redirect="):
        return True
    if lower == "a" or lower.startswith("a:") or lower.startswith("a/"):
        return True
    if lower == "mx" or lower.startswith("mx:") or lower.startswith("mx/"):
        return True
    if lower == "ptr" or lower.startswith("ptr:"):
        return True
    if lower.startswith("exists:"):
        return True
    return False


def _include_target(token: str) -> str | None:
    bare = token.lstrip("+-~?")
    if bare.lower().startswith("include:"):
        return bare.split(":", 1)[1]
    if bare.lower().startswith("redirect="):
        return bare.split("=", 1)[1]
    return None


async def count_real_lookups(
    mechanisms: list[str],
    *,
    _seen: set[str] | None = None,
    _depth: int = 0,
    _resolved_count: list[int] | None = None,
) -> tuple[int, list[str]]:
    """
    Real, recursively-resolved lookup count — not a static per-mechanism
    guess. Per RFC 7208 §4.6.4, the 10-lookup limit counts every include/a/
    mx/ptr/exists/redirect mechanism reached anywhere in the resolution
    chain, not just the top-level record. A customer's record can look
    fine at the top level and still be over budget once a platform's own
    include (e.g. Microsoft 365's SPF include nesting further includes)
    is actually counted. Bounded by _MAX_RECURSION_DEPTH and
    _MAX_RESOLVED_INCLUDES so a misconfigured or cyclic chain can't hang
    a request — hitting either bound is itself reported as a warning,
    since a chain that deep/wide is already a real problem.
    """
    seen = _seen if _seen is not None else set()
    resolved_count = _resolved_count if _resolved_count is not None else [0]
    warnings: list[str] = []
    total = 0

    for token in mechanisms:
        if not _is_lookup_mechanism(token):
            continue
        total += 1

        target = _include_target(token)
        if target is None:
            continue  # a/mx/ptr/exists — counted, but nothing further to recurse into here

        if target in seen:
            continue  # cycle guard — already counted this include elsewhere in the chain
        seen.add(target)

        if _depth >= _MAX_RECURSION_DEPTH:
            warnings.append(f"include:{target} is nested deeper than {_MAX_RECURSION_DEPTH} levels — stopped counting, this chain is already over budget.")
            continue
        if resolved_count[0] >= _MAX_RESOLVED_INCLUDES:
            warnings.append(f"Stopped resolving further includes after {_MAX_RESOLVED_INCLUDES} — this chain is already far over the 10-lookup limit.")
            continue
        resolved_count[0] += 1

        try:
            nested_record = await fetch_spf_record(target)
        except Exception:
            nested_record = None

        if nested_record is None:
            warnings.append(f"Could not fetch include:{target}'s own SPF record — counted as 1 lookup, but its nested lookups (if any) aren't included in this total.")
            continue

        nested_mechanisms, _ = parse_spf_record(nested_record)
        nested_total, nested_warnings = await count_real_lookups(
            nested_mechanisms, _seen=seen, _depth=_depth + 1, _resolved_count=resolved_count,
        )
        total += nested_total
        warnings.extend(nested_warnings)

    return total, warnings


async def compose_spf_record_live(
    domain_name: str,
    new_mechanisms: list[SpfMechanism],
) -> ComposedSpfRecord:
    """
    The real entry point for anything shown to a user: fetches the
    domain's actual current SPF record, merges in the new platform
    mechanisms, and replaces the static lookup-count estimate with a real
    recursively-resolved count. Never proposes SPF text without first
    checking what's actually published — a generic "add this include"
    that ignores the existing record is exactly the SPF-overwrite risk
    this whole module exists to prevent.
    """
    existing_record = await fetch_spf_record(domain_name)
    existing_mechanisms: list[str] = []
    all_qualifier = "~all"
    if existing_record:
        existing_mechanisms, all_qualifier = parse_spf_record(existing_record)

    result = compose_spf_record(
        new_mechanisms, existing_mechanisms=existing_mechanisms, all_qualifier=all_qualifier,
    )

    real_total, real_warnings = await count_real_lookups(list(result.mechanisms))
    over_limit = real_total > SPF_LOOKUP_LIMIT
    near_limit = not over_limit and real_total >= int(SPF_LOOKUP_LIMIT * 0.8)

    warnings: list[str] = list(real_warnings)
    if over_limit:
        warnings.insert(0,
            f"This record needs {real_total} DNS lookups (recursively resolved, including nested "
            f"includes), over the 10-lookup limit (RFC 7208 §4.6.4). Receivers will treat this as a "
            f"permanent SPF error, which most treat as an SPF fail."
        )
    elif near_limit:
        warnings.insert(0,
            f"This record needs {real_total} of the maximum 10 DNS lookups, recursively resolved "
            f"including nested includes — getting close."
        )

    return ComposedSpfRecord(
        record=result.record,
        mechanisms=result.mechanisms,
        total_lookups=real_total,
        over_limit=over_limit,
        near_limit=near_limit,
        warnings=tuple(warnings),
        existing_record_found=existing_record is not None,
        real_lookup_count=True,
    )
