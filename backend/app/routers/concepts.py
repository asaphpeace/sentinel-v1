"""
Concept Cards — PAIN_POINT_RESOLUTION_PLAN.md Pain 2.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.routers.auth import get_current_user
from app.knowledge.concepts import render_concept, CONCEPTS

router = APIRouter(prefix="/concepts", tags=["concepts"])


class RenderedConceptOut(BaseModel):
    id: str
    term: str
    text: str
    learn_more: str
    seen: bool


class ConceptContextIn(BaseModel):
    context: dict = {}


@router.get("/{concept_id}", response_model=RenderedConceptOut)
async def get_concept(
    concept_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """GET with no context renders the context-free version — context-aware
    rendering goes through POST since query strings are a poor fit for an
    arbitrary live-data dict."""
    rendered = render_concept(concept_id)
    return RenderedConceptOut(id=concept_id, seen=concept_id in (user.concepts_seen or []), **rendered)


@router.post("/{concept_id}/render", response_model=RenderedConceptOut)
async def render_concept_with_context(
    concept_id: str,
    payload: ConceptContextIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rendered = render_concept(concept_id, payload.context)
    return RenderedConceptOut(id=concept_id, seen=concept_id in (user.concepts_seen or []), **rendered)


@router.post("/{concept_id}/seen")
async def mark_concept_seen(
    concept_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    seen = set(user.concepts_seen or [])
    seen.add(concept_id)
    user.concepts_seen = sorted(seen)
    await db.commit()
    return {"ok": True}


@router.get("")
async def list_all_concepts(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Backs GlossaryModal.vue — every concept, regardless of seen-state, for self-serve lookup anytime."""
    seen = set(user.concepts_seen or [])
    return [
        {"id": c.id, "term": c.term, "text": c.learn_more, "seen": c.id in seen}
        for c in CONCEPTS.values()
    ]
