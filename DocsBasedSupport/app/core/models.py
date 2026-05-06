from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

RelationshipType = Literal["MITIGATES", "AFFECTS", "DEPENDS_ON", "INTEGRATES_WITH"]


class IngestRequest(BaseModel):
    pdf_paths: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)


class EvidenceEdge(BaseModel):
    source: str
    relationship: RelationshipType
    target: str


class ClaimCitation(BaseModel):
    claim: str
    source_id: str
    source_location: str
    evidence_edge_index: int | None = None
    quote: str | None = None
    snippet: str | None = None


class QueryRequest(BaseModel):
    question: str


class QueryResponse(BaseModel):
    answer: str
    evidence_path: list[EvidenceEdge]
    citations: list[ClaimCitation]


class TemporalCheckResult(BaseModel):
    source_id: str
    source_url: str
    stale: bool
    checked_at: datetime
    reason: str

