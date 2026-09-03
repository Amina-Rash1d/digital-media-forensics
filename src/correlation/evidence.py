from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Evidence state
# ---------------------------------------------------------------------------

class EvidenceState(str, Enum):

    OBSERVATION = "OBSERVATION"
    INDICATOR = "INDICATOR"
    CANDIDATE = "CANDIDATE"
    EXTRACTION_ATTEMPT = "EXTRACTION_ATTEMPT"
    INCONCLUSIVE = "INCONCLUSIVE"
    EXTRACTED = "EXTRACTED"
    PLAUSIBLE = "PLAUSIBLE"
    VERIFIED = "VERIFIED"


# ---------------------------------------------------------------------------
# Evidence item
# ---------------------------------------------------------------------------

@dataclass
class EvidenceItem:

    finding_id: str

    source_module: str

    source_tool: Optional[str]

    category: str

    description: str

    evidence_state: EvidenceState

    severity: Optional[str] = None

    confidence: Optional[float] = None

    target_artifact: Optional[str] = None

    artifact: Optional[str] = None

    provenance: dict[str, Any] = field(default_factory=dict)

    corroboration_group: Optional[str] = None

    derived_from: list[str] = field(default_factory=list)

    score_eligible: bool = False

    weight: Optional[float] = None

    rationale: Optional[str] = None

