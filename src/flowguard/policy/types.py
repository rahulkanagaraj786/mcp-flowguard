from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from flowguard.lattice.labels import SecurityLabel


class Decision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class FlowRequest:
    source_tool: str
    dest_tool: str
    source_label: SecurityLabel
    dest_label: SecurityLabel
    session_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class FlowDecision:
    decision: Decision
    request: FlowRequest
    reason: str
    matched_rule: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PolicyRule:
    name: str
    source_tools: list[str]         # ["*"] means any tool
    dest_tools: list[str]           # ["*"] means any tool
    action: Decision
    description: str = ""
    min_confidentiality: Optional[str] = None   # triggers when source >= this level
    max_confidentiality: Optional[str] = None   # triggers when source <= this level
    min_integrity: Optional[str] = None
    max_integrity: Optional[str] = None