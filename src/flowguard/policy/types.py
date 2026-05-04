"""Flow requests, decisions, and policy rule records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Optional

from flowguard.lattice.labels import SecurityLabel


class Decision(StrEnum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass
class PolicyRule:
    name: str
    source_tools: list[str]
    dest_tools: list[str]
    action: Decision
    description: Optional[str] = None
    min_confidentiality: Optional[str] = None
    max_confidentiality: Optional[str] = None
    min_integrity: Optional[str] = None
    max_integrity: Optional[str] = None


@dataclass(frozen=True)
class FlowRequest:
    source_tool: str
    dest_tool: str
    source_label: SecurityLabel
    dest_label: SecurityLabel
    session_id: str
    timestamp: datetime


@dataclass
class FlowDecision:
    decision: Decision
    request: FlowRequest
    reason: str
    matched_rule: Optional[PolicyRule]
    timestamp: datetime
