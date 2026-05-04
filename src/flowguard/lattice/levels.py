"""Confidentiality and integrity enumeration levels for the security lattice."""

from enum import IntEnum


class ConfidentialityLevel(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3


class IntegrityLevel(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
