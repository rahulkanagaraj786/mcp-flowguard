import enum

class ConfidentialityLevel(enum.IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3

class IntegrityLevel(enum.IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
