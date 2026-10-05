from enum import IntEnum


class ExitCode(IntEnum):
    """Stable process exit codes for SecureCC."""

    SUCCESS = 0
    VERIFICATION_FAILED = 2
    VERIFICATION_UNVERIFIED = 3
    INVALID_INPUT = 4
    TOOL_ERROR = 5
