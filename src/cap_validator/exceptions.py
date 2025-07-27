"""Custom exceptions for CAP validation."""


class CAPValidationError(Exception):
    """Base exception for CAP validation errors."""
    
    def __init__(self, message: str, field: str = None, code: str = None):
        self.message = message
        self.field = field
        self.code = code
        super().__init__(message)

    def __str__(self):
        parts = [self.message]
        if self.field:
            parts.append(f"Field: {self.field}")
        if self.code:
            parts.append(f"Code: {self.code}")
        return " | ".join(parts)


class CAPStructureError(CAPValidationError):
    """Raised when CAP structure is invalid."""
    pass


class CAPContentError(CAPValidationError):
    """Raised when CAP content validation fails."""
    pass


class CAPDateTimeError(CAPValidationError):
    """Raised when datetime validation fails."""
    pass


class CAPGeographicError(CAPValidationError):
    """Raised when geographic validation fails."""
    pass