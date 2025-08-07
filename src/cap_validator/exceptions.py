"""
Enhanced exception classes for CAP validation and generation.

This module provides comprehensive exception handling for all types of
CAP-related errors as specified in the OASIS CAP 1.2 standard.
"""

from typing import Optional, List, Dict, Any


# Base class for all CAP-related exceptions
class CAPError(Exception):
    """Base class for all CAP-related exceptions."""
    pass


class CAPValidationError(CAPError):
    """
    Base exception for CAP validation errors.
    
    Raised when CAP data fails validation against OASIS CAP 1.2 specification.
    """
    
    def __init__(self, message: str, field: Optional[str] = None, value: Optional[Any] = None):
        super().__init__(message)
        self.field = field
        self.value = value
        self.message = message
    
    def __str__(self) -> str:
        if self.field:
            return f"CAP Validation Error in field '{self.field}': {self.message}"
        return f"CAP Validation Error: {self.message}"


class CAPStructureError(CAPValidationError):
    """
    Exception for XML structure and parsing errors.
    
    Raised when CAP XML is malformed or doesn't follow proper XML structure.
    """
    
    def __init__(self, message: str, line_number: Optional[int] = None, column: Optional[int] = None):
        super().__init__(message)
        self.line_number = line_number
        self.column = column
    
    def __str__(self) -> str:
        location = ""
        if self.line_number:
            location = f" at line {self.line_number}"
            if self.column:
                location += f", column {self.column}"
        return f"CAP Structure Error{location}: {self.message}"


class CAPContentError(CAPValidationError):
    """
    Exception for content validation errors.
    
    Raised when CAP content doesn't meet OASIS specification requirements
    for format, constraints, or business rules.
    """
    
    def __init__(self, message: str, element: Optional[str] = None, 
                 constraint_type: Optional[str] = None):
        super().__init__(message, field=element)
        self.element = element
        self.constraint_type = constraint_type
    
    def __str__(self) -> str:
        prefix = "CAP Content Error"
        if self.constraint_type:
            prefix += f" ({self.constraint_type})"
        if self.element:
            prefix += f" in element '{self.element}'"
        return f"{prefix}: {self.message}"


class CAPDateTimeError(CAPValidationError):
    """
    Exception for datetime format and validation errors.
    
    Raised when datetime values don't conform to OASIS CAP 1.2 
    datetime format requirements.
    """
    
    def __init__(self, message: str, datetime_value: Optional[str] = None, 
                 expected_format: str = "YYYY-MM-DDThh:mm:ss±hh:mm"):
        super().__init__(message)
        self.datetime_value = datetime_value
        self.expected_format = expected_format
    
    def __str__(self) -> str:
        error_msg = f"CAP DateTime Error: {self.message}"
        if self.datetime_value:
            error_msg += f" (value: '{self.datetime_value}')"
        error_msg += f" Expected format: {self.expected_format}"
        return error_msg


class CAPGeographicError(CAPValidationError):
    """
    Exception for geographic coordinate and area validation errors.
    
    Raised when geographic data doesn't conform to WGS 84 requirements
    or other geographic constraints specified in OASIS CAP 1.2.
    """
    
    def __init__(self, message: str, coordinates: Optional[str] = None, 
                 geographic_element: Optional[str] = None):
        super().__init__(message)
        self.coordinates = coordinates
        self.geographic_element = geographic_element
    
    def __str__(self) -> str:
        error_msg = "CAP Geographic Error"
        if self.geographic_element:
            error_msg += f" in {self.geographic_element}"
        error_msg += f": {self.message}"
        if self.coordinates:
            error_msg += f" (coordinates: {self.coordinates})"
        return error_msg


class CAPSchemaError(CAPValidationError):
    """
    Exception for XSD schema validation errors.
    
    Raised when CAP XML fails validation against the official
    OASIS CAP 1.2 XSD schema.
    """
    
    def __init__(self, message: str, schema_errors: Optional[List[str]] = None):
        super().__init__(message)
        self.schema_errors = schema_errors or []
    
    def __str__(self) -> str:
        error_msg = f"CAP XSD Schema Validation Error: {self.message}"
        if self.schema_errors:
            error_msg += "\nSchema validation errors:"
            for i, error in enumerate(self.schema_errors[:5], 1):  # Limit to first 5 errors
                error_msg += f"\n  {i}. {error}"
            if len(self.schema_errors) > 5:
                error_msg += f"\n  ... and {len(self.schema_errors) - 5} more errors"
        return error_msg


class CAPNamespaceError(CAPValidationError):
    """
    Exception for namespace validation errors.
    
    Raised when CAP XML doesn't use the correct OASIS namespace
    or has namespace-related issues.
    """
    
    def __init__(self, message: str, found_namespace: Optional[str] = None, 
                 expected_namespace: str = "urn:oasis:names:tc:emergency:cap:1.2"):
        super().__init__(message)
        self.found_namespace = found_namespace
        self.expected_namespace = expected_namespace
    
    def __str__(self) -> str:
        error_msg = f"CAP Namespace Error: {self.message}"
        if self.found_namespace:
            error_msg += f" Found: '{self.found_namespace}'"  
        error_msg += f" Expected: '{self.expected_namespace}'"
        return error_msg


class CAPEncodingError(CAPValidationError):
    """
    Exception for character encoding and format errors.
    
    Raised when CAP content has encoding issues or uses
    prohibited character entities.
    """
    
    def __init__(self, message: str, encoding: Optional[str] = None, 
                 problematic_content: Optional[str] = None):
        super().__init__(message)
        self.encoding = encoding
        self.problematic_content = problematic_content
    
    def __str__(self) -> str:
        error_msg = f"CAP Encoding Error: {self.message}"
        if self.encoding:
            error_msg += f" (encoding: {self.encoding})"
        if self.problematic_content:
            # Truncate long content for readability
            content = self.problematic_content[:100]
            if len(self.problematic_content) > 100:
                content += "..."
            error_msg += f" Content: '{content}'"
        return error_msg


class CAPDigitalSignatureError(CAPValidationError):
    """
    Exception for digital signature validation errors.
    
    Raised when CAP digital signatures are invalid or malformed
    according to XML-Signature specifications.
    """
    
    def __init__(self, message: str, signature_element: Optional[str] = None):
        super().__init__(message)
        self.signature_element = signature_element
    
    def __str__(self) -> str:
        error_msg = f"CAP Digital Signature Error: {self.message}"
        if self.signature_element:
            error_msg += f" (signature element: {self.signature_element})"
        return error_msg


class CAPComplianceError(CAPValidationError):
    """
    Exception for overall CAP compliance failures.
    
    Raised when CAP message fails multiple validation checks
    or doesn't meet overall OASIS CAP 1.2 compliance requirements.
    """
    
    def __init__(self, message: str, failed_checks: Optional[Dict[str, List[str]]] = None):
        super().__init__(message)
        self.failed_checks = failed_checks or {}
    
    def __str__(self) -> str:
        error_msg = f"CAP Compliance Error: {self.message}"
        if self.failed_checks:
            error_msg += "\nFailed compliance checks:"
            for check_type, errors in self.failed_checks.items():
                error_msg += f"\n  {check_type}:"
                for error in errors[:3]:  # Limit to first 3 errors per check
                    error_msg += f"\n    - {error}"
                if len(errors) > 3:
                    error_msg += f"\n    ... and {len(errors) - 3} more"
        return error_msg


def create_validation_error(message: str, error_type: str = "general", **kwargs) -> CAPValidationError:
    """
    Factory function to create appropriate CAP validation error based on error type.
    
    Args:
        message: Error message
        error_type: Type of error (determines exception class)
        **kwargs: Additional arguments for specific exception types
        
    Returns:
        Appropriate CAPValidationError subclass instance
    """
    error_map = {
        'structure': CAPStructureError,
        'content': CAPContentError,
        'datetime': CAPDateTimeError,
        'geographic': CAPGeographicError,
        'schema': CAPSchemaError,
        'namespace': CAPNamespaceError,
        'encoding': CAPEncodingError,
        'signature': CAPDigitalSignatureError,
        'compliance': CAPComplianceError,
        'general': CAPValidationError
    }
    
    error_class = error_map.get(error_type, CAPValidationError)
    return error_class(message, **kwargs)


__all__ = [
    'CAPError',
    'CAPValidationError',
    'CAPStructureError',
    'CAPContentError',
    'CAPDateTimeError',
    'CAPGeographicError',
    'CAPSchemaError',
    'CAPNamespaceError',
    'CAPEncodingError',
    'CAPDigitalSignatureError',
    'CAPComplianceError',
    'create_validation_error'
]