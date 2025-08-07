"""
pycap-validator: A comprehensive Python library for CAP validation and generation.

This library provides OASIS CAP 1.2 compliant validation and XML generation capabilities
for emergency alerting systems, following both the official OASIS specification and
WMO AlertWise standards.

Main features:
- Full OASIS CAP 1.2 compliant validation with strict sequence checking
- Official XSD schema validation
- XML generation from Python data structures
- Pydantic models for type-safe CAP data structures
- Comprehensive error handling and reporting
- Command-line interface for validation and generation
- Geographic coordinate validation (WGS 84)
- Strict datetime format compliance
- Digital signature support
"""

__version__ = "0.3.0"
__author__ = "Anindita Bose"
__email__ = "anindita.bose@g.bracu.ac.bd"

# Import exceptions first
from .exceptions import (
    CAPValidationError,
    CAPStructureError,
    CAPContentError,
    CAPDateTimeError,
    CAPGeographicError,
    CAPSchemaError
)

# Import models and type literals
from .models import (
    Alert,
    Info,
    Area,
    Resource,
    Parameter,
    Geocode,
    # Type literals for better IDE support
    Status,
    MsgType,
    Scope,
    Category,
    ResponseType,
    Urgency,
    Severity,
    Certainty
)

# Import validation functions
from .validator import (
    validate_cap_xml,
    validate_cap_dict,
    validate_cap_file,
    validate_against_xsd_schema
)

# Import generation functions
from .xml_generator import (
    generate_cap_xml_from_dict,
    format_cap_timestamp
)

# Import utility functions
from .utils import (
    parse_datetime,
    format_datetime,
    validate_coordinates,
    validate_polygon,
    validate_circle,
    normalize_whitespace,
    validate_email_format,
    validate_uri_format,
    sanitize_identifier,
    parse_coordinate_pair,
    validate_cap_datetime_format,
    validate_geographic_codes,
    validate_content_constraints
)


def validate_cap_from_xml(xml_string: str, strict: bool = True, validate_xsd: bool = True) -> Alert:
    """
    Validate CAP XML string and return validated Alert model.
    
    Args:
        xml_string: CAP XML string to validate
        strict: If True, enforces strict OASIS CAP 1.2 validation
        validate_xsd: If True, validates against official OASIS XSD schema
        
    Returns:
        Validated Alert model instance
        
    Raises:
        CAPValidationError: If validation fails
        CAPStructureError: If XML structure is invalid
        CAPSchemaError: If XSD validation fails
    """
    return validate_cap_xml(xml_string, strict=strict, validate_xsd=validate_xsd)


def validate_cap_from_dict(alert_data: dict, strict: bool = True) -> Alert:
    """
    Validate CAP data from dictionary and return validated Alert model.
    
    Args:
        alert_data: Dictionary containing CAP alert data
        strict: If True, enforces strict validation
        
    Returns:
        Validated Alert model instance
        
    Raises:
        CAPValidationError: If validation fails
    """
    try:
        # Create Alert instance which will trigger all validations
        alert = Alert(**alert_data)
        
        # Additional content validation if strict mode is enabled
        if strict:
            validate_content_constraints(alert)
            
        return alert
    except Exception as e:
        raise CAPValidationError(f"Alert validation failed: {str(e)}") from e


def generate_cap_xml(alert_data, format_type: str = "auto", validate_output: bool = True) -> str:
    """
    Generate OASIS CAP 1.2 compliant XML from alert data.
    
    Args:
        alert_data: Alert data (dict format)
        format_type: Input format type (only "dict" supported currently)
        validate_output: If True, validates generated XML against XSD
        
    Returns:
        CAP 1.2 compliant XML string
        
    Raises:
        CAPValidationError: If generation fails
        CAPSchemaError: If output validation fails
    """
    try:
        if format_type == "auto":
            # Auto-detect format - currently only dict is supported
            if isinstance(alert_data, dict):
                xml_output = generate_cap_xml_from_dict(alert_data)
            else:
                raise CAPValidationError(f"Unsupported alert data type: {type(alert_data)}")
        
        elif format_type == "dict":
            xml_output = generate_cap_xml_from_dict(alert_data)
        
        else:
            raise CAPValidationError(f"Unsupported format_type: {format_type}")
        
        # Validate generated XML if requested
        if validate_output:
            validate_against_xsd_schema(xml_output)
            
        return xml_output
            
    except Exception as e:
        if isinstance(e, (CAPValidationError, CAPSchemaError)):
            raise
        raise CAPValidationError(f"CAP XML generation failed: {str(e)}") from e


def create_basic_alert(
    identifier: str,
    sender: str,
    event: str,
    urgency: str = "Unknown",
    severity: str = "Unknown",
    certainty: str = "Unknown",
    area_desc: str = "Alert Area",
    validate_strict: bool = True,
    **kwargs
) -> Alert:
    """
    Create a basic CAP alert with minimum required fields.
    
    Args:
        identifier: Unique alert identifier
        sender: Alert sender identifier (email format recommended)
        event: Description of the event
        urgency: Alert urgency level
        severity: Alert severity level
        certainty: Alert certainty level
        area_desc: Description of affected area
        validate_strict: If True, performs strict validation
        **kwargs: Additional alert fields
        
    Returns:
        Alert model instance
        
    Raises:
        CAPValidationError: If validation fails
    """
    from datetime import datetime, timezone
    
    # Validate sender format if strict validation is enabled
    if validate_strict and not validate_email_format(sender):
        raise CAPValidationError(f"Sender should be in email format for interoperability: {sender}")
    
    alert_data = {
        'identifier': sanitize_identifier(identifier),
        'sender': sender,
        'sent': datetime.now(timezone.utc),
        'status': 'Actual',
        'msgType': 'Alert',
        'scope': 'Public',
        'info': [{
            'category': ['Other'],
            'event': event,
            'urgency': urgency,
            'severity': severity,
            'certainty': certainty,
            'senderName': sender,
            'expires': datetime.now(timezone.utc).replace(hour=23, minute=59, second=59),
            'area': [{
                'areaDesc': area_desc
            }]
        }]
    }
    
    # Merge additional fields
    alert_data.update(kwargs)
    
    return validate_cap_from_dict(alert_data, strict=validate_strict)


def validate_cap_compliance(alert_data_or_xml, input_type: str = "auto") -> dict:
    """
    Comprehensive CAP compliance validation report.
    
    Args:
        alert_data_or_xml: CAP data (dict or XML string)
        input_type: Type of input ("dict", "xml", or "auto")
        
    Returns:
        Dictionary with compliance report
        
    Raises:
        CAPValidationError: If validation fails
    """
    report = {
        'compliant': False,
        'oasis_version': '1.2',
        'validation_timestamp': format_cap_timestamp(),
        'errors': [],
        'warnings': [],
        'checks': {
            'xsd_validation': False,
            'datetime_format': False,
            'element_sequence': False,
            'content_validation': False,
            'geographic_validation': False,
            'namespace_validation': False
        }
    }
    
    try:
        # Determine input type
        if input_type == "auto":
            if isinstance(alert_data_or_xml, str):
                input_type = "xml"
            elif isinstance(alert_data_or_xml, dict):
                input_type = "dict"
            else:
                raise CAPValidationError(f"Unsupported input type: {type(alert_data_or_xml)}")
        
        # Validate based on input type
        if input_type == "xml":
            alert = validate_cap_from_xml(alert_data_or_xml, strict=True, validate_xsd=True)
            report['checks']['xsd_validation'] = True
        else:
            alert = validate_cap_from_dict(alert_data_or_xml, strict=True)
        
        # Mark successful checks
        report['checks']['datetime_format'] = True
        report['checks']['element_sequence'] = True
        report['checks']['content_validation'] = True
        report['checks']['geographic_validation'] = True
        report['checks']['namespace_validation'] = True
        
        report['compliant'] = True
        report['alert_info'] = {
            'identifier': alert.identifier,
            'sender': alert.sender,
            'sent': format_cap_timestamp(alert.sent),
            'status': alert.status,
            'msgType': alert.msgType,
            'scope': alert.scope
        }
        
    except Exception as e:
        report['errors'].append(str(e))
        
        # Try to determine which checks failed
        if "XSD validation" in str(e):
            report['checks']['xsd_validation'] = False
        if "datetime" in str(e).lower():
            report['checks']['datetime_format'] = False
        if "geographic" in str(e).lower() or "coordinate" in str(e).lower():
            report['checks']['geographic_validation'] = False
    
    return report


# Export all public APIs
__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__email__",
    
    # Main models
    "Alert",
    "Info",
    "Area", 
    "Resource",
    "Parameter",
    "Geocode",
    
    # Type literals
    "Status",
    "MsgType",
    "Scope",
    "Category",
    "ResponseType",
    "Urgency",
    "Severity",
    "Certainty",
    
    # Exceptions
    "CAPValidationError",
    "CAPStructureError", 
    "CAPContentError",
    "CAPDateTimeError",
    "CAPGeographicError",
    "CAPSchemaError",
    
    # Validation functions
    "validate_cap_xml",
    "validate_cap_dict",
    "validate_cap_file",
    "validate_cap_from_xml",
    "validate_cap_from_dict",
    "validate_against_xsd_schema",
    "validate_cap_compliance",
    
    # Generation functions
    "generate_cap_xml",
    "generate_cap_xml_from_dict",
    
    # Utility functions
    "format_cap_timestamp",
    "parse_datetime",
    "format_datetime",
    "validate_coordinates",
    "validate_polygon",
    "validate_circle",
    "normalize_whitespace",
    "validate_email_format",
    "validate_uri_format",
    "sanitize_identifier",
    "parse_coordinate_pair",
    "validate_cap_datetime_format",
    "validate_geographic_codes",
    "validate_content_constraints",
    
    # Convenience functions
    "create_basic_alert",
]