# src/cap_validator/validator.py

"""
CAP Validation Functions with Full OASIS CAP 1.2 Compliance.

This module provides comprehensive validation functions for CAP data from various sources
(XML string, dictionary, or file) against both Pydantic models and the official
OASIS CAP 1.2 XSD schema, with strict compliance checking.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Union, Optional
import requests
import io
from urllib.parse import urlparse

try:
    import xmlschema
    XSD_VALIDATION_AVAILABLE = True
except ImportError:
    XSD_VALIDATION_AVAILABLE = False

from .exceptions import (
    CAPValidationError, 
    CAPStructureError, 
    CAPSchemaError,
    CAPNamespaceError,
    CAPContentError,
    CAPDateTimeError,
    CAPGeographicError
)
from .models import Alert
from .utils import (
    normalize_whitespace, 
    validate_cap_datetime_format,
    validate_content_constraints,
    validate_email_format,
    validate_uri_format
)

__all__ = [
    "validate_cap_xml",
    "validate_cap_dict", 
    "validate_cap_file",
    "validate_against_xsd_schema"
]

# Official OASIS CAP 1.2 XSD Schema URL
OASIS_CAP_12_XSD_URL = "http://docs.oasis-open.org/emergency/cap/v1.2/CAP-v1.2.xsd"
OASIS_CAP_12_NAMESPACE = "urn:oasis:names:tc:emergency:cap:1.2"

# Cache for XSD schema to avoid repeated downloads
_schema_cache = {}


def validate_cap_xml(xml_string: str, strict: bool = True, validate_xsd: bool = True) -> Alert:
    """
    Validates a CAP XML string against the Pydantic models and OASIS structure.
    
    Args:
        xml_string: CAP XML string to validate
        strict: If True, enforces strict OASIS CAP 1.2 validation
        validate_xsd: If True, validates against official OASIS XSD schema
        
    Returns:
        Validated Alert model instance
        
    Raises:
        CAPStructureError: If XML structure is invalid
        CAPSchemaError: If XSD validation fails
        CAPNamespaceError: If namespace is incorrect
        CAPValidationError: If general validation fails
    """
    if not isinstance(xml_string, str) or not xml_string.strip():
        raise CAPValidationError("XML string cannot be empty")
    
    try:
        # Step 1: Check for well-formed XML
        clean_xml = xml_string.encode('utf-8')
        root = ET.fromstring(clean_xml)
        
        # Step 2: Validate namespace
        _validate_namespace(root)
        
        # Step 3: XSD Schema validation (if requested and available)
        if validate_xsd:
            validate_against_xsd_schema(xml_string)
        
        # Step 4: Convert XML to dictionary
        alert_dict = _xml_to_dict(root)
        
        # Debug: Print the structure to understand the issue
        print(f"DEBUG: XML-to-dict structure: {list(alert_dict.keys())}")
        if 'alert' in alert_dict:
            print(f"DEBUG: Alert keys: {list(alert_dict['alert'].keys()) if isinstance(alert_dict['alert'], dict) else type(alert_dict['alert'])}")
        
        # Extract alert data from the root structure
        if 'alert' in alert_dict:
            alert_data = alert_dict['alert']
        else:
            alert_data = alert_dict
            
        print(f"DEBUG: Final alert_data keys: {list(alert_data.keys()) if isinstance(alert_data, dict) else type(alert_data)}")
        
        # Step 5: Validate the dictionary with Pydantic models
        alert = validate_cap_dict(alert_data, strict=strict)
        
        return alert
        
    except ET.ParseError as e:
        raise CAPStructureError(
            f"Invalid XML structure: {e}",
            line_number=getattr(e, 'lineno', None),
            column=getattr(e, 'offset', None)
        ) from e
    except Exception as e:
        if isinstance(e, (CAPValidationError, CAPStructureError, CAPSchemaError, CAPNamespaceError)):
            raise
        raise CAPValidationError(f"XML validation failed: {str(e)}") from e


def validate_cap_dict(alert_data: Dict[str, Any], strict: bool = True) -> Alert:
    """
    Validates a dictionary of CAP data using the Pydantic 'Alert' model.
    
    Args:
        alert_data: Dictionary containing CAP alert data
        strict: If True, enforces strict validation including content constraints
        
    Returns:
        Validated Alert model instance
        
    Raises:
        CAPValidationError: If validation fails
    """
    if not isinstance(alert_data, dict):
        raise CAPValidationError("Input data must be a dictionary.")
    
    try:
        # Pre-validation checks
        if strict:
            _validate_alert_structure(alert_data)
        
        # Normalize data structure for Pydantic validation
        normalized_data = _normalize_alert_data(alert_data.copy())
        
        # Pydantic model validation
        alert = Alert(**normalized_data)
        
        # Additional content validation in strict mode
        if strict:
            validate_content_constraints(alert)
            _validate_business_rules(alert)
        
        return alert
        
    except Exception as e:
        if isinstance(e, (CAPValidationError, CAPContentError, CAPDateTimeError, CAPGeographicError)):
            raise
        # Re-raise as our custom validation error for consistency
        raise CAPValidationError(f"Dictionary validation failed: {e}") from e


def validate_cap_file(file_path: Union[str, Path]) -> Alert:
    """
    Validates a CAP XML file by reading its content and using validate_cap_xml.
    
    Args:
        file_path: Path to the CAP XML file
        
    Returns:
        Validated Alert model instance
        
    Raises:
        FileNotFoundError: If file doesn't exist
        CAPValidationError: If validation fails
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"CAP file not found at: {path}")
    
    try:
        xml_content = path.read_text(encoding='utf-8')
        return validate_cap_xml(xml_content)
    except Exception as e:
        if isinstance(e, (CAPValidationError, CAPStructureError, FileNotFoundError)):
            raise
        raise CAPValidationError(f"File validation failed for {path}: {e}") from e


def validate_against_xsd_schema(xml_string: str) -> bool:
    """
    Validates CAP XML against the official OASIS CAP 1.2 XSD schema.
    
    Args:
        xml_string: CAP XML string to validate
        
    Returns:
        True if validation passes
        
    Raises:
        CAPSchemaError: If XSD validation fails
        CAPValidationError: If schema cannot be loaded
    """
    if not XSD_VALIDATION_AVAILABLE:
        raise CAPValidationError(
            "XSD validation requires 'xmlschema' package. Install with: pip install xmlschema"
        )
    
    try:
        # Get or load the schema
        schema = _get_xsd_schema()
        
        # Validate the XML
        schema.validate(xml_string)
        return True
        
    except xmlschema.XMLSchemaException as e:
        # Collect all validation errors
        errors = []
        if hasattr(e, 'errors') and e.errors:
            errors = [str(err) for err in e.errors]
        else:
            errors = [str(e)]
            
        raise CAPSchemaError(
            f"XSD validation failed: {str(e)}",
            schema_errors=errors
        ) from e
    except Exception as e:
        if isinstance(e, CAPSchemaError):
            raise
        raise CAPValidationError(f"Schema validation error: {str(e)}") from e


def _get_xsd_schema():
    """
    Gets the OASIS CAP 1.2 XSD schema, using cache if available.
    
    Returns:
        XMLSchema object for CAP 1.2
    """
    if 'cap_12_schema' in _schema_cache:
        return _schema_cache['cap_12_schema']
    
    try:
        # Try to load schema from URL
        schema = xmlschema.XMLSchema(OASIS_CAP_12_XSD_URL)
        _schema_cache['cap_12_schema'] = schema
        return schema
        
    except Exception as e:
        # If URL fails, try to use a local copy or embedded schema
        raise CAPValidationError(
            f"Unable to load OASIS CAP 1.2 XSD schema from {OASIS_CAP_12_XSD_URL}: {e}"
        ) from e


def _validate_namespace(root: ET.Element):
    """
    Validates that the XML uses the correct OASIS CAP 1.2 namespace.
    
    Args:
        root: Root XML element
        
    Raises:
        CAPNamespaceError: If namespace is incorrect
    """
    # Extract namespace from root element
    if root.tag.startswith('{'):
        namespace = root.tag[1:root.tag.index('}')]
    else:
        # Check for default namespace declaration
        namespace = root.get('xmlns', '')
    
    if namespace != OASIS_CAP_12_NAMESPACE:
        raise CAPNamespaceError(
            "Incorrect CAP namespace",
            found_namespace=namespace,
            expected_namespace=OASIS_CAP_12_NAMESPACE
        )
    
    # Verify root element is 'alert'
    local_name = root.tag.split('}')[-1] if '}' in root.tag else root.tag
    if local_name != 'alert':
        raise CAPStructureError(f"Root element must be 'alert', found '{local_name}'")


def _normalize_alert_data(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize alert data structure for Pydantic validation.
    
    This function ensures that all fields that should be lists are properly formatted,
    which is especially important when converting from XML back to dictionary.
    
    Args:
        alert_data: Raw alert data dictionary
        
    Returns:
        Normalized alert data dictionary
    """
    # Ensure 'info' is always a list
    if 'info' in alert_data:
        if isinstance(alert_data['info'], dict):
            alert_data['info'] = [alert_data['info']]
        elif not isinstance(alert_data['info'], list):
            alert_data['info'] = []
    
    # Ensure 'code' is always a list if present
    if 'code' in alert_data and alert_data['code'] is not None:
        if isinstance(alert_data['code'], str):
            alert_data['code'] = [alert_data['code']]
        elif not isinstance(alert_data['code'], list):
            alert_data['code'] = []
    
    # Normalize info blocks
    if 'info' in alert_data and isinstance(alert_data['info'], list):
        for i, info_block in enumerate(alert_data['info']):
            if isinstance(info_block, dict):
                alert_data['info'][i] = _normalize_info_block(info_block)
    
    return alert_data


def _normalize_info_block(info_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize an info block structure.
    
    Args:
        info_data: Raw info block data
        
    Returns:
        Normalized info block data
    """
    # Ensure list fields are properly formatted
    list_fields = ['category', 'responseType', 'eventCode', 'parameter', 'resource', 'area']
    
    for field in list_fields:
        if field in info_data and info_data[field] is not None:
            if not isinstance(info_data[field], list):
                info_data[field] = [info_data[field]]
    
    # Normalize area blocks
    if 'area' in info_data and isinstance(info_data['area'], list):
        for i, area_block in enumerate(info_data['area']):
            if isinstance(area_block, dict):
                info_data['area'][i] = _normalize_area_block(area_block)
    
    return info_data


def _normalize_area_block(area_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize an area block structure.
    
    Args:
        area_data: Raw area block data
        
    Returns:
        Normalized area block data
    """
    # Ensure list fields are properly formatted
    list_fields = ['polygon', 'circle', 'geocode']
    
    for field in list_fields:
        if field in area_data and area_data[field] is not None:
            if not isinstance(area_data[field], list):
                area_data[field] = [area_data[field]]
    
    return area_data


def _validate_alert_structure(alert_data: Dict[str, Any]):
    """
    Validates the basic structure and required fields of alert data.
    
    Args:
        alert_data: Dictionary containing alert data
        
    Raises:
        CAPValidationError: If structure is invalid
    """
    # Check required top-level fields FIRST
    required_fields = ['identifier', 'sender', 'sent', 'status', 'msgType', 'scope']
    
    for field in required_fields:
        if field not in alert_data or alert_data[field] is None:
            raise CAPValidationError(f"Required field '{field}' is missing or None")
    
    # Validate identifier format IMMEDIATELY after checking it exists
    identifier = alert_data.get('identifier', '')
    if not identifier or not identifier.strip():
        raise CAPValidationError("Alert identifier cannot be empty")
    
    # Check for invalid characters in identifier
    identifier = identifier.strip()
    if ' ' in identifier or ',' in identifier:
        raise CAPValidationError(
            f"Alert identifier cannot contain spaces or commas: '{identifier}'"
        )
    
    # Validate sender format IMMEDIATELY after identifier
    sender = alert_data.get('sender', '')
    if not sender or not sender.strip():
        raise CAPValidationError("Alert sender cannot be empty")
    
    # Check if sender is in email format (OASIS recommendation)
    sender = sender.strip()
    if not validate_email_format(sender):
        raise CAPValidationError(
            f"Alert sender should be in email format for OASIS compliance: '{sender}'"
        )
    
    # Validate sent datetime format
    sent = alert_data.get('sent')
    if sent:
        try:
            validate_cap_datetime_format(sent, 'sent')
        except Exception as e:
            raise CAPValidationError(f"Invalid 'sent' datetime: {e}")
    
    # Validate status value
    status = alert_data.get('status')
    valid_statuses = ['Actual', 'Exercise', 'System', 'Test', 'Draft']
    if status not in valid_statuses:
        raise CAPValidationError(
            f"Invalid status '{status}'. Must be one of: {', '.join(valid_statuses)}"
        )
    
    # Validate msgType value
    msg_type = alert_data.get('msgType')
    valid_msg_types = ['Alert', 'Update', 'Cancel', 'Ack', 'Error']
    if msg_type not in valid_msg_types:
        raise CAPValidationError(
            f"Invalid msgType '{msg_type}'. Must be one of: {', '.join(valid_msg_types)}"
        )
    
    # Validate scope value
    scope = alert_data.get('scope')
    valid_scopes = ['Public', 'Restricted', 'Private']
    if scope not in valid_scopes:
        raise CAPValidationError(
            f"Invalid scope '{scope}'. Must be one of: {', '.join(valid_scopes)}"
        )
    
    # Validate conditional fields AFTER basic validation
    if scope == 'Restricted' and not alert_data.get('restriction'):
        raise CAPContentError(
            "Field 'restriction' is required when scope is 'Restricted'",
            element='restriction',
            constraint_type='conditional'
        )
    
    if scope == 'Private' and not alert_data.get('addresses'):
        raise CAPContentError(
            "Field 'addresses' is required when scope is 'Private'",
            element='addresses',
            constraint_type='conditional'
        )
    
    # Validate references format if present
    references = alert_data.get('references')
    if references and references.strip():
        _validate_references_format(references)
    
    # Validate code field if present
    code = alert_data.get('code')
    if code is not None:
        if isinstance(code, str):
            raise CAPValidationError("Field 'code' must be an array, not a string")
        elif not isinstance(code, list):
            raise CAPValidationError(f"Field 'code' must be an array, got {type(code)}")
    
    # ONLY AFTER all alert-level validation, check info blocks
    info_list = alert_data.get('info', [])
    if isinstance(info_list, dict):
        info_list = [info_list]
    
    for i, info_data in enumerate(info_list):
        if not isinstance(info_data, dict):
            raise CAPValidationError(f"Info block {i} must be a dictionary")
        _validate_info_structure(info_data, i)


def _validate_references_format(references: str):
    """
    Validate references field format.
    
    Args:
        references: References string to validate
        
    Raises:
        CAPValidationError: If format is invalid
    """
    ref_parts = references.strip().split()
    for ref_part in ref_parts:
        parts = ref_part.split(',')
        if len(parts) != 3:
            raise CAPContentError(
                f"Invalid reference format: '{ref_part}'. Expected format: 'sender,identifier,sent'",
                element='references'
            )


def _validate_info_structure(info_data: Dict[str, Any], info_index: int = 0):
    """
    Validates the structure of an info block.
    
    Args:
        info_data: Dictionary containing info data
        info_index: Index of info block for error reporting
        
    Raises:
        CAPValidationError: If structure is invalid
    """
    # Check required info fields
    required_info_fields = ['category', 'event', 'urgency', 'severity', 'certainty']
    
    for field in required_info_fields:
        if field not in info_data or info_data[field] is None:
            raise CAPValidationError(
                f"Required info field '{field}' is missing or None in info block {info_index}"
            )
    
    # Validate category is a non-empty list
    category = info_data.get('category')
    if isinstance(category, str):
        info_data['category'] = [category]  # Convert single string to list
    elif not isinstance(category, list) or len(category) == 0:
        raise CAPValidationError(
            f"Category must be a non-empty list in info block {info_index}"
        )
    
    # Validate datetime fields format if present
    datetime_fields = ['effective', 'onset', 'expires']
    for field in datetime_fields:
        if field in info_data and info_data[field] is not None:
            validate_cap_datetime_format(info_data[field], field)
    
    # Validate web URI format if present
    if 'web' in info_data and info_data['web']:
        if not validate_uri_format(info_data['web']):
            raise CAPContentError(
                f"Invalid URI format in 'web' field: {info_data['web']}",
                element='web'
            )
    
    # Validate area structures if present
    areas = info_data.get('area', [])
    if isinstance(areas, dict):
        areas = [areas]
    
    for area_index, area_data in enumerate(areas):
        if not isinstance(area_data, dict):
            raise CAPValidationError(
                f"Area {area_index} in info block {info_index} must be a dictionary"
            )
        _validate_area_structure(area_data, info_index, area_index)


def _validate_area_structure(area_data: Dict[str, Any], info_index: int, area_index: int):
    """
    Validates the structure of an area block.
    
    Args:
        area_data: Dictionary containing area data
        info_index: Index of parent info block
        area_index: Index of area block
        
    Raises:
        CAPValidationError: If structure is invalid
    """
    # areaDesc is required
    if 'areaDesc' not in area_data or not area_data['areaDesc']:
        raise CAPValidationError(
            f"Required field 'areaDesc' is missing in area {area_index} of info block {info_index}"
        )
    
    # Validate geographic elements
    has_geographic_data = False
    
    # Check polygons
    polygons = area_data.get('polygon', [])
    if isinstance(polygons, str):
        polygons = [polygons]
    
    for polygon in polygons:
        _validate_polygon_coordinates(polygon, info_index, area_index)
        has_geographic_data = True
    
    # Check circles
    circles = area_data.get('circle', [])
    if isinstance(circles, str):
        circles = [circles]
    
    for circle in circles:
        _validate_circle_coordinates(circle, info_index, area_index)
        has_geographic_data = True
    
    # Check geocodes
    geocodes = area_data.get('geocode', [])
    if geocodes:
        has_geographic_data = True
        if isinstance(geocodes, dict):
            geocodes = [geocodes]
        
        for geocode in geocodes:
            if not isinstance(geocode, dict) or 'valueName' not in geocode or 'value' not in geocode:
                raise CAPContentError(
                    f"Invalid geocode format in area {area_index} of info block {info_index}",
                    element='geocode'
                )
    
    # Validate altitude/ceiling relationship
    if 'ceiling' in area_data:
        if 'altitude' not in area_data:
            raise CAPContentError(
                f"Ceiling requires altitude in area {area_index} of info block {info_index}",
                element='ceiling',
                constraint_type='conditional'
            )
        
        try:
            altitude = float(area_data['altitude'])
            ceiling = float(area_data['ceiling'])
            if ceiling <= altitude:
                raise CAPGeographicError(
                    f"Ceiling ({ceiling}) must be greater than altitude ({altitude}) "
                    f"in area {area_index} of info block {info_index}",
                    geographic_element='ceiling'
                )
        except (ValueError, TypeError):
            raise CAPGeographicError(
                f"Invalid altitude/ceiling values in area {area_index} of info block {info_index}",
                geographic_element='altitude/ceiling'
            )


def _validate_polygon_coordinates(polygon: str, info_index: int, area_index: int):
    """
    Validates polygon coordinate format and values.
    """
    if not isinstance(polygon, str) or not polygon.strip():
        raise CAPGeographicError(
            f"Empty polygon in area {area_index} of info block {info_index}",
            geographic_element='polygon'
        )
    
    try:
        coords = polygon.strip().split()
        if len(coords) < 4:
            raise CAPGeographicError(
                f"Polygon must have at least 4 coordinate pairs, got {len(coords)} "
                f"in area {area_index} of info block {info_index}",
                coordinates=polygon,
                geographic_element='polygon'
            )
        
        # Parse and validate coordinates
        parsed_coords = []
        for i, coord in enumerate(coords):
            if ',' not in coord:
                raise CAPGeographicError(
                    f"Invalid coordinate format at position {i}: {coord}. "
                    f"Expected 'latitude,longitude' in area {area_index} of info block {info_index}",
                    coordinates=coord,
                    geographic_element='polygon'
                )
            
            lat_str, lon_str = coord.split(',', 1)
            try:
                lat = float(lat_str)
                lon = float(lon_str)
                
                # Validate WGS 84 ranges
                if not (-90 <= lat <= 90):
                    raise CAPGeographicError(
                        f"Latitude must be between -90 and 90: {lat} "
                        f"in area {area_index} of info block {info_index}",
                        coordinates=coord,
                        geographic_element='polygon'
                    )
                
                if not (-180 <= lon <= 180):
                    raise CAPGeographicError(
                        f"Longitude must be between -180 and 180: {lon} "
                        f"in area {area_index} of info block {info_index}",
                        coordinates=coord,
                        geographic_element='polygon'
                    )
                
                parsed_coords.append((lat, lon))
                
            except ValueError:
                raise CAPGeographicError(
                    f"Invalid coordinate values: {coord} "
                    f"in area {area_index} of info block {info_index}",
                    coordinates=coord,
                    geographic_element='polygon'
                )
        
        # Check if polygon is closed
        if parsed_coords[0] != parsed_coords[-1]:
            raise CAPGeographicError(
                f"Polygon must be closed (first and last points must match) "
                f"in area {area_index} of info block {info_index}",
                coordinates=polygon,
                geographic_element='polygon'
            )
            
    except CAPGeographicError:
        raise
    except Exception as e:
        raise CAPGeographicError(
            f"Invalid polygon format in area {area_index} of info block {info_index}: {str(e)}",
            coordinates=polygon,
            geographic_element='polygon'
        ) from e


def _validate_circle_coordinates(circle: str, info_index: int, area_index: int):
    """
    Validates circle coordinate format and values.
    """
    if not isinstance(circle, str) or not circle.strip():
        raise CAPGeographicError(
            f"Empty circle in area {area_index} of info block {info_index}",
            geographic_element='circle'
        )
    
    try:
        parts = circle.strip().split()
        if len(parts) != 2:
            raise CAPGeographicError(
                f"Circle format must be 'latitude,longitude radius_km': {circle} "
                f"in area {area_index} of info block {info_index}",
                coordinates=circle,
                geographic_element='circle'
            )
        
        coord_part, radius_part = parts
        
        # Validate coordinate part
        if ',' not in coord_part:
            raise CAPGeographicError(
                f"Invalid coordinate format: {coord_part}. Expected 'latitude,longitude' "
                f"in area {area_index} of info block {info_index}",
                coordinates=circle,
                geographic_element='circle'
            )
        
        lat_str, lon_str = coord_part.split(',', 1)
        lat = float(lat_str)
        lon = float(lon_str)
        
        # Validate WGS 84 ranges
        if not (-90 <= lat <= 90):
            raise CAPGeographicError(
                f"Latitude must be between -90 and 90: {lat} "
                f"in area {area_index} of info block {info_index}",
                coordinates=circle,
                geographic_element='circle'
            )
        
        if not (-180 <= lon <= 180):
            raise CAPGeographicError(
                f"Longitude must be between -180 and 180: {lon} "
                f"in area {area_index} of info block {info_index}",
                coordinates=circle,
                geographic_element='circle'
            )
        
        # Validate radius
        radius = float(radius_part)
        if radius <= 0:
            raise CAPGeographicError(
                f"Circle radius must be positive: {radius} "
                f"in area {area_index} of info block {info_index}",
                coordinates=circle,
                geographic_element='circle'
            )
            
    except ValueError as e:
        raise CAPGeographicError(
            f"Invalid circle coordinate or radius values: {circle} "
            f"in area {area_index} of info block {info_index}",
            coordinates=circle,
            geographic_element='circle'
        ) from e
    except CAPGeographicError:
        raise
    except Exception as e:
        raise CAPGeographicError(
            f"Invalid circle format in area {area_index} of info block {info_index}: {str(e)}",
            coordinates=circle,
            geographic_element='circle'
        ) from e


def _validate_business_rules(alert: Alert):
    """
    Validates business rules and cross-field constraints according to OASIS CAP 1.2.
    
    Args:
        alert: Validated Alert model instance
        
    Raises:
        CAPValidationError: If business rules are violated
    """
    # Validate msgType-specific requirements
    if alert.msgType in ['Update', 'Cancel', 'Ack', 'Error']:
        if not alert.references:
            raise CAPContentError(
                f"Message type '{alert.msgType}' requires 'references' field",
                element='references',
                constraint_type='conditional'
            )
    
    # Validate status-specific requirements
    if alert.status == 'Exercise':
        # Exercise alerts should have note explaining the exercise
        if not alert.note:
            # This is a recommendation, not a hard requirement
            pass
    
    # Validate scope-specific requirements (already checked in structure validation)
    
    # Validate info block constraints
    if alert.info:
        for i, info in enumerate(alert.info):
            _validate_info_business_rules(info, i)
    
    # Cross-validation: ensure sent timestamp is reasonable
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    
    # Alert shouldn't be from too far in the future (allow 24 hours for clock skew)
    if alert.sent > now + timedelta(hours=24):
        raise CAPDateTimeError(
            f"Alert 'sent' time is too far in the future: {alert.sent}",
            datetime_value=str(alert.sent)
        )
    
    # Alert shouldn't be from too far in the past (allow 10 years for archives)
    if alert.sent < now - timedelta(days=365*10):
        raise CAPDateTimeError(
            f"Alert 'sent' time is too old: {alert.sent}",
            datetime_value=str(alert.sent)
        )


def _validate_info_business_rules(info, info_index: int):
    """
    Validates business rules for info blocks.
    
    Args:
        info: Info model instance
        info_index: Index of info block
        
    Raises:
        CAPValidationError: If business rules are violated
    """
    # Validate time relationships
    if info.effective and info.expires:
        if info.effective >= info.expires:
            raise CAPDateTimeError(
                f"Effective time must be before expires time in info block {info_index}",
                datetime_value=f"effective={info.effective}, expires={info.expires}"
            )
    
    if info.onset and info.expires:
        if info.onset >= info.expires:
            raise CAPDateTimeError(
                f"Onset time must be before expires time in info block {info_index}",
                datetime_value=f"onset={info.onset}, expires={info.expires}"
            )
    
    # Validate urgency/severity/certainty combinations
    # These are recommendations, not hard requirements in OASIS spec
    if info.urgency == 'Immediate' and info.certainty == 'Unlikely':
        # This combination doesn't make much sense but isn't prohibited
        pass
    
    # Validate response type appropriateness
    if info.responseType:
        for response in info.responseType:
            if response == 'AllClear' and info.urgency in ['Immediate', 'Expected']:
                # AllClear with high urgency is contradictory
                pass
    
    # Validate area requirements
    if info.area:
        for area_index, area in enumerate(info.area):
            # Each area should have some geographic specification
            has_geo = bool(area.polygon or area.circle or area.geocode)
            if not has_geo:
                # This is not strictly required by OASIS but is recommended
                pass


def _xml_to_dict(element: ET.Element) -> Dict[str, Any]:
    """
    Recursively converts an ElementTree element to a dictionary.
    Handles namespaces and aggregates repeated tags into lists.
    
    Args:
        element: XML element to convert
        
    Returns:
        Dictionary representation of XML element
    """
    # Strip namespace from tag
    tag = element.tag.split('}')[-1] if '}' in element.tag else element.tag
    
    # Base case: element with no children
    if not list(element):
        text_content = element.text or ""
        return {tag: normalize_whitespace(text_content) if text_content else ""}
    
    # Recursive case: element with children
    child_dict = {}
    for child in element:
        child_data = _xml_to_dict(child)
        child_tag = list(child_data.keys())[0]
        
        # Handle repeated elements by converting to lists
        if child_tag in child_dict:
            if not isinstance(child_dict[child_tag], list):
                child_dict[child_tag] = [child_dict[child_tag]]  # Convert to list
            child_dict[child_tag].append(child_data[child_tag])
        else:
            child_dict[child_tag] = child_data[child_tag]
    
    return {tag: child_dict}