# src/cap_validator/utils.py

"""
Enhanced utility functions for CAP validation and processing.

This module provides comprehensive utility functions for validating and processing
CAP data according to OASIS CAP 1.2 specifications, including datetime handling,
geographic validation, content validation, and format checking.
"""

import re
import uuid
from datetime import datetime, timezone
from typing import Union, Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse

from .exceptions import (
    CAPValidationError,
    CAPDateTimeError,
    CAPGeographicError,
    CAPContentError,
    CAPEncodingError
)

__all__ = [
    'parse_datetime',
    'format_datetime',
    'validate_coordinates',
    'validate_polygon', 
    'validate_circle',
    'normalize_whitespace',
    'validate_email_format',
    'validate_uri_format',
    'sanitize_identifier',
    'parse_coordinate_pair',
    'validate_cap_datetime_format',
    'validate_geographic_codes',
    'validate_content_constraints',
    'validate_mime_type',
    'validate_character_encoding',
    'generate_unique_identifier',
    'parse_references_field',
    'validate_language_code',
    'validate_response_types',
    'validate_categories'
]

# OASIS CAP 1.2 compliant datetime pattern
CAP_DATETIME_PATTERN = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$')

# Valid values as per OASIS CAP 1.2 specification
VALID_STATUS_VALUES = {'Actual', 'Exercise', 'System', 'Test', 'Draft'}
VALID_MSGTYPE_VALUES = {'Alert', 'Update', 'Cancel', 'Ack', 'Error'}
VALID_SCOPE_VALUES = {'Public', 'Restricted', 'Private'}
VALID_CATEGORY_VALUES = {
    'Geo', 'Met', 'Safety', 'Security', 'Rescue', 'Fire', 
    'Health', 'Env', 'Transport', 'Infra', 'CBRNE', 'Other'
}
VALID_RESPONSE_TYPE_VALUES = {
    'Shelter', 'Evacuate', 'Prepare', 'Execute', 'Avoid', 
    'Monitor', 'Assess', 'AllClear', 'None'
}
VALID_URGENCY_VALUES = {'Immediate', 'Expected', 'Future', 'Past', 'Unknown'}
VALID_SEVERITY_VALUES = {'Extreme', 'Severe', 'Moderate', 'Minor', 'Unknown'}
VALID_CERTAINTY_VALUES = {'Observed', 'Likely', 'Possible', 'Unlikely', 'Unknown'}


def parse_datetime(dt_input: Union[str, datetime]) -> datetime:
    """
    Parse various datetime formats into a datetime object.
    
    Args:
        dt_input: String or datetime object to parse
        
    Returns:
        Parsed datetime object with timezone info
        
    Raises:
        CAPDateTimeError: If datetime cannot be parsed
    """
    if isinstance(dt_input, datetime):
        # Ensure timezone info is present
        if dt_input.tzinfo is None:
            dt_input = dt_input.replace(tzinfo=timezone.utc)
        return dt_input
    
    if not isinstance(dt_input, str):
        raise CAPDateTimeError(f"Invalid datetime input type: {type(dt_input)}")
    
    dt_str = dt_input.strip()
    if not dt_str:
        raise CAPDateTimeError("Empty datetime string")
    
    try:
        # Handle 'Z' timezone designator (convert to +00:00)
        if dt_str.endswith('Z'):
            dt_str = dt_str[:-1] + '+00:00'
        
        # Parse using fromisoformat
        dt = datetime.fromisoformat(dt_str)
        
        # Ensure timezone info
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
            
        return dt
        
    except ValueError as e:
        raise CAPDateTimeError(
            f"Unable to parse datetime: {dt_input}",
            datetime_value=dt_input
        ) from e


def format_datetime(dt: datetime) -> str:
    """
    Format datetime object to OASIS CAP 1.2 compliant string.
    
    Args:
        dt: Datetime object to format
        
    Returns:
        OASIS CAP 1.2 compliant datetime string
        
    Raises:
        CAPDateTimeError: If datetime cannot be formatted
    """
    if not isinstance(dt, datetime):
        raise CAPDateTimeError(f"Expected datetime object, got {type(dt)}")
    
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    # Format using isoformat
    formatted = dt.isoformat(sep='T', timespec='seconds')
    
    # OASIS compliance: Replace 'Z' with '-00:00' for UTC
    if formatted.endswith('Z'):
        formatted = formatted[:-1] + '-00:00'
    elif formatted.endswith('+00:00'):
        formatted = formatted[:-6] + '-00:00'
    
    return formatted


def validate_cap_datetime_format(dt_value: Any, field_name: str = "datetime") -> bool:
    """
    Validate that a datetime value conforms to OASIS CAP 1.2 format.
    
    Args:
        dt_value: Value to validate
        field_name: Name of field for error reporting
        
    Returns:
        True if format is valid
        
    Raises:
        CAPDateTimeError: If format is invalid
    """
    if dt_value is None:
        return True  # Optional fields can be None
    
    if isinstance(dt_value, datetime):
        # Convert to string to validate format
        dt_str = format_datetime(dt_value)
    elif isinstance(dt_value, str):
        dt_str = dt_value.strip()
    else:
        raise CAPDateTimeError(
            f"Invalid datetime type in field '{field_name}': {type(dt_value)}",
            datetime_value=str(dt_value)
        )
    
    # Validate against OASIS pattern
    if not CAP_DATETIME_PATTERN.match(dt_str):
        raise CAPDateTimeError(
            f"Invalid datetime format in field '{field_name}': {dt_str}",
            datetime_value=dt_str
        )
    
    # Additional validation: parse to ensure it's a valid datetime
    try:
        parse_datetime(dt_str)
    except CAPDateTimeError:
        raise CAPDateTimeError(
            f"Invalid datetime value in field '{field_name}': {dt_str}",
            datetime_value=dt_str
        )
    
    return True


def validate_coordinates(lat: float, lon: float) -> bool:
    """
    Validate WGS 84 coordinate values.
    
    Args:
        lat: Latitude value
        lon: Longitude value
        
    Returns:
        True if coordinates are valid
        
    Raises:
        CAPGeographicError: If coordinates are invalid
    """
    try:
        lat_val = float(lat)
        lon_val = float(lon)
    except (ValueError, TypeError):
        raise CAPGeographicError(
            f"Invalid coordinate values: lat={lat}, lon={lon}",
            coordinates=f"{lat},{lon}"
        )
    
    if not (-90 <= lat_val <= 90):
        raise CAPGeographicError(
            f"Latitude must be between -90 and 90: {lat_val}",
            coordinates=f"{lat_val},{lon_val}"
        )
    
    if not (-180 <= lon_val <= 180):
        raise CAPGeographicError(
            f"Longitude must be between -180 and 180: {lon_val}",  
            coordinates=f"{lat_val},{lon_val}"
        )
    
    return True


def parse_coordinate_pair(coord_str: str) -> Tuple[float, float]:
    """
    Parse a coordinate pair string into latitude and longitude values.
    
    Args:
        coord_str: Coordinate string in format "latitude,longitude"
        
    Returns:
        Tuple of (latitude, longitude) as floats
        
    Raises:
        CAPGeographicError: If coordinate format is invalid
    """
    if not isinstance(coord_str, str) or not coord_str.strip():
        raise CAPGeographicError(
            "Coordinate string cannot be empty",
            coordinates=coord_str
        )
    
    coord_str = coord_str.strip()
    
    if ',' not in coord_str:
        raise CAPGeographicError(
            f"Invalid coordinate format: {coord_str}. Expected 'latitude,longitude'",
            coordinates=coord_str
        )
    
    parts = coord_str.split(',', 1)
    if len(parts) != 2:
        raise CAPGeographicError(
            f"Invalid coordinate format: {coord_str}. Expected 'latitude,longitude'",
            coordinates=coord_str
        )
    
    try:
        lat = float(parts[0].strip())
        lon = float(parts[1].strip())
    except ValueError as e:
        raise CAPGeographicError(
            f"Invalid coordinate values: {coord_str}",
            coordinates=coord_str
        ) from e
    
    # Validate ranges
    validate_coordinates(lat, lon)
    
    return lat, lon


def validate_polygon(polygon_str: str) -> bool:
    """
    Validate polygon coordinate string according to OASIS CAP 1.2.
    
    Args:
        polygon_str: Polygon coordinate string
        
    Returns:
        True if polygon is valid
        
    Raises:
        CAPGeographicError: If polygon is invalid
    """
    if not isinstance(polygon_str, str) or not polygon_str.strip():
        raise CAPGeographicError(
            "Polygon string cannot be empty",
            geographic_element='polygon'
        )
    
    coords = polygon_str.strip().split()
    
    if len(coords) < 4:
        raise CAPGeographicError(
            f"Polygon must have at least 4 coordinate pairs, got {len(coords)}",
            coordinates=polygon_str,
            geographic_element='polygon'
        )
    
    # Parse all coordinate pairs
    parsed_coords = []
    for i, coord in enumerate(coords):
        try:
            lat, lon = parse_coordinate_pair(coord)
            parsed_coords.append((lat, lon))
        except CAPGeographicError as e:
            raise CAPGeographicError(
                f"Invalid coordinate at position {i}: {str(e)}",
                coordinates=polygon_str,
                geographic_element='polygon'
            ) from e
    
    # Check if polygon is closed (first and last points must be the same)
    if parsed_coords[0] != parsed_coords[-1]:
        raise CAPGeographicError(
            "Polygon must be closed (first and last coordinate pairs must be the same)",
            coordinates=polygon_str,
            geographic_element='polygon'
        )
    
    return True


def validate_circle(circle_str: str) -> bool:
    """
    Validate circle coordinate string according to OASIS CAP 1.2.
    
    Args:
        circle_str: Circle string in format "latitude,longitude radius"
        
    Returns:
        True if circle is valid
        
    Raises:
        CAPGeographicError: If circle is invalid
    """
    if not isinstance(circle_str, str) or not circle_str.strip():
        raise CAPGeographicError(
            "Circle string cannot be empty",
            geographic_element='circle'
        )
    
    parts = circle_str.strip().split()
    
    if len(parts) != 2:
        raise CAPGeographicError(
            f"Circle format must be 'latitude,longitude radius_km': {circle_str}",
            coordinates=circle_str,
            geographic_element='circle'
        )
    
    coord_part, radius_part = parts
    
    # Validate coordinate part
    try:
        lat, lon = parse_coordinate_pair(coord_part)
    except CAPGeographicError as e:
        raise CAPGeographicError(
            f"Invalid circle coordinates: {str(e)}",
            coordinates=circle_str,
            geographic_element='circle'
        ) from e
    
    # Validate radius
    try:
        radius = float(radius_part)
        if radius <= 0:
            raise CAPGeographicError(
                f"Circle radius must be positive: {radius}",
                coordinates=circle_str,
                geographic_element='circle'
            )
    except ValueError as e:
        raise CAPGeographicError(
            f"Invalid radius value: {radius_part}",
            coordinates=circle_str,
            geographic_element='circle'
        ) from e
    
    return True


def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace in text content according to XML standards.
    
    Args:
        text: Text to normalize
        
    Returns:
        Normalized text with collapsed whitespace
    """
    if not isinstance(text, str):
        text = str(text)
    
    # Replace tabs, newlines, and carriage returns with spaces
    text = re.sub(r'[\t\n\r]', ' ', text)
    
    # Collapse multiple spaces to single space
    text = re.sub(r' +', ' ', text)
    
    # Trim leading and trailing whitespace
    return text.strip()


def validate_email_format(email: str) -> bool:
    """
    Validate email format for sender field.
    
    Args:
        email: Email string to validate
        
    Returns:
        True if email format is valid
    """
    if not isinstance(email, str) or not email.strip():
        return False
    
    # Basic email regex pattern
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email.strip()))


def validate_uri_format(uri: str) -> bool:
    """
    Validate URI format according to RFC 2396.
    
    Args:
        uri: URI string to validate
        
    Returns:
        True if URI format is valid, False otherwise
    """
    if not isinstance(uri, str) or not uri.strip():
        return False
    
    try:
        result = urlparse(uri.strip())
        # A valid URI should have at least a scheme
        return bool(result.scheme)
    except Exception:
        return False


def sanitize_identifier(identifier: str) -> str:
    """
    Sanitize alert identifier according to OASIS CAP 1.2 requirements.
    
    Args:
        identifier: Raw identifier string
        
    Returns:
        Sanitized identifier string
        
    Raises:
        CAPValidationError: If identifier cannot be sanitized
    """
    if not isinstance(identifier, str) or not identifier.strip():
        raise CAPValidationError("Identifier cannot be empty")
    
    # Remove leading/trailing whitespace
    clean_id = identifier.strip()
    
    # OASIS spec: identifiers must not contain spaces or commas
    if ' ' in clean_id or ',' in clean_id:
        # Replace spaces and commas with underscores
        clean_id = re.sub(r'[ ,]+', '_', clean_id)
    
    # Remove any other problematic characters
    clean_id = re.sub(r'[^\w\-\.]', '_', clean_id)
    
    if not clean_id:
        raise CAPValidationError("Identifier becomes empty after sanitization")
    
    return clean_id


def validate_geographic_codes(geocodes: List[Dict[str, str]]) -> bool:
    """
    Validate geographic codes according to OASIS CAP 1.2.
    
    Args:
        geocodes: List of geocode dictionaries with 'valueName' and 'value' keys
        
    Returns:
        True if all geocodes are valid
        
    Raises:
        CAPContentError: If geocodes are invalid
    """
    if not isinstance(geocodes, list):
        raise CAPContentError("Geocodes must be a list", element='geocode')
    
    for i, geocode in enumerate(geocodes):
        if not isinstance(geocode, dict):
            raise CAPContentError(
                f"Geocode {i} must be a dictionary", 
                element='geocode'
            )
        
        if 'valueName' not in geocode or 'value' not in geocode:
            raise CAPContentError(
                f"Geocode {i} must have 'valueName' and 'value' fields",
                element='geocode'
            )
        
        if not geocode['valueName'] or not geocode['value']:
            raise CAPContentError(
                f"Geocode {i} valueName and value cannot be empty",
                element='geocode'
            )
    
    return True


def validate_content_constraints(alert) -> bool:
    """
    Validate content constraints for a CAP alert according to OASIS CAP 1.2.
    
    Args:
        alert: Alert model instance to validate
        
    Returns:
        True if all constraints are satisfied
        
    Raises:
        CAPValidationError: If constraints are violated
    """
    # Import here to avoid circular imports
    from .models import Alert
    
    if not isinstance(alert, Alert):
        raise CAPValidationError("Expected Alert model instance")
    
    # Validate conditional fields
    if alert.scope == 'Restricted' and not alert.restriction:
        raise CAPContentError(
            "Field 'restriction' is required when scope is 'Restricted'",
            element='restriction',
            constraint_type='conditional'
        )
    
    if alert.scope == 'Private' and not alert.addresses:
        raise CAPContentError(
            "Field 'addresses' is required when scope is 'Private'",
            element='addresses',
            constraint_type='conditional'
        )
    
    if alert.msgType in ['Update', 'Cancel', 'Ack', 'Error'] and not alert.references:
        raise CAPContentError(
            f"Message type '{alert.msgType}' requires 'references' field",
            element='references',
            constraint_type='conditional'
        )
    
    # Validate info blocks
    if alert.info:
        for i, info in enumerate(alert.info):
            _validate_info_constraints(info, i)
    
    return True


def _validate_info_constraints(info, info_index: int):
    """
    Validate constraints for an info block.
    
    Args:
        info: Info model instance
        info_index: Index of info block for error reporting
    """
    # Validate time relationships
    if info.effective and info.expires and info.effective >= info.expires:
        raise CAPDateTimeError(
            f"Effective time must be before expires time in info block {info_index}",
            datetime_value=f"effective={info.effective}, expires={info.expires}"
        )
    
    if info.onset and info.expires and info.onset >= info.expires:
        raise CAPDateTimeError(
            f"Onset time must be before expires time in info block {info_index}",
            datetime_value=f"onset={info.onset}, expires={info.expires}"
        )
    
    # Validate area constraints
    if info.area:
        for j, area in enumerate(info.area):
            if area.ceiling is not None and area.altitude is None:
                raise CAPContentError(
                    f"Ceiling requires altitude in area {j} of info block {info_index}",
                    element='ceiling',
                    constraint_type='conditional'
                )
            
            if (area.altitude is not None and 
                area.ceiling is not None and 
                area.ceiling <= area.altitude):
                raise CAPGeographicError(
                    f"Ceiling must be greater than altitude in area {j} of info block {info_index}",
                    geographic_element='ceiling'
                )


def validate_mime_type(mime_type: str) -> bool:
    """
    Validate MIME type format according to RFC 2046.
    
    Args:
        mime_type: MIME type string to validate
        
    Returns:
        True if MIME type is valid
        
    Raises:
        CAPContentError: If MIME type is invalid
    """
    if not isinstance(mime_type, str) or not mime_type.strip():
        raise CAPContentError("MIME type cannot be empty", element='mimeType')
    
    # MIME type format: type/subtype
    mime_pattern = r'^[a-zA-Z][a-zA-Z0-9][a-zA-Z0-9\-\.]*/[a-zA-Z0-9][a-zA-Z0-9\-\.]*$'
    if not re.match(mime_pattern, mime_type.strip()):
        raise CAPContentError(
            f"Invalid MIME type format: {mime_type}",
            element='mimeType'
        )
    
    return True


def validate_character_encoding(text: str) -> bool:
    """
    Validate character encoding for CAP content.
    
    Args:
        text: Text content to validate
        
    Returns:
        True if encoding is valid
        
    Raises:
        CAPEncodingError: If encoding is invalid
    """
    if not isinstance(text, str):
        text = str(text)
    
    # Check for prohibited character entities
    if re.search(r'&[a-zA-Z][a-zA-Z0-9]*;', text):
        raise CAPEncodingError(
            "HTML character entities are discouraged in CAP content",
            problematic_content=text[:100]
        )
    
    # Validate UTF-8 compatibility
    try:
        text.encode('utf-8')
    except UnicodeEncodeError as e:
        raise CAPEncodingError(
            f"Text content contains invalid UTF-8 characters: {e}",
            problematic_content=text[:100]
        ) from e
    
    return True


def generate_unique_identifier(prefix: str = "CAP") -> str:
    """
    Generate a unique identifier for CAP alerts.
    
    Args:
        prefix: Prefix for the identifier
        
    Returns:
        Unique identifier string
    """
    if not isinstance(prefix, str) or not prefix.strip():
        prefix = "CAP"
    
    # Generate UUID-based identifier
    unique_id = str(uuid.uuid4())
    return f"{prefix.strip()}-{unique_id}"


def parse_references_field(references: str) -> List[Dict[str, str]]:
    """
    Parse the references field according to OASIS CAP 1.2 format.
    
    Args:
        references: References string in format "sender,identifier,sent sender,identifier,sent ..."
        
    Returns:
        List of reference dictionaries
        
    Raises:
        CAPContentError: If references format is invalid
    """
    if not isinstance(references, str) or not references.strip():
        return []
    
    ref_parts = references.strip().split()
    parsed_refs = []
    
    for ref_part in ref_parts:
        parts = ref_part.split(',')
        if len(parts) != 3:
            raise CAPContentError(
                f"Invalid reference format: {ref_part}. Expected 'sender,identifier,sent'",
                element='references'
            )
        
        sender, identifier, sent = parts
        
        # Validate sent datetime format
        if not CAP_DATETIME_PATTERN.match(sent):
            raise CAPDateTimeError(
                f"Invalid datetime in references: {sent}",
                datetime_value=sent
            )
        
        parsed_refs.append({
            'sender': sender,
            'identifier': identifier,
            'sent': sent
        })
    
    return parsed_refs


def validate_language_code(language: str) -> bool:
    """
    Validate language code according to RFC 3066.
    
    Args:
        language: Language code to validate
        
    Returns:
        True if language code is valid
        
    Raises:
        CAPContentError: If language code is invalid
    """
    if not isinstance(language, str) or not language.strip():
        return True  # Language is optional
    
    # RFC 3066 language code validation
    lang_pattern = r'^[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*$'
    if not re.match(lang_pattern, language.strip()):
        raise CAPContentError(
            f"Invalid language code: {language}. Expected RFC 3066 format",
            element='language'
        )
    
    return True


def validate_response_types(response_types: List[str]) -> bool:
    """
    Validate response types according to OASIS CAP 1.2.
    
    Args:
        response_types: List of response type strings
        
    Returns:
        True if all response types are valid
        
    Raises:
        CAPContentError: If response types are invalid
    """
    if not isinstance(response_types, list):
        raise CAPContentError("Response types must be a list", element='responseType')
    
    for response_type in response_types:
        if response_type not in VALID_RESPONSE_TYPE_VALUES:
            raise CAPContentError(
                f"Invalid response type: {response_type}. Must be one of {VALID_RESPONSE_TYPE_VALUES}",
                element='responseType'
            )
    
    return True


def validate_categories(categories: List[str]) -> bool:
    """
    Validate categories according to OASIS CAP 1.2.
    
    Args:
        categories: List of category strings
        
    Returns:
        True if all categories are valid
        
    Raises:
        CAPContentError: If categories are invalid
    """
    if not isinstance(categories, list) or len(categories) == 0:
        raise CAPContentError("At least one category is required", element='category')
    
    for category in categories:
        if category not in VALID_CATEGORY_VALUES:
            raise CAPContentError(
                f"Invalid category: {category}. Must be one of {VALID_CATEGORY_VALUES}",
                element='category'
            )
    
    return True