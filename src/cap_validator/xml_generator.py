# src/cap_validator/xml_generator.py

"""
OASIS CAP 1.2 Compliant XML Generation

This module provides functions to generate a CAP XML string from a Python dictionary,
ensuring the output strictly follows the element sequence defined in the standard
and complies with all OASIS CAP 1.2 requirements.
"""

import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
import re
import uuid

from .exceptions import (
    CAPValidationError, 
    CAPDateTimeError, 
    CAPContentError, 
    CAPGeographicError,
    CAPEncodingError
)

__all__ = [
    "generate_cap_xml_from_dict",
    "format_cap_timestamp"
]


def format_cap_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Formats a datetime object into an OASIS CAP 1.2 compliant timestamp string.
    
    OASIS CAP 1.2 Requirements:
    - Format: YYYY-MM-DDThh:mm:ssXzh:zm
    - X must be '+' or '-' (never 'Z')
    - UTC must be represented as '-00:00' (not 'Z' or '+00:00')
    - Alphabetic timezone designators are prohibited
    
    Args:
        dt: Datetime object to format. If None, uses current UTC time.
        
    Returns:
        OASIS CAP 1.2 compliant timestamp string
        
    Example:
        '2025-07-29T13:12:19-06:00' or '2025-07-29T19:12:19-00:00' for UTC
    """
    if dt is None:
        dt = datetime.now(timezone.utc)
    
    if dt.tzinfo is None:
        dt = dt.astimezone()  # Use local timezone if none is set
    
    # Format to ISO string with timezone
    formatted = dt.isoformat(sep='T', timespec='seconds')
    
    # OASIS CAP 1.2 compliance: Replace 'Z' with '-00:00' for UTC
    if formatted.endswith('Z'):
        formatted = formatted[:-1] + '-00:00'
    # Replace '+00:00' with '-00:00' for UTC as required by OASIS
    elif formatted.endswith('+00:00'):
        formatted = formatted[:-6] + '-00:00'
    
    # Validate the final format matches OASIS requirements
    if not re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$', formatted):
        raise CAPDateTimeError(
            f"Generated timestamp does not match OASIS CAP 1.2 format: {formatted}",
            datetime_value=formatted
        )
    
    return formatted


def generate_cap_xml_from_dict(alert_data: Dict[str, Any]) -> str:
    """
    Generates an OASIS CAP 1.2 compliant XML string from a dictionary.
    
    This function carefully constructs the XML to match the strict element
    sequence required by the CAP 1.2 standard and validates content constraints.
    
    Args:
        alert_data: Dictionary containing CAP alert data
        
    Returns:
        OASIS CAP 1.2 compliant XML string
        
    Raises:
        CAPValidationError: If alert data is invalid
        CAPContentError: If content constraints are violated
    """
    if not isinstance(alert_data, dict):
        raise CAPValidationError("Alert data must be a dictionary")
    
    # Validate required top-level fields
    _validate_required_alert_fields(alert_data)
    
    # Create root element with the correct namespace
    root = ET.Element('alert')
    root.set('xmlns', 'urn:oasis:names:tc:emergency:cap:1.2')
    
    # Add elements in the correct OASIS sequence
    _add_alert_elements(root, alert_data)
    
    # Process info elements
    info_list = alert_data.get('info', [])
    if isinstance(info_list, dict):  # Handle case where 'info' is a single dict
        info_list = [info_list]
    
    for info_data in info_list:
        _add_info_element(root, info_data)
    
    # Generate pretty-printed XML
    rough_string = ET.tostring(root, 'unicode', xml_declaration=True)
    reparsed = minidom.parseString(rough_string)
    pretty_xml = reparsed.toprettyxml(indent="  ")
    
    # Clean up extra whitespace that minidom adds
    lines = [line for line in pretty_xml.split('\n') if line.strip()]
    return '\n'.join(lines)


def _validate_required_alert_fields(alert_data: Dict[str, Any]):
    """
    Validates required fields at the alert level according to OASIS CAP 1.2.
    """
    required_fields = ['identifier', 'sender', 'sent', 'status', 'msgType', 'scope']
    
    for field in required_fields:
        if field not in alert_data or alert_data[field] is None:
            raise CAPValidationError(f"Required field '{field}' is missing or None")
    
    # Validate conditional requirements
    if alert_data.get('scope') == 'Restricted' and 'restriction' not in alert_data:
        raise CAPContentError(
            "Field 'restriction' is required when scope is 'Restricted'",
            element='restriction',
            constraint_type='conditional'
        )
    
    if alert_data.get('scope') == 'Private' and 'addresses' not in alert_data:
        raise CAPContentError(
            "Field 'addresses' is required when scope is 'Private'",
            element='addresses',
            constraint_type='conditional'
        )


def _add_alert_elements(root: ET.Element, data: Dict[str, Any]):
    """
    Adds top-level <alert> elements in the correct OASIS sequence.
    """
    # Generate identifier if not provided
    identifier = data.get('identifier')
    if not identifier:
        identifier = f'urn:uuid:{uuid.uuid4()}'
    
    _add_element(root, 'identifier', identifier)
    _add_element(root, 'sender', data.get('sender', 'Unknown'))
    _add_element(root, 'sent', _format_datetime(data.get('sent', datetime.now(timezone.utc))))
    _add_element(root, 'status', data.get('status', 'Actual'))
    _add_element(root, 'msgType', data.get('msgType', 'Alert'))
    
    # Optional elements in sequence
    if 'source' in data:
        _add_element(root, 'source', data['source'])
    
    _add_element(root, 'scope', data.get('scope', 'Public'))
    
    if 'restriction' in data:
        _add_element(root, 'restriction', data['restriction'])
    
    if 'addresses' in data:
        _add_element(root, 'addresses', data['addresses'])
    
    _add_list_elements(root, 'code', data.get('code', []))
    
    if 'note' in data:
        _add_element(root, 'note', data['note'])
    
    if 'references' in data:
        _add_element(root, 'references', data['references'])
    
    if 'incidents' in data:
        _add_element(root, 'incidents', data['incidents'])


def _add_info_element(root: ET.Element, data: Dict[str, Any]):
    """
    Adds an <info> block and its sub-elements in the correct OASIS sequence.
    """
    if not isinstance(data, dict):
        raise CAPValidationError("Info data must be a dictionary")
    
    # Validate required info fields
    _validate_required_info_fields(data)
    
    info_elem = ET.SubElement(root, 'info')
    
    # Add info elements in OASIS CAP 1.2 sequence
    if 'language' in data:
        _add_element(info_elem, 'language', data['language'])
    
    _add_list_elements(info_elem, 'category', data.get('category', ['Other']))
    _add_element(info_elem, 'event', data.get('event', 'N/A'))
    _add_list_elements(info_elem, 'responseType', data.get('responseType', []))
    _add_element(info_elem, 'urgency', data.get('urgency', 'Unknown'))
    _add_element(info_elem, 'severity', data.get('severity', 'Unknown'))
    _add_element(info_elem, 'certainty', data.get('certainty', 'Unknown'))
    
    if 'audience' in data:
        _add_element(info_elem, 'audience', data['audience'])
    
    _add_name_value_elements(info_elem, 'eventCode', data.get('eventCode', []))
    
    if 'effective' in data:
        _add_element(info_elem, 'effective', _format_datetime(data['effective']))
    
    if 'onset' in data:
        _add_element(info_elem, 'onset', _format_datetime(data['onset']))
    
    if 'expires' in data:
        _add_element(info_elem, 'expires', _format_datetime(data['expires']))
    
    if 'senderName' in data:
        _add_element(info_elem, 'senderName', data['senderName'])
    
    if 'headline' in data:
        headline = str(data['headline'])
        # OASIS recommendation: headline should be concise (160 chars recommended)
        if len(headline) > 160:
            # This is a warning, not an error - we'll still include it
            pass
        _add_element(info_elem, 'headline', headline)
    
    if 'description' in data:
        _add_element(info_elem, 'description', data['description'])
    
    if 'instruction' in data:
        _add_element(info_elem, 'instruction', data['instruction'])
    
    if 'web' in data:
        _validate_uri_format(data['web'])
        _add_element(info_elem, 'web', data['web'])
    
    if 'contact' in data:
        _add_element(info_elem, 'contact', data['contact'])
    
    _add_name_value_elements(info_elem, 'parameter', data.get('parameter', []))
    
    # Add complex elements (resource, area)
    for resource_data in data.get('resource', []):
        _add_resource_element(info_elem, resource_data)
    
    for area_data in data.get('area', []):
        _add_area_element(info_elem, area_data)


def _validate_required_info_fields(data: Dict[str, Any]):
    """
    Validates required fields at the info level according to OASIS CAP 1.2.
    """
    required_fields = ['category', 'event', 'urgency', 'severity', 'certainty']
    
    for field in required_fields:
        if field not in data or data[field] is None:
            raise CAPValidationError(f"Required info field '{field}' is missing or None")
        
        # Category must be non-empty list
        if field == 'category':
            if not isinstance(data[field], list) or len(data[field]) == 0:
                raise CAPValidationError("Category must be a non-empty list")


def _add_resource_element(parent: ET.Element, data: Dict[str, Any]):
    """
    Adds a <resource> element in the correct OASIS sequence.
    """
    if not isinstance(data, dict):
        raise CAPValidationError("Resource data must be a dictionary")
    
    # resourceDesc is required for resource elements
    if 'resourceDesc' not in data:
        raise CAPValidationError("Resource element requires 'resourceDesc' field")
    
    res_elem = ET.SubElement(parent, 'resource')
    _add_element(res_elem, 'resourceDesc', data['resourceDesc'])
    
    # mimeType is optional but recommended
    if 'mimeType' in data:
        _validate_mime_type(data['mimeType'])
        _add_element(res_elem, 'mimeType', data['mimeType'])
    
    if 'size' in data:
        # Validate size is a positive integer
        try:
            size_val = int(data['size'])
            if size_val < 0:
                raise ValueError("Size must be non-negative")
            _add_element(res_elem, 'size', str(size_val))
        except (ValueError, TypeError) as e:
            raise CAPContentError(f"Invalid size value: {data['size']}", element='size') from e
    
    if 'uri' in data:
        _validate_uri_format(data['uri'])
        _add_element(res_elem, 'uri', data['uri'])
    
    if 'derefUri' in data:
        # derefUri should be base64 encoded data
        _add_element(res_elem, 'derefUri', data['derefUri'])
    
    if 'digest' in data:
        # Validate SHA-1 digest format (40 hex characters) - Fixed regex
        if not re.match(r'^[a-fA-F0-9]{40}$', str(data['digest'])):
            raise CAPContentError(
                f"Digest must be a 40-character SHA-1 hash: {data['digest']}", 
                element='digest'
            )
        _add_element(res_elem, 'digest', data['digest'])


def _add_area_element(parent: ET.Element, data: Dict[str, Any]):
    """
    Adds an <area> element in the correct OASIS sequence.
    """
    if not isinstance(data, dict):
        raise CAPValidationError("Area data must be a dictionary")
    
    # areaDesc is required
    if 'areaDesc' not in data:
        raise CAPValidationError("Area element requires 'areaDesc' field")
    
    area_elem = ET.SubElement(parent, 'area')
    _add_element(area_elem, 'areaDesc', data['areaDesc'])
    
    # Validate and add geographic elements
    polygons = data.get('polygon', [])
    for polygon in polygons:
        _validate_polygon_format(polygon)
        _add_element(area_elem, 'polygon', polygon)
    
    circles = data.get('circle', [])
    for circle in circles:
        _validate_circle_format(circle)
        _add_element(area_elem, 'circle', circle)
    
    _add_name_value_elements(area_elem, 'geocode', data.get('geocode', []))
    
    if 'altitude' in data:
        try:
            alt_val = float(data['altitude'])
            _add_element(area_elem, 'altitude', str(alt_val))
        except (ValueError, TypeError):
            raise CAPGeographicError(
                f"Invalid altitude value: {data['altitude']}", 
                geographic_element='altitude'
            )
    
    if 'ceiling' in data:
        if 'altitude' not in data:
            raise CAPContentError(
                "Ceiling element requires altitude element to be present",
                element='ceiling',
                constraint_type='conditional'
            )
        try:
            ceiling_val = float(data['ceiling'])
            alt_val = float(data['altitude'])
            if ceiling_val <= alt_val:
                raise CAPGeographicError(
                    f"Ceiling ({ceiling_val}) must be greater than altitude ({alt_val})",
                    geographic_element='ceiling'
                )
            _add_element(area_elem, 'ceiling', str(ceiling_val))
        except (ValueError, TypeError):
            raise CAPGeographicError(
                f"Invalid ceiling value: {data['ceiling']}", 
                geographic_element='ceiling'
            )


# Helper functions for adding elements
def _add_element(parent: ET.Element, tag: str, text: Any):
    """
    Adds a single element with text content if the text is not None.
    """
    if text is not None:
        elem = ET.SubElement(parent, tag)
        # Sanitize text content and validate encoding
        text_str = _sanitize_text_content(str(text))
        elem.text = text_str


def _add_list_elements(parent: ET.Element, tag: str, items: List[Any]):
    """
    Adds multiple elements for a list of items.
    """
    if not isinstance(items, list):
        items = [items] if items else []  # Convert single item to list
    
    for item in items:
        if item is not None:  # Skip None items
            _add_element(parent, tag, item)


def _add_name_value_elements(parent: ET.Element, tag: str, items: List[Dict[str, str]]):
    """
    Adds elements for a list of name/value dictionaries (e.g., eventCode, parameter, geocode).
    """
    if not isinstance(items, list):
        items = [items] if items else []
    
    for item in items:
        if isinstance(item, dict) and 'valueName' in item and 'value' in item:
            elem = ET.SubElement(parent, tag)
            _add_element(elem, 'valueName', item['valueName'])
            _add_element(elem, 'value', item['value'])
        else:
            raise CAPContentError(
                f"Invalid {tag} format. Must have 'valueName' and 'value' fields",
                element=tag
            )


def _format_datetime(dt_input: Union[datetime, str, None]) -> Optional[str]:
    """
    Parses and formats various datetime inputs into a standard CAP timestamp.
    """
    if not dt_input:
        return None
    
    if isinstance(dt_input, datetime):
        return format_cap_timestamp(dt_input)
    
    try:
        # Parse string datetime
        dt_str = str(dt_input).strip()
        
        # Handle various input formats
        if dt_str.endswith('Z'):
            dt_str = dt_str[:-1] + '+00:00'
        
        dt = datetime.fromisoformat(dt_str)
        return format_cap_timestamp(dt)
        
    except (ValueError, TypeError) as e:
        raise CAPDateTimeError(
            f"Unable to parse datetime: {dt_input}",
            datetime_value=str(dt_input)
        ) from e


def _sanitize_text_content(text: str) -> str:
    """
    Sanitizes text content according to OASIS CAP 1.2 requirements.
    
    - Normalizes whitespace
    - Validates character encoding
    - Removes prohibited character entities
    """
    if not isinstance(text, str):
        text = str(text)
    
    # Normalize whitespace (collapse multiple spaces, trim)
    text = ' '.join(text.split())
    
    # Check for prohibited character entities (OASIS discourages HTML entities)
    if re.search(r'&[a-zA-Z][a-zA-Z0-9]*;', text):
        raise CAPEncodingError(
            "HTML character entities are discouraged in CAP content",
            problematic_content=text
        )
    
    # Validate UTF-8 compatibility
    try:
        text.encode('utf-8')
    except UnicodeEncodeError as e:
        raise CAPEncodingError(
            f"Text content contains invalid UTF-8 characters: {e}",
            problematic_content=text
        ) from e
    
    return text


def _validate_uri_format(uri: str):
    """
    Validates URI format according to RFC 2396 as required by OASIS CAP 1.2.
    """
    if not isinstance(uri, str) or not uri.strip():
        raise CAPContentError("URI cannot be empty", element='uri')
    
    # Basic URI format validation
    uri_pattern = r'^https?://[^\s/$.?#].[^\s]*$|^[a-zA-Z][a-zA-Z0-9+.-]*:'
    if not re.match(uri_pattern, uri):
        raise CAPContentError(f"Invalid URI format: {uri}", element='uri')


def _validate_mime_type(mime_type: str):
    """
    Validates MIME type format according to RFC 2046.
    """
    if not isinstance(mime_type, str) or not mime_type.strip():
        raise CAPContentError("MIME type cannot be empty", element='mimeType')
    
    # MIME type format: type/subtype - Fixed regex pattern
    mime_pattern = r'^[a-zA-Z][a-zA-Z0-9][a-zA-Z0-9\-\.]*/[a-zA-Z0-9][a-zA-Z0-9\-\.]*$'
    if not re.match(mime_pattern, mime_type):
        raise CAPContentError(f"Invalid MIME type format: {mime_type}", element='mimeType')


def _validate_polygon_format(polygon: str):
    """
    Validates polygon coordinate format according to OASIS CAP 1.2.
    
    Requirements:
    - Minimum 4 coordinate pairs
    - First and last coordinate pairs must be the same (closed polygon)
    - Coordinates in WGS 84 format (latitude,longitude)
    """
    if not isinstance(polygon, str) or not polygon.strip():
        raise CAPGeographicError("Polygon cannot be empty", geographic_element='polygon')
    
    try:
        coords = polygon.strip().split()
        if len(coords) < 4:
            raise CAPGeographicError(
                f"Polygon must have at least 4 coordinate pairs, got {len(coords)}",
                coordinates=polygon,
                geographic_element='polygon'
            )
        
        # Validate coordinate format and values
        parsed_coords = []
        for coord in coords:
            if ',' not in coord:
                raise CAPGeographicError(
                    f"Invalid coordinate format: {coord}. Expected 'latitude,longitude'",
                    coordinates=coord,
                    geographic_element='polygon'
                )
            
            lat_str, lon_str = coord.split(',', 1)
            try:
                lat = float(lat_str)
                lon = float(lon_str)
                
                # Validate WGS 84 coordinate ranges
                if not (-90 <= lat <= 90):
                    raise CAPGeographicError(
                        f"Latitude must be between -90 and 90: {lat}",
                        coordinates=coord,
                        geographic_element='polygon'
                    )
                
                if not (-180 <= lon <= 180):
                    raise CAPGeographicError(
                        f"Longitude must be between -180 and 180: {lon}",
                        coordinates=coord,
                        geographic_element='polygon'
                    )
                
                parsed_coords.append((lat, lon))
                
            except ValueError:
                raise CAPGeographicError(
                    f"Invalid coordinate values: {coord}",
                    coordinates=coord,
                    geographic_element='polygon'
                )
        
        # Check if polygon is closed (first and last points must be the same)
        if parsed_coords[0] != parsed_coords[-1]:
            raise CAPGeographicError(
                "Polygon must be closed (first and last coordinate pairs must be the same)",
                coordinates=polygon,
                geographic_element='polygon'
            )
            
    except Exception as e:
        if isinstance(e, CAPGeographicError):
            raise
        raise CAPGeographicError(
            f"Invalid polygon format: {str(e)}",
            coordinates=polygon,
            geographic_element='polygon'
        ) from e


def _validate_circle_format(circle: str):
    """
    Validates circle format according to OASIS CAP 1.2.
    
    Format: "latitude,longitude radius_in_km"
    """
    if not isinstance(circle, str) or not circle.strip():
        raise CAPGeographicError("Circle cannot be empty", geographic_element='circle')
    
    try:
        parts = circle.strip().split()
        if len(parts) != 2:
            raise CAPGeographicError(
                f"Circle format must be 'latitude,longitude radius_km': {circle}",
                coordinates=circle,
                geographic_element='circle'
            )
        
        coord_part, radius_part = parts
        
        # Validate coordinate
        if ',' not in coord_part:
            raise CAPGeographicError(
                f"Invalid coordinate format: {coord_part}. Expected 'latitude,longitude'",
                coordinates=circle,
                geographic_element='circle'
            )
        
        lat_str, lon_str = coord_part.split(',', 1)
        lat = float(lat_str)
        lon = float(lon_str)
        
        # Validate WGS 84 coordinate ranges
        if not (-90 <= lat <= 90):
            raise CAPGeographicError(
                f"Latitude must be between -90 and 90: {lat}",
                coordinates=circle,
                geographic_element='circle'
            )
        
        if not (-180 <= lon <= 180):
            raise CAPGeographicError(
                f"Longitude must be between -180 and 180: {lon}",
                coordinates=circle,
                geographic_element='circle'
            )
        
        # Validate radius
        radius = float(radius_part)
        if radius <= 0:
            raise CAPGeographicError(
                f"Circle radius must be positive: {radius}",
                coordinates=circle,
                geographic_element='circle'
            )
            
    except ValueError as e:
        raise CAPGeographicError(
            f"Invalid circle coordinate or radius values: {circle}",
            coordinates=circle,
            geographic_element='circle'
        ) from e
    except Exception as e:
        if isinstance(e, CAPGeographicError):
            raise
        raise CAPGeographicError(
            f"Invalid circle format: {str(e)}",
            coordinates=circle,
            geographic_element='circle'
        ) from e