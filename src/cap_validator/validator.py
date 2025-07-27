"""Main validation functions for CAP messages."""

import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional, List
import json

# Handle Pydantic v1/v2 compatibility
try:
    from pydantic import ValidationError
except ImportError:
    from pydantic.v1 import ValidationError

from .models import Alert
from .exceptions import CAPValidationError, CAPStructureError
from .utils import parse_datetime


def validate_cap_dict(cap_data: Dict[str, Any], strict: bool = True) -> Alert:
    """
    Validates a CAP alert provided as a Python dictionary.
    
    Args:
        cap_data: A dictionary representing the CAP alert.
        strict: If True, applies strict WMO AlertWise validation rules.
        
    Returns:
        A validated Alert model instance.
        
    Raises:
        CAPValidationError: If the data is invalid.
    """
    try:
        # Create the Alert model - Pydantic handles most validation
        alert = Alert(**cap_data)
        
        # Additional WMO AlertWise specific validation
        if strict:
            _apply_wmo_alertwise_rules(alert)
            
        return alert
        
    except ValidationError as e:
        # Convert Pydantic errors to our custom exception
        errors = []
        for error in e.errors():
            field = '.'.join(str(x) for x in error['loc'])
            errors.append(f"{field}: {error['msg']}")
        
        raise CAPValidationError(
            f"Validation failed: {'; '.join(errors)}",
            code='VALIDATION_ERROR'
        ) from e
        
    except Exception as e:
        raise CAPValidationError(f"Unexpected validation error: {str(e)}") from e


def validate_cap_xml(xml_string: str, strict: bool = True) -> Alert:
    """
    Parses and validates a CAP alert from an XML string.
    
    Args:
        xml_string: A string containing the CAP XML.
        strict: If True, applies strict WMO AlertWise validation rules.
        
    Returns:
        A validated Alert model instance.
        
    Raises:
        CAPValidationError: If parsing or validation fails.
    """
    try:
        # Parse XML and convert to dictionary
        alert_dict = _xml_to_dict(xml_string)
        
        # Validate using the dictionary validator
        return validate_cap_dict(alert_dict, strict=strict)
        
    except ET.ParseError as e:
        raise CAPStructureError(f"Invalid XML structure: {str(e)}") from e
    except Exception as e:
        if isinstance(e, CAPValidationError):
            raise
        raise CAPValidationError(f"Failed to parse CAP XML: {str(e)}") from e


def validate_cap_file(file_path: str, strict: bool = True) -> Alert:
    """
    Validate CAP alert from file.
    
    Args:
        file_path: Path to the CAP file (XML or JSON)
        strict: If True, applies strict WMO AlertWise validation rules.
        
    Returns:
        A validated Alert model instance.
        
    Raises:
        CAPValidationError: If file reading, parsing, or validation fails.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Detect if it's XML or JSON
        content = content.strip()
        if content.startswith('<'):
            return validate_cap_xml(content, strict=strict)
        else:
            # Assume JSON
            data = json.loads(content)
            return validate_cap_dict(data, strict=strict)
            
    except FileNotFoundError:
        raise CAPValidationError(f"File not found: {file_path}")
    except json.JSONDecodeError as e:
        raise CAPValidationError(f"Invalid JSON format: {str(e)}")
    except Exception as e:
        if isinstance(e, CAPValidationError):
            raise
        raise CAPValidationError(f"Error reading file: {str(e)}")


def _xml_to_dict(xml_string: str) -> Dict[str, Any]:
    """
    Convert CAP XML to dictionary format.
    
    Args:
        xml_string: CAP XML string
        
    Returns:
        Dictionary representation of the CAP alert
        
    Raises:
        CAPStructureError: If XML structure is invalid
    """
    try:
        root = ET.fromstring(xml_string)
        
        # Remove namespace prefixes for simplicity
        for elem in root.iter():
            if '}' in elem.tag:
                elem.tag = elem.tag.split('}')[1]
        
        if root.tag != 'alert':
            raise CAPStructureError("Root element must be 'alert'")
            
        return _element_to_dict(root)
        
    except ET.ParseError as e:
        raise CAPStructureError(f"XML parsing failed: {str(e)}") from e


# It's best to define this at the module level for performance
REPEATABLE_CAP_ELEMENTS = {'info', 'resource', 'area', 'parameter', 'geocode'}

def _element_to_dict(element: ET.Element) -> Dict[str, Any]:
    """
    Recursively convert XML element to dictionary, correctly handling lists.
    
    Args:
        element: XML element to convert
        
    Returns:
        Dictionary representation of the element
    """
    result = {}
    
    # Handle child elements
    children = list(element)
    if children:
        child_dict = {}
        for child in children:
            child_data = _element_to_dict(child)
            tag = child.tag

            # If the tag is not yet in our dictionary
            if tag not in child_dict:
                # If it's a known repeatable element, create a list with the first item
                if tag in REPEATABLE_CAP_ELEMENTS:
                    child_dict[tag] = [child_data]
                # Otherwise, it's a single value
                else:
                    child_dict[tag] = child_data
            # If tag is already present, it must be a list, so append to it
            else:
                # Ensure it's a list (handles cases of invalid XML with duplicate single-value tags)
                if not isinstance(child_dict[tag], list):
                    child_dict[tag] = [child_dict[tag]]
                child_dict[tag].append(child_data)
                
        result.update(child_dict)
    
    # Handle text content
    text = element.text and element.text.strip()
    if not children and text:
        return text  # Element with only text
    
    if text:
        # If element has children/attributes AND text, store text in a special key.
        # This is rare in CAP but good practice for a general parser.
        result['_value'] = text
            
    return result if result else None

def _apply_wmo_alertwise_rules(alert: Alert) -> None:
    """
    Apply WMO AlertWise specific validation rules.
    
    Args:
        alert: Alert instance to validate
        
    Raises:
        CAPValidationError: If WMO-specific validation fails
    """
    
    # WMO AlertWise requires specific sender format
    if not _is_valid_wmo_sender(alert.sender):
        raise CAPValidationError(
            "Sender must follow WMO AlertWise format",
            field='sender',
            code='INVALID_WMO_SENDER'
        )
    
    # Check for required WMO codes in info blocks
    if alert.info:
        for i, info in enumerate(alert.info):
            _validate_wmo_info_block(info, i)


def _is_valid_wmo_sender(sender: str) -> bool:
    """
    Validate WMO AlertWise sender format.
    
    Args:
        sender: Sender identifier to validate
        
    Returns:
        True if sender format is valid for WMO AlertWise
    """
    # WMO typically uses format like: country-code@wmo.int
    # This is a simplified check - adjust based on actual WMO requirements
    return '@' in sender and ('wmo' in sender.lower() or len(sender.split('@')[0]) >= 2)


def _validate_wmo_info_block(info, index: int) -> None:
    """
    Validate WMO-specific requirements for info blocks.
    
    Args:
        info: Info block to validate
        index: Index of the info block for error reporting
        
    Raises:
        CAPValidationError: If WMO-specific validation fails
    """
    
    # WMO AlertWise typically requires certain categories for weather alerts
    meteorological_events = [
        'thunderstorm', 'tornado', 'hurricane', 'flood', 'snow', 'ice',
        'wind', 'rain', 'heat', 'cold', 'drought', 'fog', 'cyclone',
        'typhoon', 'blizzard', 'hail', 'lightning', 'storm'
    ]
    
    if any(keyword in info.event.lower() for keyword in meteorological_events):
        if 'Met' not in info.category:
            raise CAPValidationError(
                f"Meteorological event '{info.event}' should include 'Met' category",
                field=f'info[{index}].category',
                code='MISSING_MET_CATEGORY'
            )
    
    # Ensure reasonable expires time (not too far in future for weather)
    if info.expires:
        from datetime import datetime, timezone, timedelta
        max_future = datetime.now(timezone.utc) + timedelta(days=7)
        if info.expires > max_future:
            raise CAPValidationError(
                f"Expires time too far in future for weather alert: {info.expires}",
                field=f'info[{index}].expires',
                code='EXPIRES_TOO_FAR'
            )
    
    # Validate geographic coverage for meteorological alerts
    if 'Met' in info.category and info.area:
        for j, area in enumerate(info.area):
            if not any([area.polygon, area.circle, area.geocode]):
                raise CAPValidationError(
                    f"Meteorological alert should have specific geographic coverage",
                    field=f'info[{index}].area[{j}]',
                    code='MISSING_GEOGRAPHIC_COVERAGE'
                )


def get_validation_summary(alert: Alert) -> Dict[str, Any]:
    """
    Get a summary of the validated CAP alert.
    
    Args:
        alert: Validated Alert instance
        
    Returns:
        Dictionary containing validation summary information
    """
    summary = {
        'identifier': alert.identifier,
        'sender': alert.sender,
        'sent': alert.sent.isoformat(),
        'status': alert.status,
        'msgType': alert.msgType,
        'scope': alert.scope,
        'info_blocks': len(alert.info) if alert.info else 0,
        'total_areas': 0,
        'categories': set(),
        'urgency_levels': set(),
        'severity_levels': set(),
        'certainty_levels': set(),
        'expires_times': []
    }
    
    if alert.info:
        for info in alert.info:
            summary['categories'].update(info.category)
            summary['urgency_levels'].add(info.urgency)
            summary['severity_levels'].add(info.severity)
            summary['certainty_levels'].add(info.certainty)
            
            if info.expires:
                summary['expires_times'].append(info.expires.isoformat())
            
            if info.area:
                summary['total_areas'] += len(info.area)
    
    # Convert sets to lists for JSON serialization
    summary['categories'] = list(summary['categories'])
    summary['urgency_levels'] = list(summary['urgency_levels'])
    summary['severity_levels'] = list(summary['severity_levels'])
    summary['certainty_levels'] = list(summary['certainty_levels'])
    
    return summary


def validate_multiple_caps(cap_data_list: List[Dict[str, Any]], strict: bool = True) -> List[Alert]:
    """
    Validate multiple CAP alerts.
    
    Args:
        cap_data_list: List of dictionaries representing CAP alerts
        strict: If True, applies strict WMO AlertWise validation rules
        
    Returns:
        List of validated Alert instances
        
    Raises:
        CAPValidationError: If any validation fails
    """
    validated_alerts = []
    errors = []
    
    for i, cap_data in enumerate(cap_data_list):
        try:
            alert = validate_cap_dict(cap_data, strict=strict)
            validated_alerts.append(alert)
        except CAPValidationError as e:
            errors.append(f"Alert {i}: {e.message}")
    
    if errors:
        raise CAPValidationError(f"Multiple validation errors: {'; '.join(errors)}")
    
    return validated_alerts