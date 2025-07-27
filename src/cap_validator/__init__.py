"""
WMO AlertWise CAP Validator Library

A comprehensive Python library for validating Common Alerting Protocol (CAP) messages
according to the WMO AlertWise specifications and CAP 1.2 standard.
"""

from .validator import validate_cap_xml, validate_cap_dict, validate_cap_file
from .models import Alert, Info, Area, Resource, Parameter, Geocode
from .utils import parse_datetime, format_datetime, validate_coordinates
from .exceptions import (
    CAPValidationError, 
    CAPStructureError, 
    CAPContentError, 
    CAPDateTimeError, 
    CAPGeographicError
)

__version__ = "1.0.0"
__all__ = [
    "validate_cap_xml",
    "validate_cap_dict", 
    "validate_cap_file",
    "CAPValidationError",
    "CAPStructureError",
    "CAPContentError", 
    "CAPDateTimeError",
    "CAPGeographicError",
    "Alert",
    "Info", 
    "Area",
    "Resource",
    "Parameter",
    "Geocode",
    "parse_datetime",
    "format_datetime",
    "validate_coordinates"
]