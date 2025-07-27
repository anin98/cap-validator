"""Utility functions for CAP validation."""

import re
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from .exceptions import CAPDateTimeError, CAPGeographicError


def parse_datetime(dt_str: str) -> datetime:
    """
    Parse CAP datetime string to datetime object.
    
    CAP uses ISO 8601 format: YYYY-MM-DDTHH:MM:SS+/-HHMM
    
    Args:
        dt_str: ISO 8601 datetime string
        
    Returns:
        datetime object with timezone info
        
    Raises:
        CAPDateTimeError: If datetime cannot be parsed
    """
    if not dt_str:
        raise CAPDateTimeError("Empty datetime string")
    
    # Remove any whitespace
    dt_str = dt_str.strip()
    
    # Common ISO 8601 formats used in CAP
    formats = [
        "%Y-%m-%dT%H:%M:%S%z",      # With timezone
        "%Y-%m-%dT%H:%M:%S.%f%z",   # With microseconds and timezone
        "%Y-%m-%dT%H:%M:%SZ",       # UTC (Z suffix)
        "%Y-%m-%dT%H:%M:%S.%fZ",    # UTC with microseconds
        "%Y-%m-%dT%H:%M:%S",        # No timezone (assume UTC)
    ]
    
    # Handle 'Z' suffix by replacing with +00:00
    if dt_str.endswith('Z'):
        dt_str = dt_str[:-1] + '+00:00'
    
    for fmt in formats:
        try:
            dt = datetime.strptime(dt_str, fmt)
            # If no timezone info, assume UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    
    raise CAPDateTimeError(f"Unable to parse datetime: {dt_str}")


def format_datetime(dt: datetime) -> str:
    """
    Format datetime for CAP output.
    
    Args:
        dt: datetime object to format
        
    Returns:
        ISO 8601 formatted string
    """
    return dt.isoformat()


def validate_coordinates(lat: float, lon: float) -> bool:
    """
    Validate latitude and longitude values.
    
    Args:
        lat: Latitude value
        lon: Longitude value
        
    Returns:
        True if coordinates are valid, False otherwise
    """
    return -90 <= lat <= 90 and -180 <= lon <= 180


def parse_coordinate_pair(coord_str: str) -> Tuple[float, float]:
    """
    Parse 'lat,lon' string into float tuple.
    
    Args:
        coord_str: Coordinate string in format 'lat,lon'
        
    Returns:
        Tuple of (latitude, longitude)
        
    Raises:
        CAPGeographicError: If coordinate format is invalid
    """
    try:
        parts = coord_str.strip().split(',')
        if len(parts) != 2:
            raise ValueError("Coordinate must be in 'lat,lon' format")
        
        lat, lon = float(parts[0]), float(parts[1])
        
        if not validate_coordinates(lat, lon):
            raise ValueError(f"Invalid coordinates: lat={lat}, lon={lon}")
            
        return lat, lon
    except (ValueError, IndexError) as e:
        raise CAPGeographicError(f"Invalid coordinate format: {coord_str}") from e


def validate_polygon(polygon_str: str) -> bool:
    """
    Validate polygon coordinate string.
    
    Format: lat1,lon1 lat2,lon2 lat3,lon3 ... lat1,lon1
    
    Args:
        polygon_str: Polygon coordinate string
        
    Returns:
        True if polygon is valid, False otherwise
    """
    try:
        coords = polygon_str.strip().split()
        if len(coords) < 4:  # Need at least 3 points + closing point
            return False
            
        parsed_coords = []
        for coord in coords:
            lat, lon = parse_coordinate_pair(coord)
            parsed_coords.append((lat, lon))
        
        # First and last coordinates should be the same (closed polygon)
        if parsed_coords[0] != parsed_coords[-1]:
            return False
            
        return True
    except Exception:
        return False


def validate_circle(circle_str: str) -> bool:
    """
    Validate circle coordinate string.
    
    Format: lat,lon radius
    
    Args:
        circle_str: Circle coordinate string
        
    Returns:
        True if circle is valid, False otherwise
    """
    try:
        parts = circle_str.strip().split()
        if len(parts) != 2:
            return False
            
        # Validate center coordinates
        lat, lon = parse_coordinate_pair(parts[0])
        
        # Validate radius (should be positive number)
        radius = float(parts[1])
        if radius <= 0:
            return False
            
        return True
    except Exception:
        return False


def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace in text fields.
    
    Args:
        text: Input text
        
    Returns:
        Text with normalized whitespace
    """
    if not text:
        return text
    return ' '.join(text.split())


def validate_email_format(email: str) -> bool:
    """
    Basic email format validation.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if email format is valid, False otherwise
    """
    if not email:
        return False
    
    # Basic email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_uri_format(uri: str) -> bool:
    """
    Basic URI format validation.
    
    Args:
        uri: URI to validate
        
    Returns:
        True if URI format is valid, False otherwise
    """
    if not uri:
        return False
    
    # Basic URI pattern for HTTP(S) URLs
    pattern = r'^https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?(?:/.*)?$'
    return bool(re.match(pattern, uri))


def sanitize_identifier(identifier: str) -> str:
    """
    Sanitize identifier string.
    
    Args:
        identifier: Input identifier
        
    Returns:
        Sanitized identifier
    """
    if not identifier:
        return identifier
    
    # Remove leading/trailing whitespace and limit length
    sanitized = identifier.strip()
    if len(sanitized) > 255:
        sanitized = sanitized[:255]
    
    return sanitized