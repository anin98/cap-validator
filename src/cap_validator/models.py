# src/cap_validator/models.py

"""
Enhanced Pydantic models for OASIS CAP 1.2 compliance.

This module provides comprehensive Pydantic models that enforce all OASIS CAP 1.2
requirements, including field validation, format checking, and business rules.
"""

from datetime import datetime, timezone
from typing import List, Optional, Union, Literal
from pydantic import BaseModel, Field, field_validator, model_validator
import re

from .exceptions import CAPValidationError, CAPDateTimeError, CAPContentError, CAPGeographicError

# Type literals for better IDE support and validation
Status = Literal["Actual", "Exercise", "System", "Test", "Draft"]
MsgType = Literal["Alert", "Update", "Cancel", "Ack", "Error"]
Scope = Literal["Public", "Restricted", "Private"]
Category = Literal["Geo", "Met", "Safety", "Security", "Rescue", "Fire", "Health", "Env", "Transport", "Infra", "CBRNE", "Other"]
ResponseType = Literal["Shelter", "Evacuate", "Prepare", "Execute", "Avoid", "Monitor", "Assess", "AllClear", "None"]
Urgency = Literal["Immediate", "Expected", "Future", "Past", "Unknown"]
Severity = Literal["Extreme", "Severe", "Moderate", "Minor", "Unknown"]
Certainty = Literal["Observed", "Likely", "Possible", "Unlikely", "Unknown"]

# OASIS CAP 1.2 datetime pattern
CAP_DATETIME_PATTERN = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
URI_PATTERN = re.compile(r'^https?://[^\s/$.?#].[^\s]*$|^[a-zA-Z][a-zA-Z0-9+.-]*:')


class Parameter(BaseModel):
    """
    Model for parameter elements (name/value pairs).
    """
    valueName: str = Field(..., min_length=1, description="Parameter name")
    value: str = Field(..., description="Parameter value")
    
    @field_validator('valueName')
    @classmethod
    def validate_value_name(cls, v):
        if not v or not v.strip():
            raise CAPContentError("Parameter valueName cannot be empty", element='parameter.valueName')
        # OASIS recommendation: acronyms should be uppercase without periods
        return v.strip()
    
    @field_validator('value')
    @classmethod 
    def validate_value(cls, v):
        if v is None:
            raise CAPContentError("Parameter value cannot be None", element='parameter.value')
        return str(v).strip()


class Geocode(BaseModel):
    """
    Model for geocode elements (geographic code name/value pairs).
    """
    valueName: str = Field(..., min_length=1, description="Geographic code name")
    value: str = Field(..., min_length=1, description="Geographic code value")
    
    @field_validator('valueName')
    @classmethod
    def validate_value_name(cls, v):
        if not v or not v.strip():
            raise CAPContentError("Geocode valueName cannot be empty", element='geocode.valueName')
        # OASIS recommendation: acronyms should be uppercase without periods
        return v.strip()
    
    @field_validator('value')
    @classmethod
    def validate_value(cls, v):
        if not v or not v.strip():
            raise CAPContentError("Geocode value cannot be empty", element='geocode.value')
        return v.strip()


class Resource(BaseModel):
    """
    Model for resource elements containing supplemental information.
    """
    resourceDesc: str = Field(..., min_length=1, description="Resource description")
    mimeType: Optional[str] = Field(None, description="MIME content type")
    size: Optional[int] = Field(None, ge=0, description="Resource size in bytes")
    uri: Optional[str] = Field(None, description="Resource URI")
    derefUri: Optional[str] = Field(None, description="Base64 encoded resource content")
    digest: Optional[str] = Field(None, description="SHA-1 digest of resource")
    
    @field_validator('resourceDesc')
    @classmethod
    def validate_resource_desc(cls, v):
        if not v or not v.strip():
            raise CAPContentError("Resource description cannot be empty", element='resourceDesc')
        return v.strip()
    
    @field_validator('mimeType')
    @classmethod
    def validate_mime_type(cls, v):
        if v is not None:
            if not v or not v.strip():
                raise CAPContentError("MIME type cannot be empty if provided", element='mimeType')
            # Basic MIME type validation
            mime_pattern = r'^[a-zA-Z][a-zA-Z0-9][a-zA-Z0-9\-\.]*/[a-zA-Z0-9][a-zA-Z0-9\-\.]*$'
            if not re.match(mime_pattern, v.strip()):
                raise CAPContentError(f"Invalid MIME type format: {v}", element='mimeType')
        return v.strip() if v else None
    
    @field_validator('uri')
    @classmethod
    def validate_uri(cls, v):
        if v is not None:
            if not v or not v.strip():
                raise CAPContentError("URI cannot be empty if provided", element='uri')
            # Basic URI validation
            from urllib.parse import urlparse
            try:
                result = urlparse(v.strip())
                if not (result.scheme and result.netloc):
                    raise CAPContentError(f"Invalid URI format: {v}", element='uri')
            except Exception:
                raise CAPContentError(f"Invalid URI format: {v}", element='uri')
        return v.strip() if v else None
    
    @field_validator('digest')
    @classmethod
    def validate_digest(cls, v):
        if v is not None:
            if not v or not v.strip():
                raise CAPContentError("Digest cannot be empty if provided", element='digest')
            # SHA-1 digest should be 40 hex characters
            if not re.match(r'^[a-fA-F0-9]{40}$', v.strip()):
                raise CAPContentError(
                    f"Digest must be a 40-character SHA-1 hash: {v}", 
                    element='digest'
                )
        return v.strip() if v else None


class Area(BaseModel):
    """
    Model for area elements describing affected geographic areas.
    """
    areaDesc: str = Field(..., min_length=1, description="Area description")
    polygon: Optional[List[str]] = Field(None, description="Polygon coordinates")
    circle: Optional[List[str]] = Field(None, description="Circle coordinates")
    geocode: Optional[List[Geocode]] = Field(None, description="Geographic codes")
    altitude: Optional[float] = Field(None, description="Altitude in feet above sea level")
    ceiling: Optional[float] = Field(None, description="Ceiling in feet above sea level")
    
    @field_validator('areaDesc')
    @classmethod
    def validate_area_desc(cls, v):
        if not v or not v.strip():
            raise CAPContentError("Area description cannot be empty", element='areaDesc')
        return v.strip()
    
    @field_validator('polygon')
    @classmethod
    def validate_polygon(cls, v):
        if v is not None:
            for i, polygon in enumerate(v):
                if not polygon or not polygon.strip():
                    raise CAPGeographicError(f"Polygon {i} cannot be empty", geographic_element='polygon')
                cls._validate_polygon_format(polygon.strip(), i)
        return v
    
    @field_validator('circle')
    @classmethod
    def validate_circle(cls, v):
        if v is not None:
            for i, circle in enumerate(v):
                if not circle or not circle.strip():
                    raise CAPGeographicError(f"Circle {i} cannot be empty", geographic_element='circle')
                cls._validate_circle_format(circle.strip(), i)
        return v
    
    @model_validator(mode='after')
    def validate_altitude_ceiling(self):
        if self.ceiling is not None and self.altitude is None:
            raise CAPContentError(
                "Ceiling requires altitude to be specified",
                element='ceiling',
                constraint_type='conditional'
            )
        
        if self.altitude is not None and self.ceiling is not None:
            if self.ceiling <= self.altitude:
                raise CAPGeographicError(
                    f"Ceiling ({self.ceiling}) must be greater than altitude ({self.altitude})",
                    geographic_element='ceiling'
                )
        
        return self
    
    @staticmethod
    def _validate_polygon_format(polygon: str, index: int):
        """Validate polygon coordinate format."""
        coords = polygon.split()
        if len(coords) < 4:
            raise CAPGeographicError(
                f"Polygon {index} must have at least 4 coordinate pairs, got {len(coords)}",
                coordinates=polygon,
                geographic_element='polygon'
            )
        
        # Parse and validate coordinates
        parsed_coords = []
        for coord in coords:
            if ',' not in coord:
                raise CAPGeographicError(
                    f"Invalid coordinate format in polygon {index}: {coord}. Expected 'latitude,longitude'",
                    coordinates=coord,
                    geographic_element='polygon'
                )
            
            try:
                lat_str, lon_str = coord.split(',', 1)
                lat = float(lat_str)
                lon = float(lon_str)
                
                # Validate WGS 84 ranges
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
                    f"Invalid coordinate values in polygon {index}: {coord}",
                    coordinates=coord,
                    geographic_element='polygon'
                )
        
        # Check if polygon is closed
        if parsed_coords[0] != parsed_coords[-1]:
            raise CAPGeographicError(
                f"Polygon {index} must be closed (first and last points must match)",
                coordinates=polygon,
                geographic_element='polygon'
            )
    
    @staticmethod
    def _validate_circle_format(circle: str, index: int):
        """Validate circle coordinate format."""
        parts = circle.split()
        if len(parts) != 2:
            raise CAPGeographicError(
                f"Circle {index} format must be 'latitude,longitude radius_km': {circle}",
                coordinates=circle,
                geographic_element='circle'
            )
        
        coord_part, radius_part = parts
        
        # Validate coordinate
        if ',' not in coord_part:
            raise CAPGeographicError(
                f"Invalid coordinate format in circle {index}: {coord_part}. Expected 'latitude,longitude'",
                coordinates=circle,
                geographic_element='circle'
            )
        
        try:
            lat_str, lon_str = coord_part.split(',', 1)
            lat = float(lat_str)
            lon = float(lon_str)
            
            # Validate WGS 84 ranges
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
                    f"Circle {index} radius must be positive: {radius}",
                    coordinates=circle,
                    geographic_element='circle'
                )
                
        except ValueError:
            raise CAPGeographicError(
                f"Invalid coordinate or radius values in circle {index}: {circle}",
                coordinates=circle,
                geographic_element='circle'
            )


class Info(BaseModel):
    """
    Model for info elements containing alert information.
    """
    language: Optional[str] = Field("en-US", description="Language code (RFC 3066)")
    category: List[Category] = Field(..., min_length=1, description="Event categories")
    event: str = Field(..., min_length=1, description="Event description")
    responseType: Optional[List[ResponseType]] = Field(None, description="Recommended response types")
    urgency: Urgency = Field(..., description="Urgency level")
    severity: Severity = Field(..., description="Severity level")
    certainty: Certainty = Field(..., description="Certainty level")
    audience: Optional[str] = Field(None, description="Intended audience")
    eventCode: Optional[List[Parameter]] = Field(None, description="Event codes")
    effective: Optional[datetime] = Field(None, description="Effective time")
    onset: Optional[datetime] = Field(None, description="Event onset time")
    expires: Optional[datetime] = Field(None, description="Expiration time")
    senderName: Optional[str] = Field(None, description="Sender name")
    headline: Optional[str] = Field(None, max_length=160, description="Alert headline")
    description: Optional[str] = Field(None, description="Event description")
    instruction: Optional[str] = Field(None, description="Response instructions")
    web: Optional[str] = Field(None, description="Reference URI")
    contact: Optional[str] = Field(None, description="Contact information")
    parameter: Optional[List[Parameter]] = Field(None, description="Additional parameters")
    resource: Optional[List[Resource]] = Field(None, description="Associated resources")
    area: Optional[List[Area]] = Field(None, description="Affected areas")
    
    @field_validator('language')
    @classmethod
    def validate_language(cls, v):
        if v is not None:
            # RFC 3066 language code validation - Fixed regex pattern
            lang_pattern = r'^[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*$'
            if not re.match(lang_pattern, v):
                raise CAPContentError(
                    f"Invalid language code: {v}. Expected RFC 3066 format",
                    element='language'
                )
        return v or "en-US"
    
    @field_validator('category')
    @classmethod
    def validate_category(cls, v):
        if not v or len(v) == 0:
            raise CAPContentError("At least one category is required", element='category')
        return v
    
    @field_validator('event')
    @classmethod
    def validate_event(cls, v):
        if not v or not v.strip():
            raise CAPContentError("Event description cannot be empty", element='event')
        return v.strip()
    
    @field_validator('headline')
    @classmethod
    def validate_headline(cls, v):
        if v is not None:
            if len(v) > 160:
                # OASIS recommendation, not a hard requirement
                pass  # Could issue warning
            return v.strip() if v.strip() else None
        return v
    
    @field_validator('web')
    @classmethod
    def validate_web(cls, v):
        if v is not None:
            if not v.strip():
                raise CAPContentError("Web URI cannot be empty if provided", element='web')
            # Basic URI validation
            from urllib.parse import urlparse
            try:
                result = urlparse(v.strip())
                if not (result.scheme and result.netloc):
                    raise CAPContentError(f"Invalid URI format: {v}", element='web')
            except Exception:
                raise CAPContentError(f"Invalid URI format: {v}", element='web')
        return v.strip() if v and v.strip() else None
    
    @field_validator('effective', 'onset', 'expires')
    @classmethod
    def validate_datetime_fields(cls, v):
        if v is not None:
            # Ensure timezone info is present
            if v.tzinfo is None:
                v = v.replace(tzinfo=timezone.utc)
            
            # Validate format by converting to string and checking pattern
            dt_str = v.isoformat(sep='T', timespec='seconds')
            if dt_str.endswith('Z'):
                dt_str = dt_str[:-1] + '-00:00'
            elif dt_str.endswith('+00:00'):
                dt_str = dt_str[:-6] + '-00:00'
            
            if not CAP_DATETIME_PATTERN.match(dt_str):
                raise CAPDateTimeError(
                    f"Invalid datetime format: {dt_str}",
                    datetime_value=dt_str
                )
        return v
    
    @model_validator(mode='after')
    def validate_time_relationships(self):
        """Validate logical relationships between time fields."""
        # Effective should be before expires
        if self.effective and self.expires and self.effective >= self.expires:
            raise CAPDateTimeError(
                "Effective time must be before expires time",
                datetime_value=f"effective={self.effective}, expires={self.expires}"
            )
        
        # Onset should be before expires
        if self.onset and self.expires and self.onset >= self.expires:
            raise CAPDateTimeError(
                "Onset time must be before expires time",
                datetime_value=f"onset={self.onset}, expires={self.expires}"
            )
        
        return self


class Alert(BaseModel):
    """
    Model for the root alert element.
    """
    identifier: str = Field(..., min_length=1, description="Alert identifier")
    sender: str = Field(..., min_length=1, description="Alert sender")
    sent: datetime = Field(..., description="Time alert was sent")
    status: Status = Field(..., description="Alert status")
    msgType: MsgType = Field(..., description="Message type")
    source: Optional[str] = Field(None, description="Alert source")
    scope: Scope = Field(..., description="Alert scope")
    restriction: Optional[str] = Field(None, description="Restriction text")
    addresses: Optional[str] = Field(None, description="Private alert addresses")
    code: Optional[List[str]] = Field(None, description="Special handling codes")
    note: Optional[str] = Field(None, description="Alert note")
    references: Optional[str] = Field(None, description="References to other alerts")
    incidents: Optional[str] = Field(None, description="Related incidents")
    info: Optional[List[Info]] = Field(None, description="Alert information blocks")
    
    @field_validator('identifier')
    @classmethod
    def validate_identifier(cls, v):
        if not v or not v.strip():
            raise CAPValidationError("Alert identifier cannot be empty")
        
        # Sanitize identifier (remove spaces and commas as per OASIS spec)
        identifier = v.strip()
        if ' ' in identifier or ',' in identifier:
            raise CAPValidationError(
                "Alert identifier cannot contain spaces or commas",
                field='identifier',
                value=v
            )
        
        return identifier
    
    @field_validator('sender')
    @classmethod
    def validate_sender(cls, v):
        if not v or not v.strip():
            raise CAPValidationError("Alert sender cannot be empty")
        
        # OASIS recommends email format for interoperability
        sender = v.strip()
        if not EMAIL_PATTERN.match(sender):
            # This is a recommendation, not a hard requirement
            # Could issue a warning here
            pass
        
        return sender
    
    @field_validator('sent')
    @classmethod
    def validate_sent(cls, v):
        if v is None:
            raise CAPValidationError("Alert sent time is required")
        
        # Ensure timezone info is present
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        
        # Validate format
        dt_str = v.isoformat(sep='T', timespec='seconds')
        if dt_str.endswith('Z'):
            dt_str = dt_str[:-1] + '-00:00'
        elif dt_str.endswith('+00:00'):
            dt_str = dt_str[:-6] + '-00:00'
        
        if not CAP_DATETIME_PATTERN.match(dt_str):
            raise CAPDateTimeError(
                f"Invalid sent datetime format: {dt_str}",
                datetime_value=dt_str
            )
        
        # Validate sent time is reasonable (not too far in future/past)
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        
        if v > now + timedelta(hours=24):
            raise CAPDateTimeError(
                f"Alert sent time is too far in the future: {v}",
                datetime_value=str(v)
            )
        
        if v < now - timedelta(days=365*10):  # 10 years ago
            raise CAPDateTimeError(
                f"Alert sent time is too old: {v}",
                datetime_value=str(v)
            )
        
        return v
    
    @field_validator('references')
    @classmethod
    def validate_references(cls, v):
        if v is not None:
            if not v.strip():
                return None
            
            # Parse references format: "sender,identifier,sent sender,identifier,sent ..."
            references = v.strip()
            ref_parts = references.split()
            
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
        
        return v
    
    @model_validator(mode='after')
    def validate_conditional_fields(self):
        """Validate conditional field requirements."""
        # Restricted scope requires restriction field
        if self.scope == 'Restricted' and not self.restriction:
            raise CAPContentError(
                "Field 'restriction' is required when scope is 'Restricted'",
                element='restriction',
                constraint_type='conditional'
            )
        
        # Private scope requires addresses field
        if self.scope == 'Private' and not self.addresses:
            raise CAPContentError(
                "Field 'addresses' is required when scope is 'Private'",
                element='addresses',
                constraint_type='conditional'
            )
        
        # Update, Cancel, Ack, and Error message types require references
        if self.msgType in ['Update', 'Cancel', 'Ack', 'Error'] and not self.references:
            raise CAPContentError(
                f"Message type '{self.msgType}' requires 'references' field",
                element='references',
                constraint_type='conditional'
            )
        
        return self

    class Config:
        # Pydantic v2 configuration
        validate_assignment = True
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat(sep='T', timespec='seconds')
        }


# Export all models and type literals
__all__ = [
    'Alert',
    'Info',
    'Area',
    'Resource',
    'Parameter',
    'Geocode',
    'Status',
    'MsgType',
    'Scope',
    'Category',
    'ResponseType',
    'Urgency',
    'Severity',
    'Certainty'
]