"""Pydantic models for CAP (Common Alerting Protocol) validation."""

from datetime import datetime, timezone
from typing import List, Literal, Optional, Any, Dict, Union
from pydantic import BaseModel, field_validator, Field, model_validator
from email.utils import parseaddr
import re

from .exceptions import CAPValidationError, CAPDateTimeError, CAPGeographicError
from .utils import (
    parse_datetime, 
    validate_coordinates, 
    validate_polygon, 
    validate_circle,
    validate_email_format,
    validate_uri_format,
    sanitize_identifier,
    normalize_whitespace
)

# CAP 1.2 Standard Literal Types
Status = Literal["Actual", "Exercise", "System", "Test", "Draft"]
MsgType = Literal["Alert", "Update", "Cancel", "Ack", "Error"]
Scope = Literal["Public", "Restricted", "Private"]
Category = Literal["Geo", "Met", "Safety", "Security", "Rescue", "Fire", "Health", "Env", "Transport", "Infra", "CBRNE", "Other"]
ResponseType = Literal["Shelter", "Evacuate", "Prepare", "Execute", "Avoid", "Monitor", "Assess", "AllClear", "None"]
Urgency = Literal["Immediate", "Expected", "Future", "Past", "Unknown"]
Severity = Literal["Extreme", "Severe", "Moderate", "Minor", "Unknown"]
Certainty = Literal["Observed", "Likely", "Possible", "Unlikely", "Unknown"]


class Parameter(BaseModel):
    """CAP Parameter element for key-value pairs."""
    valueName: str
    value: str

    @field_validator('valueName', 'value')
    @classmethod
    def normalize_parameter_text(cls, v):
        """Normalize text in parameters."""
        return normalize_whitespace(v) if v else v


class Geocode(BaseModel):
    """CAP Geocode element for geographic codes."""
    valueName: str
    value: str

    @field_validator('valueName', 'value')
    @classmethod
    def normalize_geocode_text(cls, v):
        """Normalize text in geocodes."""
        return normalize_whitespace(v) if v else v


class Resource(BaseModel):
    """CAP Resource element for embedded or linked resources."""
    resourceDesc: str
    mimeType: Optional[str] = None
    size: Optional[int] = None
    uri: Optional[str] = None
    derefUri: Optional[str] = None
    digest: Optional[str] = None
    
    @field_validator('size')
    @classmethod
    def size_must_be_positive(cls, v):
        """Validate resource size is positive."""
        if v is not None and v <= 0:
            raise ValueError('Resource size must be positive')
        return v
    
    @field_validator('uri', 'derefUri')
    @classmethod
    def validate_uri(cls, v):
        """Validate URI format."""
        if v is not None:
            if not validate_uri_format(v):
                raise ValueError('URI must be a valid HTTP(S) URL')
        return v

    @field_validator('resourceDesc')
    @classmethod
    def normalize_resource_desc(cls, v):
        """Normalize resource description."""
        return normalize_whitespace(v) if v else v


class Area(BaseModel):
    """CAP Area element with comprehensive geographic validation."""
    areaDesc: str
    polygon: Optional[List[str]] = None
    circle: Optional[List[str]] = None
    geocode: Optional[List[Geocode]] = None
    altitude: Optional[float] = None
    ceiling: Optional[float] = None
    
    @field_validator('areaDesc')
    @classmethod
    def normalize_area_desc(cls, v):
        """Normalize area description."""
        return normalize_whitespace(v) if v else v
    
    @field_validator('polygon', mode='before')
    @classmethod
    def normalize_polygon(cls, v):
        """Normalize polygon to list format."""
        if v is None:
            return v
        if isinstance(v, str):
            return [v]
        return v
    
    @field_validator('circle', mode='before')
    @classmethod
    def normalize_circle(cls, v):
        """Normalize circle to list format."""
        if v is None:
            return v
        if isinstance(v, str):
            return [v]
        return v
    
    @field_validator('polygon')
    @classmethod
    def validate_polygon_coordinates(cls, v):
        """Validate polygon coordinate strings."""
        if v:
            for polygon_str in v:
                if not validate_polygon(polygon_str):
                    raise CAPGeographicError(f"Invalid polygon coordinates: {polygon_str}")
        return v
    
    @field_validator('circle')
    @classmethod
    def validate_circle_coordinates(cls, v):
        """Validate circle coordinate strings."""
        if v:
            for circle_str in v:
                if not validate_circle(circle_str):
                    raise CAPGeographicError(f"Invalid circle coordinates: {circle_str}")
        return v
    
    @field_validator('altitude', 'ceiling')
    @classmethod
    def validate_elevation(cls, v):
        """Validate elevation values are reasonable."""
        if v is not None and v < -1000:  # Below Dead Sea level seems unreasonable
            raise ValueError('Elevation value seems unreasonably low')
        return v
    
    @model_validator(mode='after')
    def area_must_have_geographic_info(self):
        """Validate that area has some geographic information."""
        polygon = self.polygon
        circle = self.circle
        geocode = self.geocode
        
        if not any([polygon, circle, geocode]):
            # This is just a warning in some implementations
            # Could be made stricter based on requirements
            pass
            
        return self


class Info(BaseModel):
    """CAP Info element with comprehensive validation."""
    language: Optional[str] = Field("en-US")
    category: List[Category]
    event: str
    responseType: Optional[List[ResponseType]] = None
    urgency: Urgency
    severity: Severity
    certainty: Certainty
    audience: Optional[str] = None
    eventCode: Optional[List[Parameter]] = None
    effective: Optional[datetime] = None
    onset: Optional[datetime] = None
    expires: Optional[datetime] = None
    senderName: str
    headline: Optional[str] = None
    description: Optional[str] = None
    instruction: Optional[str] = None
    web: Optional[str] = None
    contact: Optional[str] = None
    parameter: Optional[List[Parameter]] = None
    resource: Optional[List[Resource]] = None
    area: Optional[List[Area]] = None
    
    @field_validator('language')
    @classmethod
    def validate_language_code(cls, v):
        """Validate RFC 3066 language code."""
        if v and not re.match(r'^[a-z]{2}(-[A-Z]{2})?$', v):
            raise ValueError('Language must be a valid RFC 3066 code (e.g., en-US)')
        return v
    
    @field_validator('category', mode='before')
    @classmethod
    def ensure_category_is_list(cls, v):
        """CAP allows category to be a single item or a list. Normalize to a list."""
        if not isinstance(v, list):
            return [v]
        return v
    
    @field_validator('responseType', mode='before')
    @classmethod
    def normalize_response_type(cls, v):
        """Normalize responseType to list format."""
        if v is None:
            return v
        if isinstance(v, str):
            return [v]
        return v
    
    @field_validator('effective', 'onset', 'expires', mode='before')
    @classmethod
    def parse_datetime_fields(cls, v):
        """Parse datetime strings into datetime objects."""
        if isinstance(v, str):
            return parse_datetime(v)
        return v
    
    @field_validator('web')
    @classmethod
    def validate_web_url(cls, v):
        """Validate web URL format."""
        if v and not validate_uri_format(v):
            raise ValueError('web must be a valid HTTP(S) URL')
        return v
    
    @field_validator('contact')
    @classmethod
    def validate_contact(cls, v):
        """Validate contact information."""
        if v:
            # Check if it looks like an email address
            if '@' in v:
                name, addr = parseaddr(v)
                if not addr or not validate_email_format(addr):
                    raise ValueError('Invalid email format in contact')
        return v
    
    @field_validator('event', 'senderName', 'headline', 'description', 'instruction', 'audience')
    @classmethod
    def normalize_text_fields(cls, v):
        """Normalize whitespace in text fields."""
        return normalize_whitespace(v) if v else v
    
    @model_validator(mode='after')
    def validate_info_consistency(self):
        """Cross-field validation for Info element."""
        # Expires validation
        if self.expires is None:
            raise ValueError('expires is required')
            
        # Check if expires is in the future
        now = datetime.now(timezone.utc)
        if self.expires <= now:
            raise CAPDateTimeError('expires must be in the future')
            
        # Check against effective date
        if self.effective and self.expires <= self.effective:
            raise CAPDateTimeError('expires must be after effective date')
        
        # Onset validation
        if self.onset and self.effective and self.onset < self.effective:
            raise CAPDateTimeError('onset cannot be before effective date')
        
        urgency = self.urgency
        severity = self.severity
        certainty = self.certainty
        
        # WMO AlertWise specific validation
        if urgency == 'Immediate' and severity in ['Minor', 'Unknown']:
            raise CAPValidationError(
                'Immediate urgency should not be used with Minor or Unknown severity',
                field='urgency'
            )
            
        if certainty == 'Unlikely' and urgency == 'Immediate':
            raise CAPValidationError(
                'Unlikely certainty conflicts with Immediate urgency',
                field='certainty'
            )
            
        return self


class Alert(BaseModel):
    """The root CAP Alert model with comprehensive validation."""
    identifier: str
    sender: str
    sent: datetime
    status: Status
    msgType: MsgType
    source: Optional[str] = None
    scope: Scope
    restriction: Optional[str] = None
    addresses: Optional[str] = None
    code: Optional[List[str]] = None
    note: Optional[str] = None
    references: Optional[str] = None
    incidents: Optional[str] = None
    info: Optional[List[Info]] = None
    
    @field_validator('identifier')
    @classmethod
    def validate_identifier(cls, v):
        """Validate CAP identifier format."""
        if not v or len(v.strip()) == 0:
            raise ValueError('identifier cannot be empty')
        
        sanitized = sanitize_identifier(v)
        if len(sanitized) > 255:
            raise ValueError('identifier too long (max 255 characters)')
        return sanitized
    
    @field_validator('sender')
    @classmethod
    def validate_sender(cls, v):
        """Validate sender format (should be an identifier)."""
        if not v or len(v.strip()) == 0:
            raise ValueError('sender cannot be empty')
        
        # Basic email-like format check for sender
        if '@' in v and not validate_email_format(v):
            raise ValueError('sender email format invalid')
        
        return v.strip()
    
    @field_validator('sent', mode='before')
    @classmethod
    def parse_sent_datetime(cls, v):
        """Parse sent datetime."""
        if isinstance(v, str):
            return parse_datetime(v)
        return v
    
    @field_validator('code', mode='before')
    @classmethod
    def normalize_code(cls, v):
        """Normalize code to list."""
        if v is None:
            return v
        if isinstance(v, str):
            return [v]
        return v
    
    @field_validator('references')
    @classmethod
    def validate_references_format(cls, v):
        """Validate references format: sender,identifier,sent"""
        if v is None:
            return v
            
        # References should be space-separated triplets
        refs = v.strip().split()
        for ref in refs:
            parts = ref.split(',')
            if len(parts) != 3:
                raise ValueError(f'Invalid reference format: {ref} (should be sender,identifier,sent)')
            # Validate the datetime part
            try:
                parse_datetime(parts[2])
            except Exception:
                raise ValueError(f'Invalid datetime in reference: {parts[2]}')
        return v
    
    @field_validator('source', 'restriction', 'addresses', 'note', 'incidents')
    @classmethod
    def normalize_optional_text_fields(cls, v):
        """Normalize whitespace in optional text fields."""
        return normalize_whitespace(v) if v else v
    
    @model_validator(mode='after')
    def validate_alert_consistency(self):
        """Comprehensive cross-field validation."""
        msg_type = self.msgType
        references = self.references
        info = self.info
        status = self.status
        scope = self.scope
        
        # Scope validation
        if scope == 'Restricted' and not self.restriction:
            raise ValueError('Restricted scope requires restriction element')
        if scope == 'Private' and not self.addresses:
            raise ValueError('Private scope requires addresses element')
        
        # Update and Cancel must have references
        if msg_type in ['Update', 'Cancel'] and not references:
            raise CAPValidationError(
                f"msgType '{msg_type}' requires references element",
                field='references',
                code='MISSING_REFERENCES'
            )
        
        # Alert, Update must have info blocks (Cancel typically doesn't)
        if msg_type in ['Alert', 'Update']:
            if not info or len(info) == 0:
                raise CAPValidationError(
                    f"msgType '{msg_type}' requires at least one info block",
                    field='info',
                    code='MISSING_INFO'
                )
        
        # Exercise and Test alerts validation
        if status in ['Exercise', 'Test']:
            # Could add specific validation for test alerts
            pass
            
        # Draft alerts should not be distributed
        if status == 'Draft':
            raise CAPValidationError(
                'Draft alerts should not be validated for distribution',
                field='status',
                code='DRAFT_STATUS'
            )
            
        return self