# CAP Validator Usage Documentation

A comprehensive guide to using the CAP Validator library for validating and generating OASIS CAP 1.2 compliant XML messages.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Core Validation Functions](#core-validation-functions)
4. [XML Generation Functions](#xml-generation-functions)
5. [Data Models](#data-models)
6. [Utility Functions](#utility-functions)
7. [Exception Handling](#exception-handling)
8. [Advanced Usage](#advanced-usage)
9. [CLI Usage](#cli-usage)
10. [Examples](#examples)

## Installation

```bash
pip install pycap-validator
```

## Quick Start

```python
import json
from cap_validator import (
    validate_cap_dict,
    generate_cap_xml_from_dict,
    Alert
)

# Load your CAP data
with open('alert.json', 'r') as f:
    cap_data = json.load(f)

# Validate the data
alert = validate_cap_dict(cap_data)

# Generate XML
xml_content = generate_cap_xml_from_dict(cap_data)

# Save XML
with open('alert.xml', 'w') as f:
    f.write(xml_content)
```

## Core Validation Functions

### validate_cap_dict()

Validates CAP data from a Python dictionary.

```python
from cap_validator import validate_cap_dict, CAPValidationError

cap_data = {
    "identifier": "KSTO1055887203",
    "sender": "KSTO@NWS.NOAA.GOV",
    "sent": "2003-06-17T14:57:00-07:00",
    "status": "Actual",
    "msgType": "Alert",
    "scope": "Public",
    "info": [{
        "category": ["Met"],
        "event": "SEVERE THUNDERSTORM",
        "urgency": "Expected",
        "severity": "Severe",
        "certainty": "Likely",
        "description": "Severe thunderstorm approaching..."
    }]
}

try:
    alert = validate_cap_dict(cap_data, strict=True)
    print(f"✅ Validation passed! Alert ID: {alert.identifier}")
except CAPValidationError as e:
    print(f"❌ Validation failed: {e}")
```

**Parameters:**
- `cap_data` (dict): Dictionary containing CAP alert data
- `strict` (bool, optional): Enable strict validation (default: True)

**Returns:** `Alert` object

### validate_cap_xml()

Validates CAP data from XML string.

```python
from cap_validator import validate_cap_xml

xml_string = """<?xml version="1.0" encoding="UTF-8"?>
<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
    <identifier>43b080713727</identifier>
    <sender>hsas@dhs.gov</sender>
    <!-- ... rest of XML ... -->
</alert>"""

try:
    alert = validate_cap_xml(xml_string, strict=True, validate_xsd=True)
    print(f"✅ XML validation passed!")
except Exception as e:
    print(f"❌ XML validation failed: {e}")
```

**Parameters:**
- `xml_string` (str): CAP XML string
- `strict` (bool, optional): Enable strict validation (default: True)
- `validate_xsd` (bool, optional): Validate against XSD schema (default: True)

### validate_cap_file()

Validates CAP data from a file.

```python
from cap_validator import validate_cap_file

# Validate JSON file
alert = validate_cap_file("alert.json", file_type="json")

# Validate XML file
alert = validate_cap_file("alert.xml", file_type="xml")

# Auto-detect format
alert = validate_cap_file("alert.json", file_type="auto")
```

### validate_cap_compliance()

Comprehensive compliance validation with detailed report.

```python
from cap_validator import validate_cap_compliance

# Validate dictionary
report = validate_cap_compliance(cap_data, input_type="dict")

# Validate XML
report = validate_cap_compliance(xml_string, input_type="xml")

print(f"Compliant: {report['compliant']}")
print(f"Errors: {report['errors']}")
print(f"Warnings: {report['warnings']}")
print(f"XSD Validation: {report['checks']['xsd_validation']}")
```

**Report Structure:**
```python
{
    'compliant': bool,
    'oasis_version': '1.2',
    'validation_timestamp': str,
    'errors': [str],
    'warnings': [str],
    'checks': {
        'xsd_validation': bool,
        'datetime_format': bool,
        'element_sequence': bool,
        'content_validation': bool,
        'geographic_validation': bool,
        'namespace_validation': bool
    },
    'alert_info': {
        'identifier': str,
        'sender': str,
        'sent': str,
        'status': str,
        'msgType': str,
        'scope': str
    }
}
```

## XML Generation Functions

### generate_cap_xml_from_dict()

Generates OASIS CAP 1.2 compliant XML from dictionary data.

```python
from cap_validator import generate_cap_xml_from_dict

cap_data = {
    "identifier": "43b080713727",
    "sender": "hsas@dhs.gov",
    "sent": "2003-04-02T14:39:01-05:00",
    "status": "Actual",
    "msgType": "Alert",
    "scope": "Public",
    "info": [{
        "category": ["Security"],
        "event": "Homeland Security Advisory System Update",
        "urgency": "Immediate",
        "severity": "Severe",
        "certainty": "Likely",
        "description": "The Department of Homeland Security has elevated..."
    }]
}

xml_content = generate_cap_xml_from_dict(cap_data)
print(xml_content)
```

#### Special Character Handling

**The XML generator automatically escapes all XML special characters.** You don't need to manually escape characters in your input data.

```python
from cap_validator import generate_cap_xml_from_dict

# Use special characters directly in your data
cap_data = {
    "identifier": "ALERT-001",
    "sender": "alerts@emergency.gov",
    "sent": "2025-01-15T10:00:00-00:00",
    "status": "Actual",
    "msgType": "Alert",
    "scope": "Public",
    "info": [{
        "category": ["Met"],
        "event": "Flood Warning",
        "urgency": "Immediate",
        "severity": "Severe",
        "certainty": "Observed",
        # Special characters are automatically escaped:
        "senderName": "Flood Forecasting & Warning Center",  # & → &amp;
        "headline": "Alert with <special> characters & \"quotes\"",  # < → &lt;, > → &gt;
        "description": "Water levels: 5 < 10 meters. Contact us at Emergency & Response Center",
        "instruction": "Don't ignore warnings! Move to higher ground & evacuate immediately"
    }]
}

# Generate XML - all special characters are automatically escaped
xml_output = generate_cap_xml_from_dict(cap_data)

# The XML will contain properly escaped characters:
# <senderName>Flood Forecasting &amp; Warning Center</senderName>
# <headline>Alert with &lt;special&gt; characters &amp; "quotes"</headline>
```

**Supported Special Characters:**
- `&` → `&amp;` (ampersand)
- `<` → `&lt;` (less than)
- `>` → `&gt;` (greater than)
- `"` → `&quot;` (double quote, in attributes)
- `'` → `&apos;` (single quote, in attributes)

**Important Notes:**
1. ✅ **DO** use plain text characters in your JSON/dict data
2. ❌ **DON'T** manually escape characters (e.g., using `&amp;`) - this will cause double-escaping
3. ✅ The validator accepts both JSON and XML input formats
4. ✅ UTF-8 encoding is fully supported for international characters

### generate_cap_xml()

Advanced XML generation with validation options.

```python
from cap_validator import generate_cap_xml

xml_content = generate_cap_xml(
    cap_data, 
    format_type="dict",  # or "auto"
    validate_output=True  # Validate generated XML
)
```

## Data Models

### Alert Model

The main CAP alert container.

```python
from cap_validator import Alert
from datetime import datetime, timezone

alert = Alert(
    identifier="WEATHER-ALERT-001",
    sender="weather@emergency.gov",
    sent=datetime.now(timezone.utc),
    status="Actual",
    msgType="Alert",
    scope="Public",
    info=[{
        "category": ["Met"],
        "event": "Severe Weather Warning",
        "urgency": "Immediate",
        "severity": "Severe",
        "certainty": "Observed",
        "description": "Severe thunderstorm with damaging winds..."
    }]
)

# Access properties
print(f"Alert ID: {alert.identifier}")
print(f"Sender: {alert.sender}")
print(f"Number of info blocks: {len(alert.info)}")
```

### Info Model

Information block within an alert.

```python
from cap_validator import Info

info = Info(
    category=["Met"],
    event="Tornado Warning",
    urgency="Immediate",
    severity="Extreme", 
    certainty="Observed",
    description="A tornado has been spotted...",
    instruction="Take shelter immediately in a sturdy building",
    area=[{
        "areaDesc": "Knox County, TN",
        "polygon": "35.9,-84.2 35.9,-84.0 36.0,-84.0 36.0,-84.2 35.9,-84.2"
    }]
)
```

### Area Model

Geographic area description.

```python
from cap_validator import Area

area = Area(
    areaDesc="Knox County, Tennessee",
    polygon="35.9,-84.2 35.9,-84.0 36.0,-84.0 36.0,-84.2 35.9,-84.2",
    geocode=[{
        "valueName": "FIPS6",
        "value": "047093"
    }]
)
```

### Resource Model

Attached resources like images, audio, etc.

```python
from cap_validator import Resource

resource = Resource(
    resourceDesc="Radar image showing storm location",
    mimeType="image/png",
    uri="https://weather.gov/radar/storm123.png",
    size=245760
)
```

## Utility Functions

### Date/Time Utilities

```python
from cap_validator import (
    parse_datetime,
    format_datetime,
    format_cap_timestamp,
    validate_cap_datetime_