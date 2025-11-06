# Installation Guide

## Install from GitHub

You can install `pycap-validator` directly from GitHub without needing PyPI.

### Latest Version (Recommended)

Install the latest version from the main branch:

```bash
pip install git+https://github.com/anin98/cap-validator.git
```

### Specific Version

Install a specific tagged version (e.g., v1.1.0):

```bash
pip install git+https://github.com/anin98/cap-validator.git@v1.1.0
```

### Development Version

Install the latest development version:

```bash
git clone https://github.com/anin98/cap-validator.git
cd cap-validator
pip install -e .
```

## Verify Installation

After installation, verify it's working:

```python
from cap_validator import validate_cap_dict, generate_cap_xml_from_dict

print("✓ CAP Validator installed successfully!")
```

Or from command line:

```bash
python -c "from cap_validator import __version__; print(f'CAP Validator v{__version__} installed')"
```

## Requirements

- Python 3.8 or higher
- Dependencies (automatically installed):
  - lxml>=4.6.0
  - pydantic>=2.0.0
  - python-dateutil>=2.8.0
  - click>=8.0.0
  - xmlschema>=1.10.0

## Quick Start

```python
import json
from cap_validator import generate_cap_xml_from_dict

# Your CAP data
cap_data = {
    "identifier": "alert-001",
    "sender": "alerts@example.com",
    "sent": "2025-01-15T10:00:00-00:00",
    "status": "Actual",
    "msgType": "Alert",
    "scope": "Public",
    "info": [{
        "category": ["Met"],
        "event": "Severe Weather Warning",
        "urgency": "Immediate",
        "severity": "Severe",
        "certainty": "Observed",
        "senderName": "Weather & Climate Center",  # Special characters automatically handled!
        "description": "Temperature > 40°C expected"
    }]
}

# Generate XML (special characters automatically escaped)
xml = generate_cap_xml_from_dict(cap_data)
print(xml)
```

## What's New in v1.1.0

✅ **Automatic XML Special Character Handling**
- All special characters (`&`, `<`, `>`, `"`, `'`) are automatically escaped
- No manual escaping required
- Prevents double-escaping issues

✅ **Enhanced Documentation**
- Comprehensive special character handling guide
- Common use cases and examples

✅ **Improved Error Messages**
- Better validation for encoding issues
- Clear guidance on character usage

## Support

- GitHub Issues: https://github.com/anin98/cap-validator/issues
- Documentation: See [README.md](README.md)
