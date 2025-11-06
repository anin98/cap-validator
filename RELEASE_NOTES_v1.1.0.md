# Release Notes - Version 1.1.0

## 🎉 What's New

### Automatic XML Special Character Handling

The CAP Validator now **automatically handles all XML special characters** when generating CAP XML from JSON/dictionary data. You no longer need to worry about manually escaping characters!

#### Supported Characters

| Character | Escaped As | Example Use Case |
|-----------|-----------|------------------|
| `&` | `&amp;` | Organization names: "Emergency & Response" |
| `<` | `&lt;` | Comparisons: "Temperature < 30°C" |
| `>` | `&gt;` | Comparisons: "Wind speed > 50 km/h" |
| `"` | `&quot;` | Quotes in text |
| `'` | `&apos;` | Apostrophes: "Don't ignore" |

#### Example

**Before (required manual escaping):**
```json
{
  "senderName": "Emergency &amp; Response Center"  // ❌ Manual escaping
}
```

**Now (automatic escaping):**
```json
{
  "senderName": "Emergency & Response Center"  // ✅ Just use plain text!
}
```

**Generated XML:**
```xml
<senderName>Emergency &amp; Response Center</senderName>
```

### Enhanced Documentation

- 📚 New "Special Character Handling" section in README
- 📖 Comprehensive examples for common use cases
- ⚠️ Clear warnings about double-escaping
- 🌍 International character support documented

### Improved Error Handling

- Better error messages for encoding issues
- Validation to prevent double-escaping
- Clear guidance on proper character usage

### Updated Validator

- Added optional `validate_xsd` parameter to `validate_cap_file()`
- Improved UTF-8 encoding validation
- Better handling of pre-escaped content

## 📦 Installation

### From GitHub (Recommended)

```bash
# Latest version
pip install git+https://github.com/anin98/cap-validator.git

# Specific version v1.1.0
pip install git+https://github.com/anin98/cap-validator.git@v1.1.0
```

## 🚀 Quick Start with Special Characters

```python
from cap_validator import generate_cap_xml_from_dict

cap_data = {
    "identifier": "alert-001",
    "sender": "alerts@example.com",
    "sent": "2025-01-15T10:00:00-00:00",
    "status": "Actual",
    "msgType": "Alert",
    "scope": "Public",
    "info": [{
        "category": ["Met"],
        "event": "Weather Alert",
        "urgency": "Immediate",
        "severity": "Severe",
        "certainty": "Observed",
        # Use special characters naturally - they're automatically escaped!
        "senderName": "Weather & Climate Center",
        "headline": "Temperatures > 40°C expected",
        "description": "Risk level: Current > Normal. Contact Emergency & Response.",
        "instruction": "Don't stay outdoors. Seek shelter where temp < 25°C"
    }]
}

# Generate XML - all special characters are automatically escaped
xml = generate_cap_xml_from_dict(cap_data)
print(xml)
```

## 🔧 Technical Changes

### Modified Files

- `src/cap_validator/xml_generator.py`
  - Updated `_sanitize_text_content()` function
  - Added validation for pre-escaped entities
  - Improved documentation

- `src/cap_validator/validator.py`
  - Added `validate_xsd` parameter to `validate_cap_file()`
  - Enhanced parameter passing

- `README.md`
  - Added "Special Character Handling" section
  - Updated installation instructions
  - Added comprehensive examples

- `pyproject.toml`
  - Bumped version to 1.1.0
  - Fixed metadata format

### New Files

- `INSTALL.md` - Detailed installation instructions
- `.gitignore` - Build artifacts exclusion
- `example_special_characters.py` - Demonstration script

## 📝 Upgrade Notes

### Breaking Changes

None! This is a backward-compatible release.

### Recommendations

1. ✅ **DO** use plain text characters in your JSON/dict data
2. ❌ **DON'T** manually escape characters (e.g., `&amp;`) - this will cause errors
3. ✅ Review existing code that manually escapes XML entities

### Migration

If you were manually escaping characters:

**Old Code (will now fail):**
```python
cap_data = {
    "senderName": "Weather &amp; Climate"  # Manual escaping
}
```

**New Code (correct):**
```python
cap_data = {
    "senderName": "Weather & Climate"  # Plain text - automatic escaping
}
```

## 🌍 Global Ready

This release makes the CAP Validator truly global-ready:

- ✅ Works with all international characters
- ✅ Supports UTF-8 encoding
- ✅ Handles organization names with special characters
- ✅ Perfect for multilingual alerts
- ✅ No locale-specific issues

## 🐛 Bug Fixes

- Fixed potential double-escaping issues
- Improved whitespace normalization
- Enhanced UTF-8 validation

## 📊 Testing

All special character handling has been thoroughly tested:

- ✅ Ampersands in organization names
- ✅ Less than/greater than in comparisons
- ✅ Quotes and apostrophes in text
- ✅ Mixed special characters
- ✅ International characters (°, μ, etc.)

## 🙏 Acknowledgments

This release addresses feedback from global users who need to handle special characters in organization names, international alerts, and scientific data.

## 📞 Support

- **GitHub Issues**: https://github.com/anin98/cap-validator/issues
- **Documentation**: [README.md](README.md)
- **Installation Guide**: [INSTALL.md](INSTALL.md)

---

**Release Date**: 2025-11-06
**Version**: 1.1.0
**Status**: Stable
