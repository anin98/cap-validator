#!/usr/bin/env python3
"""
Simple CAP XML generator that should work regardless of import issues
"""
import json
import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

def main():
    print("🚀 Simple CAP XML Generator")
    print("=" * 40)
    
    # Step 1: Try to import
    try:
        from cap_validator import (
            validate_cap_dict, 
            generate_cap_xml_from_dict,
            __version__
        )
        print(f"✅ Imports successful! Version: {__version__}")
    except Exception as e:
        print(f"❌ Import failed: {e}")
        print("\nTrying alternative import method...")
        try:
            # Try direct file imports
            sys.path.insert(0, str(src_path / "cap_validator"))
            from xml_generator import generate_cap_xml_from_dict
            from models import Alert
            from exceptions import CAPValidationError
            print("✅ Alternative imports successful!")
            
            # Simple validation function
            def validate_cap_dict(data, strict=True):
                return Alert(**data)
                
        except Exception as e2:
            print(f"❌ Alternative import also failed: {e2}")
            return
    
    # Step 2: Load test.json
    test_file = Path("test.json")
    if not test_file.exists():
        print(f"❌ {test_file} not found!")
        return
    
    print(f"📂 Loading {test_file}...")
    with open(test_file, 'r') as f:
        data = json.load(f)
    
    print(f"✅ JSON loaded: {data.get('identifier', 'Unknown')}")
    
    # Step 3: Validate
    print("🔍 Validating...")
    try:
        alert = validate_cap_dict(data)
        print("✅ Validation passed!")
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        return
    
    # Step 4: Generate XML
    print("🔧 Generating XML...")
    try:
        xml_content = generate_cap_xml_from_dict(data)
        print(f"✅ XML generated ({len(xml_content)} characters)")
    except Exception as e:
        print(f"❌ XML generation failed: {e}")
        return
    
    # Step 5: Save XML
    output_file = Path("simple_output.xml")
    with open(output_file, 'w') as f:
        f.write(xml_content)
    
    print(f"💾 XML saved to: {output_file}")
    
    # Step 6: Show preview
    print("\n📄 XML Preview:")
    print("-" * 40)
    print(xml_content[:500] + "..." if len(xml_content) > 500 else xml_content)
    print("-" * 40)
    
    print(f"\n🎉 Success! Check {output_file}")

if __name__ == "__main__":
    main()