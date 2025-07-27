#!/usr/bin/env python3
"""
CAP Validator Example - XML File Validation (Fixed Version)

This example demonstrates how to validate CAP XML files using the cap_validator package.
It loads the test_alert.xml file and validates it against CAP 1.2 and WMO AlertWise standards.

This version imports directly from the source directory to avoid installation issues.
"""

import os
import sys
from pathlib import Path

# Add the src directory to Python path for direct import
src_path = Path("src")
if src_path.exists():
    sys.path.insert(0, str(src_path))
    print(f"🔧 Using direct import from {src_path.absolute()}")
else:
    print("❌ Error: src directory not found!")
    print("Please run this script from the cap_validator project root directory.")
    sys.exit(1)

# Import the CAP validator package
try:
    from cap_validator import (
        validate_cap_file,
        validate_cap_xml,
        CAPValidationError
    )
    print("✅ CAP validator imported successfully")
except ImportError as e:
    print(f"❌ Error importing cap_validator: {e}")
    print("Please check that all required files are in the src/cap_validator/ directory.")
    sys.exit(1)


def validate_xml_file(file_path, strict_mode=False):
    """
    Validate a single CAP XML file.
    
    Args:
        file_path (str): Path to the XML file
        strict_mode (bool): Whether to use strict WMO validation
    
    Returns:
        dict: Validation results
    """
    print(f"\n{'='*60}")
    print(f"📄 Validating: {file_path}")
    print(f"🔍 Strict Mode: {'Enabled' if strict_mode else 'Disabled'}")
    print(f"{'='*60}")
    
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return {"valid": False, "error": "File not found"}
    
    try:
        # Method 1: Validate using file path
        alert = validate_cap_file(file_path, strict=strict_mode)
        
        print(f"✅ VALIDATION SUCCESSFUL")
        print(f"   📋 Identifier: {alert.identifier}")
        print(f"   👤 Sender: {alert.sender}")
        print(f"   📅 Sent: {alert.sent}")
        print(f"   🏷️  Status: {alert.status}")
        print(f"   📧 Message Type: {alert.msgType}")
        print(f"   🌐 Scope: {alert.scope}")
        
        if alert.source:
            print(f"   🏢 Source: {alert.source}")
        
        if alert.references:
            print(f"   🔗 References: {alert.references}")
            
        if alert.code:
            print(f"   🏷️  Codes: {', '.join(alert.code)}")
        
        # Display info blocks
        if alert.info:
            print(f"\n   ℹ️  INFO BLOCKS: {len(alert.info)}")
            
            for i, info in enumerate(alert.info, 1):
                print(f"\n   📢 Info Block {i}:")
                print(f"      🗣️  Language: {info.language}")
                print(f"      🏷️  Categories: {', '.join(info.category)}")
                print(f"      🚨 Event: {info.event}")
                print(f"      ⚡ Urgency: {info.urgency}")
                print(f"      🔥 Severity: {info.severity}")
                print(f"      ✅ Certainty: {info.certainty}")
                
                if info.effective:
                    print(f"      🟢 Effective: {info.effective}")
                if info.onset:
                    print(f"      🔶 Onset: {info.onset}")
                print(f"      ⏰ Expires: {info.expires}")
                
                print(f"      👨‍💼 Sender Name: {info.senderName}")
                
                if info.headline:
                    print(f"      📰 Headline: {info.headline[:80]}{'...' if len(info.headline) > 80 else ''}")
                
                if info.description:
                    print(f"      📝 Description: {info.description[:100]}{'...' if len(info.description) > 100 else ''}")
                
                if info.instruction:
                    print(f"      📋 Instructions: {info.instruction[:100]}{'...' if len(info.instruction) > 100 else ''}")
                
                if info.web:
                    print(f"      🌐 Web: {info.web}")
                    
                if info.contact:
                    print(f"      📞 Contact: {info.contact}")
                
                # Display response types
                if info.responseType:
                    print(f"      🎯 Response Types: {', '.join(info.responseType)}")
                
                # Display event codes
                if info.eventCode:
                    print(f"      🏷️  Event Codes: {len(info.eventCode)}")
                    for code in info.eventCode[:3]:  # Show first 3
                        print(f"         {code.valueName}: {code.value}")
                
                # Display area information
                if info.area:
                    print(f"      🗺️  Geographic Areas: {len(info.area)}")
                    for j, area in enumerate(info.area, 1):
                        print(f"         Area {j}: {area.areaDesc}")
                        if area.polygon:
                            print(f"           🔺 Polygons: {len(area.polygon)}")
                            for k, polygon in enumerate(area.polygon[:2]):  # Show first 2
                                coords = polygon.split()[:3]  # Show first 3 coordinate pairs
                                print(f"              Polygon {k+1}: {' '.join(coords)}...")
                        if area.circle:
                            print(f"           ⭕ Circles: {len(area.circle)}")
                            for circle in area.circle:
                                print(f"              {circle}")
                        if area.geocode:
                            print(f"           🏷️  Geocodes: {len(area.geocode)}")
                            for geocode in area.geocode[:3]:  # Show first 3
                                print(f"              {geocode.valueName}: {geocode.value}")
                        if area.altitude is not None:
                            print(f"           📏 Altitude: {area.altitude}")
                        if area.ceiling is not None:
                            print(f"           📐 Ceiling: {area.ceiling}")
                
                # Display parameters
                if info.parameter:
                    print(f"      ⚙️  Parameters: {len(info.parameter)}")
                    for param in info.parameter[:5]:  # Show first 5
                        print(f"         {param.valueName}: {param.value}")
                
                # Display resources
                if info.resource:
                    print(f"      📎 Resources: {len(info.resource)}")
                    for resource in info.resource:
                        print(f"         📄 {resource.resourceDesc}")
                        if resource.mimeType:
                            print(f"           🎭 Type: {resource.mimeType}")
                        if resource.size:
                            print(f"           📏 Size: {resource.size} bytes")
                        if resource.uri:
                            print(f"           🔗 URI: {resource.uri}")
        
        # Create a simple validation summary
        print(f"\n   📊 VALIDATION SUMMARY:")
        if alert.info:
            categories = set()
            urgency_levels = set()
            severity_levels = set()
            certainty_levels = set()
            total_areas = 0
            
            for info in alert.info:
                categories.update(info.category)
                urgency_levels.add(info.urgency)
                severity_levels.add(info.severity)
                certainty_levels.add(info.certainty)
                if info.area:
                    total_areas += len(info.area)
            
            print(f"      Total Areas: {total_areas}")
            print(f"      Categories: {list(categories)}")
            print(f"      Urgency Levels: {list(urgency_levels)}")
            print(f"      Severity Levels: {list(severity_levels)}")
            print(f"      Certainty Levels: {list(certainty_levels)}")
        
        return {
            "valid": True,
            "alert": alert
        }
        
    except CAPValidationError as e:
        print(f"❌ VALIDATION FAILED")
        print(f"   💥 Error: {e.message}")
        if e.field:
            print(f"   🎯 Field: {e.field}")
        if e.code:
            print(f"   🏷️  Code: {e.code}")
        
        return {
            "valid": False,
            "error": str(e.message),
            "field": e.field,
            "code": e.code
        }
    
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR")
        print(f"   💥 Error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return {
            "valid": False,
            "error": f"Unexpected error: {str(e)}"
        }


def main():
    """Main function to validate the test_alert.xml file."""
    print("🚀 CAP Validator - test_alert.xml Validation Example")
    print("=" * 80)
    
    # The specific XML file to validate
    xml_file = "test_alert.xml"
    
    # Check if the file exists
    if not os.path.exists(xml_file):
        print(f"❌ File not found: {xml_file}")
        print("\nPlease ensure test_alert.xml exists in the current directory.")
        
        # Show current directory contents
        current_dir = Path(".")
        xml_files = list(current_dir.glob("*.xml"))
        if xml_files:
            print(f"\n📁 XML files found in current directory:")
            for file in xml_files:
                print(f"   - {file.name}")
        else:
            print(f"\n📁 No XML files found in current directory.")
        
        return
    
    print(f"✅ Found file: {xml_file}")
    
    # Show file size
    file_size = os.path.getsize(xml_file)
    print(f"📏 File size: {file_size} bytes")
    
    # Validation results storage
    results = []
    
    # Phase 1: Relaxed validation
    print(f"\n🔍 PHASE 1: Relaxed CAP 1.2 Validation")
    print("=" * 50)
    
    result_relaxed = validate_xml_file(xml_file, strict_mode=False)
    results.append({
        'mode': 'Relaxed',
        'result': result_relaxed
    })
    
    # Phase 2: Strict WMO validation (if relaxed validation passed)
    if result_relaxed['valid']:
        print(f"\n🔍 PHASE 2: Strict WMO AlertWise Validation")
        print("=" * 50)
        
        result_strict = validate_xml_file(xml_file, strict_mode=True)
        results.append({
            'mode': 'Strict WMO',
            'result': result_strict
        })
    else:
        print(f"\n⚠️  Skipping strict validation due to basic validation failure.")
    
    # Print overall summary
    print(f"\n📊 VALIDATION SUMMARY FOR {xml_file}")
    print("=" * 60)
    
    for i, result in enumerate(results, 1):
        mode = result['mode']
        is_valid = result['result']['valid']
        status = "✅ PASSED" if is_valid else "❌ FAILED"
        
        print(f"{i}. {mode} Validation: {status}")
        
        if not is_valid and 'error' in result['result']:
            print(f"   Error: {result['result']['error']}")
    
    # Overall assessment
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r['result']['valid'])
    
    print(f"\nOverall Result: {passed_tests}/{total_tests} validations passed")
    
    if passed_tests == total_tests:
        print("🎉 Excellent! Your CAP alert passes all validation tests.")
    elif passed_tests > 0:
        print("⚠️  Your CAP alert has some issues but basic structure is valid.")
    else:
        print("❌ Your CAP alert has significant validation issues that need fixing.")
    
    print(f"\n✨ Validation completed for {xml_file}!")
    print("=" * 80)


if __name__ == "__main__":
    main()