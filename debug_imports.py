#!/usr/bin/env python3
"""
Debug script to check package installation and imports.
"""

import sys
import os
from pathlib import Path

print("🔍 Debug Information")
print("=" * 50)

# Check Python path
print("📍 Python executable:", sys.executable)
print("📁 Current directory:", os.getcwd())
print("🐍 Python version:", sys.version)

# Check if we're in a virtual environment
if hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix:
    print("🌐 Virtual environment: Active")
else:
    print("🌐 Virtual environment: Not detected")

print("\n📦 Python Path:")
for i, path in enumerate(sys.path):
    print(f"   {i}: {path}")

# Check current directory structure
print(f"\n📁 Current Directory Contents:")
current_dir = Path(".")
for item in sorted(current_dir.iterdir()):
    if item.is_dir():
        print(f"   📁 {item.name}/")
    else:
        print(f"   📄 {item.name}")

# Check if src directory exists
src_dir = Path("src")
if src_dir.exists():
    print(f"\n📁 src/ Directory Contents:")
    for item in sorted(src_dir.iterdir()):
        if item.is_dir():
            print(f"   📁 {item.name}/")
        else:
            print(f"   📄 {item.name}")
    
    # Check cap_validator directory
    cap_validator_dir = src_dir / "cap_validator"
    if cap_validator_dir.exists():
        print(f"\n📁 src/cap_validator/ Directory Contents:")
        for item in sorted(cap_validator_dir.iterdir()):
            if item.is_dir():
                print(f"   📁 {item.name}/")
            else:
                print(f"   📄 {item.name}")

# Try to import the package step by step
print(f"\n🧪 Import Testing:")

try:
    import cap_validator
    print("✅ cap_validator imported successfully")
    print(f"   📍 Package location: {cap_validator.__file__}")
    
    # Try importing specific functions
    try:
        from cap_validator import validate_cap_file
        print("✅ validate_cap_file imported successfully")
    except ImportError as e:
        print(f"❌ validate_cap_file import failed: {e}")
    
    try:
        from cap_validator import validate_cap_xml
        print("✅ validate_cap_xml imported successfully")
    except ImportError as e:
        print(f"❌ validate_cap_xml import failed: {e}")
        
    try:
        from cap_validator import CAPValidationError
        print("✅ CAPValidationError imported successfully")
    except ImportError as e:
        print(f"❌ CAPValidationError import failed: {e}")

except ImportError as e:
    print(f"❌ cap_validator import failed: {e}")
    
    # Check if there are any installed packages with similar names
    try:
        import pkg_resources
        installed_packages = [d.project_name for d in pkg_resources.working_set]
        cap_packages = [pkg for pkg in installed_packages if 'cap' in pkg.lower()]
        if cap_packages:
            print(f"🔍 Found CAP-related packages: {cap_packages}")
    except:
        pass

# Check if we can find the modules manually
print(f"\n🔍 Manual Module Check:")
try:
    sys.path.insert(0, str(Path("src")))
    import cap_validator
    print("✅ Manual import from src/ successful")
    print(f"   📍 Module location: {cap_validator.__file__}")
except ImportError as e:
    print(f"❌ Manual import failed: {e}")

print(f"\n✨ Debug completed!")