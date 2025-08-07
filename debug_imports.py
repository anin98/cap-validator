#!/usr/bin/env python3
"""
Debug script to identify and fix import issues
"""
import sys
from pathlib import Path

def main():
    print("🔍 CAP Validator Import Debugger")
    print("=" * 50)
    
    # Check current working directory
    cwd = Path.cwd()
    print(f"Current working directory: {cwd}")
    
    # Check for src directory
    src_path = cwd / "src"
    print(f"src directory exists: {src_path.exists()}")
    
    # Check for cap_validator directory
    cap_validator_path = src_path / "cap_validator"
    print(f"cap_validator directory exists: {cap_validator_path.exists()}")
    
    # Check for __init__.py
    init_file = cap_validator_path / "__init__.py"
    print(f"__init__.py exists: {init_file.exists()}")
    
    # List all files in cap_validator directory
    if cap_validator_path.exists():
        print(f"\nFiles in cap_validator directory:")
        for file in cap_validator_path.iterdir():
            if file.is_file():
                print(f"  - {file.name}")
    
    # Add src to Python path
    if src_path.exists():
        sys.path.insert(0, str(src_path))
        print(f"\n✅ Added {src_path} to Python path")
    
    # Try importing
    print(f"\n🧪 Testing imports...")
    
    # Test 1: Try importing the module
    try:
        import cap_validator
        print("✅ Successfully imported cap_validator module")
        print(f"   Module file: {cap_validator.__file__}")
    except ImportError as e:
        print(f"❌ Failed to import cap_validator module: {e}")
        return False
    
    # Test 2: Try importing version
    try:
        from cap_validator import __version__
        print(f"✅ Successfully imported version: {__version__}")
    except ImportError as e:
        print(f"❌ Failed to import __version__: {e}")
    
    # Test 3: Try importing main functions
    try:
        from cap_validator import validate_cap_dict, generate_cap_xml_from_dict
        print("✅ Successfully imported main functions")
    except ImportError as e:
        print(f"❌ Failed to import main functions: {e}")
        return False
    
    # Test 4: Try importing exceptions
    try:
        from cap_validator import CAPValidationError
        print("✅ Successfully imported exceptions")
    except ImportError as e:
        print(f"❌ Failed to import exceptions: {e}")
    
    print(f"\n🎉 All imports successful! You can now run the main script.")
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        print(f"\n🔧 Suggested fixes:")
        print(f"1. Make sure __init__.py exists in src/cap_validator/")
        print(f"2. Clear Python cache: rm -rf src/cap_validator/__pycache__/")
        print(f"3. Check file permissions")
        sys.exit(1)