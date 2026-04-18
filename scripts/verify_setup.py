#!/usr/bin/env python3
"""
Hayyan SOC Setup Verification Script
Checks all prerequisites before running the system.
"""
import sys
import os
from pathlib import Path

def check_python_version():
    """Verify Python 3.10+."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        print(f"[ERROR] Python 3.10+ required, got {version.major}.{version.minor}")
        return False
    print(f"[OK] Python {version.major}.{version.minor}.{version.micro}")
    return True

def check_venv():
    """Check if venv is activated."""
    if hasattr(sys, 'real_prefix') or (
        hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    ):
        print("[OK] Virtual environment is active")
        return True
    print("[WARNING] Virtual environment not detected. Run 'setup.sh' or 'setup.ps1' first")
    return False

def check_env_file():
    """Check .env exists and is configured."""
    env_path = Path(".env")
    if not env_path.exists():
        print("[ERROR] .env file not found. Run setup.sh first")
        return False
    
    content = env_path.read_text()
    if "your_gemini" in content or "your_" in content:
        print("[ERROR] .env not configured. Add your GOOGLE_API_KEY and Splunk credentials")
        return False
    
    if "GOOGLE_API_KEY" not in content:
        print("[ERROR] GOOGLE_API_KEY not in .env")
        return False
    
    print("[OK] .env is configured")
    return True

def check_dependencies():
    """Check key dependencies are installed."""
    required = [
        "fastapi", "langchain", "langchain_google_genai",
        "langgraph", "chromadb", "splunk_sdk"
    ]
    missing = []
    
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    
    if missing:
        print(f"[ERROR] Missing packages: {', '.join(missing)}")
        print("Run: pip install -r requirements.txt")
        return False
    
    print(f"[OK] All {len(required)} required packages installed")
    return True

def check_directories():
    """Check required directories exist."""
    required_dirs = [
        Path("data"),
        Path("data/chroma_db"),
        Path("soc_agents"),
        Path("soc_agents/ui"),
    ]
    
    for d in required_dirs:
        if not d.exists():
            print(f"[ERROR] Missing directory: {d}")
            return False
    
    print("[OK] All required directories exist")
    return True

def check_splunk_connectivity():
    """Test Splunk connectivity."""
    try:
        from soc_agents.core.splunk_client import SplunkClient
        client = SplunkClient()
        if client.ping():
            print("[OK] Splunk is reachable")
            return True
        else:
            print("[ERROR] Splunk is not responding (check credentials)")
            return False
    except Exception as e:
        print(f"[ERROR] Splunk connection failed: {e}")
        return False

def check_gemini_api():
    """Test Gemini API connectivity."""
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        from soc_agents.core.config import get_settings
        
        cfg = get_settings()
        if not cfg.google_api_key:
            print("[ERROR] GOOGLE_API_KEY not set")
            return False
        
        llm = ChatGoogleGenerativeAI(
            model="gemini-2.5-flash",
            google_api_key=cfg.google_api_key,
            temperature=0,
        )
        # Try a simple invoke
        response = llm.invoke("Hello")
        if response:
            print("[OK] Gemini API is accessible")
            return True
    except Exception as e:
        print(f"[ERROR] Gemini API test failed: {e}")
        return False

def main():
    print("=" * 50)
    print("  Hayyan SOC — Setup Verification")
    print("=" * 50)
    print()

    checks = [
        ("Python version", check_python_version),
        ("Virtual environment", check_venv),
        ("Configuration (.env)", check_env_file),
        ("Dependencies", check_dependencies),
        ("Directories", check_directories),
        ("Splunk connectivity", check_splunk_connectivity),
        ("Gemini API", check_gemini_api),
    ]

    results = []
    for name, check_fn in checks:
        print(f"Checking {name}...")
        try:
            result = check_fn()
            results.append((name, result))
        except Exception as e:
            print(f"[ERROR] {e}")
            results.append((name, False))
        print()

    print("=" * 50)
    print("  Summary")
    print("=" * 50)
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "[OK]" if result else "[FAIL]"
        print(f"{status} {name}")
    
    print()
    print(f"Result: {passed}/{total} checks passed")
    
    if passed == total:
        print()
        print("All checks passed! Ready to run:")
        print("  Windows: .\run.ps1")
        print("  Mac/Linux: ./scripts/run.sh")
        return 0
    else:
        print()
        print("Some checks failed. Fix errors above before running the system.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
