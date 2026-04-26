#!/usr/bin/env python3
"""
Hayyan SOC Setup Verification Script
Checks all prerequisites before running the system.
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))


def check_python_version():
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        print(f"[ERROR] Python 3.10+ required, got {version.major}.{version.minor}")
        return False
    print(f"[OK] Python {version.major}.{version.minor}.{version.micro}")
    return True


def check_venv():
    if hasattr(sys, 'real_prefix') or (
        hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    ):
        print("[OK] Virtual environment is active")
        return True
    print("[WARNING] Virtual environment not detected. Run setup.ps1 first.")
    return True  # non-fatal


def check_env_file():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        print(f"[ERROR] .env not found at {env_path}")
        return False

    content = env_path.read_text()
    if "GROQ_API_KEY" not in content:
        print("[ERROR] GROQ_API_KEY not in .env — get a free key at console.groq.com")
        return False

    if "your_groq" in content or "YOUR_KEY" in content:
        print("[ERROR] GROQ_API_KEY looks like a placeholder — set a real key")
        return False

    print("[OK] .env is configured")
    return True


def check_dependencies():
    required = [
        "fastapi", "langchain", "langchain_core",
        "langgraph", "langchain_groq", "requests",
        "pydantic_settings",
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
    required_dirs = [Path("data"), Path("soc_agents"), Path("soc_agents/ui")]
    for d in required_dirs:
        if not d.exists():
            print(f"[ERROR] Missing directory: {d}")
            return False
    print("[OK] All required directories exist")
    return True


def check_splunk_connectivity():
    try:
        from soc_agents.core.splunk_client import SplunkClient
        client = SplunkClient()
        if client.ping():
            scheme = client._scheme or "?"
            print(f"[OK] Splunk reachable via {scheme}://{client._host}:{client._port}")
            return True
        else:
            print("[ERROR] Splunk not responding — check port 8089 is exposed on Docker container")
            return False
    except Exception as e:
        print(f"[ERROR] Splunk connection failed: {e}")
        return False


def check_groq_api():
    try:
        from langchain_groq import ChatGroq
        from soc_agents.core.config import get_settings

        cfg = get_settings()
        if not cfg.groq_api_key:
            print("[ERROR] GROQ_API_KEY not set in .env")
            return False

        llm = ChatGroq(
            model=cfg.model_name,
            groq_api_key=cfg.groq_api_key,
            temperature=0,
            max_tokens=10,
        )
        response = llm.invoke("Say OK")
        if response:
            print(f"[OK] Groq API accessible — model: {cfg.model_name}")
            return True
    except Exception as e:
        print(f"[ERROR] Groq API test failed: {e}")
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
        ("Groq API", check_groq_api),
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
        print("All checks passed! Run the platform:")
        print("  Windows: .\\run.ps1")
        print("  Or:      python main.py")
        return 0
    else:
        print()
        print("Fix the errors above before running.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
