"""Check presence of local OpenAI settings without printing secrets or calling API.

This does not authenticate the key, verify model access, or enforce reporter
limits. The API integration will consume these settings in a later step.
"""

import json
import os
from pathlib import Path

from dotenv import dotenv_values


def setup_status(settings) -> dict:
    """Return only booleans and fixed labels; never return configuration values."""
    key = (settings.get("OPENAI_API_KEY") or "").strip()
    model = (settings.get("OPENAI_MODEL") or "").strip()
    offline = settings.get("DEMO_OFFLINE", "1")
    cap = settings.get("MAX_AI_CALLS", "60") or ""
    cap_valid = cap.isascii() and cap.isdigit() and 1 <= int(cap) <= 60
    return {
        "api_key_present": bool(key) and key.casefold() not in {"your-key-here", "your_api_key", "placeholder"},
        "model_configured": bool(model),
        "offline_mode": offline == "1",
        "offline_setting_valid": offline in {"0", "1"},
        "call_limit_setting_valid": cap_valid,
        "api_authentication_tested": False,
        "api_calls": 0,
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    path = root / ".env"
    try:
        local = dotenv_values(path, encoding="utf-8-sig") if path.is_file() else {}
        # Match the later SDK convention: exported environment settings take
        # precedence over the local .env. No values are printed.
        status = setup_status({**local, **os.environ})
    except Exception as error:
        raise SystemExit(f"Could not check settings ({type(error).__name__}); values not displayed") from None
    print(json.dumps({"env_file_present": path.is_file(), **status}, indent=2))


if __name__ == "__main__":
    main()
