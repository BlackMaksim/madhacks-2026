"""Read-only Maksym environment inventory. Uses only the Python standard library."""

import importlib.metadata
import importlib.util
from pathlib import Path
import platform
import shutil
import sys


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    print("EdgeSentinel Maksym environment check (read-only)")
    print(f"Repository: {root}")
    print(f"Working directory: {Path.cwd()}")
    print(f"Python: {platform.python_version()}")
    print(f"Interpreter: {sys.executable}")
    print(f"Virtual environment: {'yes' if sys.prefix != sys.base_prefix else 'no'}")
    print("Blueprint Python target: 3.12 (confirm with the team)")
    for command in ("git", "py", "node"):
        print(f"{command}: {shutil.which(command) or 'NOT FOUND'}")
    print("\nMaksym libraries in this interpreter:")
    for module, distribution in (
        ("pydantic", "pydantic"),
        ("openai", "openai"),
        ("dotenv", "python-dotenv"),
        ("pytest", "pytest"),
    ):
        if importlib.util.find_spec(module) is None:
            version = "MISSING"
        else:
            try:
                version = importlib.metadata.version(distribution)
            except importlib.metadata.PackageNotFoundError:
                version = "module found; distribution version unavailable"
        print(f"  {distribution}: {version}")
    print("\nIntegration files:")
    for relative in ("requirements.txt", "contracts/models.py", "app/db.py"):
        print(f"  {relative}: {'present' if (root / relative).is_file() else 'not yet present'}")
    print("\nNo packages installed, files written, secrets read, or API calls made.")


if __name__ == "__main__":
    main()
