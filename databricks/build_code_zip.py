"""Pack the detection code into one zip that Databricks notebooks can import.

    python -m databricks.build_code_zip      # -> data/upload/edgesentinel_code.zip

Our GitHub repo is private, so instead of a Git folder (which needs a GitHub
token in Databricks) we upload this one file to the `raw` volume. Python can
import straight from a zip on sys.path, so notebooks 02-04 start with:

    sys.path.insert(0, "/Volumes/workspace/edgesentinel/raw/edgesentinel_code.zip")

Rebuild and re-upload it whenever detection/ changes.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "upload" / "edgesentinel_code.zip"


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    files = sorted((ROOT / "detection").glob("*.py"))
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            z.write(f, f"detection/{f.name}")
    print(f"wrote {OUT.relative_to(ROOT)} with {len(files)} files: {', '.join(f.name for f in files)}")
    print("upload it to Catalog > workspace > edgesentinel > raw (replace the old one if asked)")


if __name__ == "__main__":
    main()
