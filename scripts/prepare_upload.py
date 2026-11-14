"""Copy fleet files to data/upload/ with the flat names 01_ingest_bronze expects.

    python -m scripts.prepare_upload            # data/fleetA + data/fleetB -> data/upload/
"""
import shutil
import sys
from pathlib import Path

import pandas as pd

EXPECTED = {"A": 172_800, "B": 86_400}


def main(src="data", dst="data/upload"):
    src, dst = Path(src), Path(dst)
    dst.mkdir(parents=True, exist_ok=True)
    for fleet, n in EXPECTED.items():
        folder = src / f"fleet{fleet}"
        rows = len(pd.read_parquet(folder / "records.parquet", columns=["ts"]))
        status = "OK" if rows == n else f"WARNING: expected {n:,}"
        for name in ("records.parquet", "labels.parquet", "episodes.csv"):
            shutil.copyfile(folder / name, dst / f"fleet{fleet}_{name}")
        print(f"fleet {fleet}: {rows:,} records {status}")
    print(f"upload these 6 files from {dst.resolve()} to /Volumes/workspace/edgesentinel/raw")


if __name__ == "__main__":
    main(*sys.argv[1:])
