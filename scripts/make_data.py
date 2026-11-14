"""Build every P1 dataset with one command, and check it matches Person 1's copy.

    python -m scripts.make_data            # fleets A and B (v2) + data/upload/ for Databricks
    python -m scripts.make_data --extra    # also fleet A with seeds 3 and 4 (seed-range results)
    python -m scripts.make_data --record   # P1 only: rewrite simulator/data_manifest.json

The simulator is deterministic, so anyone can rebuild the exact same data from main
instead of downloading it. The check compares a content fingerprint of each file with
simulator/data_manifest.json (the fingerprints of P1's copy). Data stays out of Git.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

from simulator.generate_dataset import generate, write

MANIFEST = Path(__file__).resolve().parent.parent / "simulator" / "data_manifest.json"
FLEETS = {  # name: (fleet, seed, routers, expected records)
    "fleetA": ("A", 1, 60, 172_800),
    "fleetB": ("B", 2, 30, 86_400),
}
EXTRA = {"fleetA_seed3": ("A", 3, 60, 172_800), "fleetA_seed4": ("A", 4, 60, 172_800)}


def fingerprint(df: pd.DataFrame) -> str:
    """Hash of the table's contents (not file bytes, which vary with the pyarrow version)."""
    df = df.copy()
    for c in df.columns:
        if df[c].map(lambda v: isinstance(v, (list, tuple)) or hasattr(v, "tolist")).any():
            df[c] = df[c].map(lambda v: "|".join(map(str, list(v))))
    h = hashlib.sha256(",".join(df.columns).encode())
    h.update(pd.util.hash_pandas_object(df.astype(str), index=False).values.tobytes())
    return h.hexdigest()[:16]


def build(name: str, spec, out_root: Path) -> dict:
    fleet, seed, routers, expected = spec
    records, labels, episodes = generate(fleet, seed=seed, routers=routers, days=2)
    assert len(records) == expected, f"{name}: {len(records)} records, expected {expected}"
    write(records, labels, episodes, out_root / name)
    eps = pd.read_csv(out_root / name / "episodes.csv", keep_default_na=False)
    return {"records": fingerprint(records), "labels": fingerprint(labels),
            "episodes": fingerprint(eps), "n_records": len(records), "n_episodes": len(eps)}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    ap.add_argument("--extra", action="store_true", help="also fleet A seeds 3 and 4")
    ap.add_argument("--record", action="store_true", help="P1 only: save fingerprints to the manifest")
    a = ap.parse_args(argv)
    out = Path(a.out)
    todo = {**FLEETS, **(EXTRA if a.extra or a.record else {})}
    expected = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    got, ok = {}, True
    for name, spec in todo.items():
        got[name] = build(name, spec, out)
        want = expected.get(name)
        status = "new" if want is None else "MATCHES P1's copy" if want == got[name] else "DIFFERS from P1's copy"
        ok &= status != "DIFFERS from P1's copy"
        print(f"{name:13} {got[name]['n_records']:>7,} records  {got[name]['n_episodes']:>3} episodes  {status}")
    if a.record:
        MANIFEST.write_text(json.dumps(got, indent=2) + "\n")
        print(f"wrote {MANIFEST}")
    from scripts.prepare_upload import main as prepare
    prepare(str(out), str(out / "upload"))
    if not ok:
        print("Data differs: check numpy/pandas versions against P1's (pip list) and tell P1.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
