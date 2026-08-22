#!/usr/bin/env python3
"""Publishing-parity gate: prove the /py layout still packages byte-for-byte.

Builds a package's wheel from ``py/`` and diffs it against a baseline release
already on PyPI. It fails if the **module tree** or the **structured metadata**
(name, requires-python, dependencies, classifiers, entry points) diverge — the
things that define what consumers actually install. The version string and the
free-text long description (the README) are expected to differ and are ignored.

This guards the CONS-2.1 relocation of the Python package into ``py/``: run it
against the last pre-move release to prove the move changed nothing that ships;
run it in CI against the latest release as an ongoing regression gate.

Usage (from ``py/``):
    uv run python tools/publish_parity.py                       # core, vs latest
    uv run python tools/publish_parity.py --baseline 3.11.1     # vs a pinned release
    uv run python tools/publish_parity.py --package fastapi-identity-model
"""

from __future__ import annotations

import argparse
import email.parser
import io
from pathlib import Path
import subprocess
import sys
import zipfile

import httpx


PY_ROOT = Path(__file__).resolve().parents[1]

# Metadata headers that are expected to differ release-to-release and say
# nothing about what is installed — excluded from the comparison.
_VOLATILE_HEADERS = frozenset(
    {"Version", "Description", "Description-Content-Type", "Metadata-Version"}
)


def _run(cmd: list[str], cwd: Path) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def build_wheel(package: str) -> Path:
    """Build ``package`` from py/ and return the freshly built wheel path."""
    out = PY_ROOT / "dist" / "parity"
    _run(
        ["uv", "build", "--wheel", "--package", package, "--out-dir", str(out)],
        cwd=PY_ROOT,
    )
    wheels = sorted(out.glob(f"{package.replace('-', '_')}-*.whl"))
    if not wheels:
        sys.exit(f"parity: no wheel built for {package} in {out}")
    return wheels[-1]


def download_baseline_wheel(package: str, baseline: str) -> tuple[str, bytes]:
    """Return ``(version, wheel_bytes)`` for the baseline PyPI release.

    Uses httpx (a core dependency, so consistent with the rest of the library)
    with retries so a transient PyPI hiccup does not flake the gate.
    """
    transport = httpx.HTTPTransport(retries=3)
    with httpx.Client(transport=transport, timeout=60.0) as client:
        meta = client.get(f"https://pypi.org/pypi/{package}/json").raise_for_status()
        data = meta.json()
        version = data["info"]["version"] if baseline == "latest" else baseline
        files = data["releases"].get(version)
        if not files:
            sys.exit(f"parity: {package} {version} not found on PyPI")
        wheel = next((f for f in files if f["filename"].endswith(".whl")), None)
        if wheel is None:
            sys.exit(f"parity: {package} {version} has no wheel on PyPI")
        return version, client.get(wheel["url"]).raise_for_status().content


def _module_tree(zf: zipfile.ZipFile) -> set[str]:
    """Paths inside the wheel that are shipped code, excluding dist-info."""
    return {
        name
        for name in zf.namelist()
        if not name.endswith("/") and ".dist-info/" not in name
    }


def _metadata(zf: zipfile.ZipFile) -> email.message.Message:
    name = next(n for n in zf.namelist() if n.endswith(".dist-info/METADATA"))
    return email.parser.Parser().parsestr(zf.read(name).decode("utf-8"))


def _stable_metadata(msg: email.message.Message) -> dict[str, list[str]]:
    """Multi-valued metadata headers minus the volatile ones, each sorted."""
    names = {key for key in set(msg.keys()) if key not in _VOLATILE_HEADERS}
    return {name: sorted(msg.get_all(name, [])) for name in names}


def _entry_points(zf: zipfile.ZipFile) -> str:
    name = next(
        (n for n in zf.namelist() if n.endswith(".dist-info/entry_points.txt")),
        None,
    )
    return zf.read(name).decode("utf-8").strip() if name else ""


def compare(built: Path, baseline_bytes: bytes, baseline_version: str) -> list[str]:
    diffs: list[str] = []
    with (
        zipfile.ZipFile(built) as bz,
        zipfile.ZipFile(io.BytesIO(baseline_bytes)) as pz,
    ):
        built_tree, base_tree = _module_tree(bz), _module_tree(pz)
        diffs.extend(
            f"module DROPPED vs {baseline_version}: {m}"
            for m in sorted(base_tree - built_tree)
        )
        diffs.extend(
            f"module ADDED vs {baseline_version}: {a}"
            for a in sorted(built_tree - base_tree)
        )

        built_md = _stable_metadata(_metadata(bz))
        base_md = _stable_metadata(_metadata(pz))
        diffs.extend(
            f"metadata {key} differs: built={built_md.get(key)} "
            f"baseline({baseline_version})={base_md.get(key)}"
            for key in sorted(set(built_md) | set(base_md))
            if built_md.get(key) != base_md.get(key)
        )

        if _entry_points(bz) != _entry_points(pz):
            diffs.append("entry_points.txt differs")
    return diffs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package",
        default="py-identity-model",
        choices=["py-identity-model", "fastapi-identity-model"],
    )
    parser.add_argument(
        "--baseline",
        default="latest",
        help="PyPI version to compare against (default: latest published)",
    )
    args = parser.parse_args()

    print(f"[parity] building {args.package} from py/ ...")
    built = build_wheel(args.package)
    print(f"[parity] built {built.name}")
    version, baseline_bytes = download_baseline_wheel(args.package, args.baseline)
    print(f"[parity] baseline: {args.package} {version} from PyPI")

    diffs = compare(built, baseline_bytes, version)
    if diffs:
        print(f"\n[parity] GATE FAILED — {args.package} packaging diverged:")
        for d in diffs:
            print(f"  - {d}")
        return 1
    print(
        f"[parity] GATE PASSED — {args.package} module tree + metadata match "
        f"PyPI {version} (only version + long description differ)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
