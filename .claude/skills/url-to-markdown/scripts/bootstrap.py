"""Dependency cascade for the url-to-markdown skill.

Checks the environment for the fastest viable way to run the main script:

  1. If the current Python interpreter already has trafilatura, curl_cffi, and
     browser_cookie3 importable, run the main script in-process. Zero setup cost.
     This handles the case where a user has already created a venv with the deps,
     or is running in an environment where they're globally available.

  2. Otherwise, if `uv` is on PATH, delegate to `uv run --with ...`. uv creates
     an ephemeral (cached) environment on the fly, so this is nearly as fast as
     option 1 after the first run.

  3. Otherwise, create a dedicated venv at a stable cache location and install
     the deps via pip. Slower first run (~15-30 seconds), but self-contained and
     reused on subsequent invocations.

  4. If none of the above work (no pip, no Python stdlib venv module, etc.),
     fail with a clear diagnostic and actionable install instructions.

Invocation:

    python bootstrap.py <url> [--out DIR] [--json] [...]

All arguments after the script name are forwarded verbatim to url_to_markdown.py.

See ../SKILL.md for full usage and ../references/tool-selection-rationale.md
for why this cascade exists rather than a single declared dependency.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Required third-party deps. Keep in sync with url_to_markdown.py's imports
# and lib/extractors.py's imports.
REQUIRED = ("trafilatura", "curl_cffi", "browser_cookie3", "beautifulsoup4")

# Map pip package names to their Python import names where they differ.
# importlib.util.find_spec() needs the import name; pip install needs the
# package name. Most packages share the same name; beautifulsoup4 is the
# notable exception (pip name "beautifulsoup4", imports as "bs4").
_PIP_TO_IMPORT_NAME = {
    "beautifulsoup4": "bs4",
}

MIN_PYTHON = (3, 12)

_HERE = Path(__file__).resolve().parent
MAIN_SCRIPT = _HERE / "url_to_markdown.py"


def _deps_importable() -> bool:
    """True if all required packages can be found by the current interpreter."""
    return all(
        importlib.util.find_spec(_PIP_TO_IMPORT_NAME.get(name, name)) is not None
        for name in REQUIRED
    )


def _cache_venv_root() -> Path:
    """Stable per-user cache location for the skill's venv."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "url-to-markdown" / "venv"
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "url-to-markdown" / "venv"
    return Path.home() / ".cache" / "url-to-markdown" / "venv"


def _venv_python(venv_dir: Path) -> Path:
    """Return the path to the Python interpreter inside a venv."""
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _create_venv_and_install(venv_dir: Path) -> Path:
    """Create a venv at venv_dir, install the deps, return the venv's python path."""
    import venv

    print(
        f"[bootstrap] Creating venv at {venv_dir} (first run may take 20-30s)...",
        file=sys.stderr,
    )
    venv_dir.parent.mkdir(parents=True, exist_ok=True)
    builder = venv.EnvBuilder(with_pip=True, clear=False, upgrade_deps=False)
    builder.create(str(venv_dir))

    vpy = _venv_python(venv_dir)
    if not vpy.exists():
        raise RuntimeError(f"Venv creation succeeded but {vpy} not found")

    print(f"[bootstrap] Installing {', '.join(REQUIRED)}...", file=sys.stderr)
    result = subprocess.run(
        [str(vpy), "-m", "pip", "install", "--quiet", "--upgrade",
         "pip", *REQUIRED],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"pip install failed:\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

    # Sentinel: signals that this venv has all required deps installed.
    # Checked by main() to skip the per-run import verification subprocess.
    sentinel = venv_dir / ".deps-ok"
    try:
        sentinel.write_text(
            f"deps={','.join(REQUIRED)}\n"
            f"python={sys.version_info.major}.{sys.version_info.minor}\n",
            encoding="utf-8",
        )
    except OSError:
        pass  # best-effort; not a blocker

    return vpy


def _run_in_process(argv: list[str]) -> int:
    """Import and run the main script in the current interpreter."""
    sys.path.insert(0, str(_HERE))
    from url_to_markdown import main as main_runner  # type: ignore[import-not-found]
    return main_runner(argv)


def _exec_subprocess(python_path: Path, argv: list[str]) -> int:
    """Run the main script as a subprocess and return its exit code."""
    result = subprocess.run(
        [str(python_path), str(MAIN_SCRIPT), *argv],
    )
    return result.returncode


def _exec_uv(uv_path: str, argv: list[str]) -> int:
    """Run the main script via `uv run --with ...`. Caches after first run."""
    cmd = [uv_path, "run"]
    for dep in REQUIRED:
        cmd.extend(["--with", dep])
    cmd.extend(["python", str(MAIN_SCRIPT), *argv])
    print(
        f"[bootstrap] Using uv ephemeral environment (cached after first run)",
        file=sys.stderr,
    )
    result = subprocess.run(cmd)
    return result.returncode


def main() -> int:
    if sys.version_info < MIN_PYTHON:
        print(
            f"[bootstrap] Python {'.'.join(map(str, MIN_PYTHON))}+ required "
            f"(3.12 is current stable, 3.11 EOL Oct 2027, 3.10 EOL Oct 2026, "
            f"3.9 EOL Oct 2025), but found "
            f"{sys.version_info.major}.{sys.version_info.minor}. "
            f"Install a newer Python, or use uv python install 3.12 "
            f"(https://docs.astral.sh/uv/getting-started/installation/).",
            file=sys.stderr,
        )
        return 5

    forwarded = sys.argv[1:]

    # Tier 1: all deps are already importable in this interpreter.
    if _deps_importable():
        return _run_in_process(forwarded)

    # Tier 2: uv is on PATH — fastest path that installs anything.
    uv = shutil.which("uv")
    if uv:
        return _exec_uv(uv, forwarded)

    # Tier 3: create a dedicated venv at the cache location, reuse across runs.
    venv_dir = _cache_venv_root()
    vpy = _venv_python(venv_dir)
    sentinel = venv_dir / ".deps-ok"

    if vpy.exists():
        if sentinel.exists():
            # Fast path: sentinel says deps were installed successfully on a
            # prior run. Skip the per-invocation import verification subprocess
            # and exec the main script directly. Saves ~100-300ms on each run
            # which agent hot-loops pay every time.
            return _exec_subprocess(vpy, forwarded)

        # Fallback: venv exists but sentinel is missing (could be a partial
        # install from an interrupted prior run, or a venv from before the
        # sentinel was introduced). Verify by actually importing the deps;
        # on success, write the sentinel so the next run hits the fast path.
        check = subprocess.run(
            [str(vpy), "-c", "import " + ", ".join(REQUIRED)],
            capture_output=True,
        )
        if check.returncode == 0:
            try:
                sentinel.write_text(
                    f"deps={','.join(REQUIRED)}\n"
                    f"python={sys.version_info.major}.{sys.version_info.minor}\n",
                    encoding="utf-8",
                )
            except OSError:
                pass  # sentinel write is best-effort; not a blocker
            return _exec_subprocess(vpy, forwarded)
        # Partial venv — rebuild.
        print(
            f"[bootstrap] Existing venv at {venv_dir} is missing deps; "
            f"reinstalling...",
            file=sys.stderr,
        )

    # Fresh venv creation — print a one-time hint that uv would make
    # future runs dramatically faster. Hint only appears on fresh-venv
    # creation, not on every invocation.
    print(
        "[bootstrap] Note: installing uv would make future runs of this "
        "skill (and other Python tools) ~20x faster by skipping the venv "
        "dance entirely. See https://docs.astral.sh/uv/getting-started/installation/",
        file=sys.stderr,
    )

    try:
        vpy = _create_venv_and_install(venv_dir)
    except Exception as exc:
        print(
            f"[bootstrap] Could not create venv: {exc}\n"
            f"\n"
            f"To fix, either:\n"
            f"  (a) install uv from "
            f"https://docs.astral.sh/uv/getting-started/installation/ "
            f"— fastest and cleanest\n"
            f"  (b) install deps into your system Python:\n"
            f"      pip install {' '.join(REQUIRED)}\n"
            f"  (c) check that your Python has the `venv` and `pip` modules "
            f"available (on some Linux distros, install python3.12-venv).",
            file=sys.stderr,
        )
        return 5

    return _exec_subprocess(vpy, forwarded)


if __name__ == "__main__":
    raise SystemExit(main())
