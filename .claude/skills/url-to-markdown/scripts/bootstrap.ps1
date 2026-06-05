# Thin Windows wrapper: find a Python 3 interpreter and invoke bootstrap.py.
# All real logic lives in bootstrap.py so there is one source of truth.
$ErrorActionPreference = "Stop"

$Here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$BootstrapPy = Join-Path $Here "bootstrap.py"

# Prefer py.exe (Python launcher for Windows), fall back to python on PATH.
if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $BootstrapPy @args
    exit $LASTEXITCODE
}

if (Get-Command python -ErrorAction SilentlyContinue) {
    & python $BootstrapPy @args
    exit $LASTEXITCODE
}

Write-Error "No Python 3 interpreter found. Install Python 3.12+ from https://python.org (or run 'uv python install 3.12' after installing uv from https://docs.astral.sh/uv/getting-started/installation/) and retry."
exit 5
