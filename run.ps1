<#
.SYNOPSIS
    Verify the environment and launch the Insider Threat Predictor.

.DESCRIPTION
    Resolves a Python interpreter (3.12 or 3.13 - Kev requires >=3.12,<3.14),
    runs the build verification script against a throwaway database, then
    launches the GUI.

.PARAMETER Python
    Path to the interpreter to use. Overrides every other source.

.PARAMETER SkipVerify
    Launch the GUI without running the build verification first.

.PARAMETER SkipModel
    Run the verification but skip the two checks that load the Kev checkpoint.
    Useful on a machine without a GPU.

.EXAMPLE
    .\run.ps1
    .\run.ps1 -Python "C:\envs\kev-env\Scripts\python.exe"
    .\run.ps1 -SkipVerify

.NOTES
    The interpreter is looked up in this order:
        1. -Python
        2. $env:ITP_PYTHON
        3. .python-path   (a one-line file holding an interpreter path)
        4. .\.venv\Scripts\python.exe
        5. .\venv\Scripts\python.exe
        6. $env:KEV_ENV\Scripts\python.exe
        7. python on PATH
#>

[CmdletBinding()]
param(
    [string]$Python,
    [switch]$SkipVerify,
    [switch]$SkipModel
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

function Write-Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }
function Write-Ok($text)   { Write-Host "    $text" -ForegroundColor Green }
function Write-Warn($text) { Write-Host "    $text" -ForegroundColor Yellow }

# --------------------------------------------------------------------------
# 1. Resolve the interpreter
# --------------------------------------------------------------------------
Write-Step "Resolving the Python interpreter"

$candidates = [System.Collections.Generic.List[string]]::new()
if ($Python)                                    { $candidates.Add($Python) }
if ($env:ITP_PYTHON)                            { $candidates.Add($env:ITP_PYTHON) }

$pathFile = Join-Path $root ".python-path"
if (Test-Path -LiteralPath $pathFile -PathType Leaf) {
    $recorded = (Get-Content -LiteralPath $pathFile -TotalCount 1)
    if ($recorded) { $candidates.Add($recorded.Trim()) }
}

$candidates.Add((Join-Path $root ".venv\Scripts\python.exe"))
$candidates.Add((Join-Path $root "venv\Scripts\python.exe"))
if ($env:KEV_ENV)                               { $candidates.Add((Join-Path $env:KEV_ENV "Scripts\python.exe")) }
$candidates.Add("python")

$exe = $null
foreach ($candidate in $candidates) {
    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $exe = (Resolve-Path -LiteralPath $candidate).Path
        break
    }
    $command = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($command) { $exe = $command.Source; break }
}

if (-not $exe) {
    Write-Host "No Python interpreter found." -ForegroundColor Red
    Write-Host "Install Python 3.12 or 3.13, or pass one explicitly:"
    Write-Host "    .\run.ps1 -Python C:\path\to\python.exe"
    exit 2
}
Write-Ok $exe

# --------------------------------------------------------------------------
# 2. Check the version (Kev requires >=3.12,<3.14)
# --------------------------------------------------------------------------
Write-Step "Checking the Python version"

$version = & $exe -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Could not run $exe" -ForegroundColor Red
    exit 2
}
Write-Ok "Python $version"

$supported = @("3.12", "3.13")
if ($supported -notcontains $version) {
    Write-Host "Python $version is not supported by this project." -ForegroundColor Red
    Write-Host "Kev needs >=3.12,<3.14, and the GUI uses 3.12+ f-string syntax."
    Write-Host "Point -Python at a 3.12 or 3.13 interpreter."
    exit 2
}

# --------------------------------------------------------------------------
# 3. Verify the build
# --------------------------------------------------------------------------
if (-not $SkipVerify) {
    Write-Step "Verifying the build (throwaway database, your data is untouched)"
    $verifyArgs = @("scripts\verify_build.py")
    if ($SkipModel) { $verifyArgs += "--skip-model" }
    & $exe @verifyArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build verification failed - not launching." -ForegroundColor Red
        exit 1
    }
    Write-Ok "Verification passed"
} else {
    Write-Warn "Build verification skipped (-SkipVerify)"
}

# --------------------------------------------------------------------------
# 4. Launch
# --------------------------------------------------------------------------
Write-Step "Launching the Insider Threat Predictor"
Write-Host "    Kev loads in the background; the GUI shows a loading state until it is ready."
& $exe "main.py"
exit $LASTEXITCODE
