# Dot-source from the project root. All tool storage stays in this workspace.
$projectRoot = Split-Path $PSScriptRoot -Parent
$env:UV_CACHE_DIR = Join-Path $projectRoot '.tools/uv-cache'
$env:UV_PYTHON_INSTALL_DIR = Join-Path $projectRoot '.tools/python'
$env:UV_PYTHON_BIN_DIR = Join-Path $projectRoot '.tools/bin'
$bootstrapScripts = Join-Path $projectRoot '.tools/bootstrap/Scripts'
if (Test-Path -LiteralPath (Join-Path $bootstrapScripts 'uv.exe')) {
    $env:PATH = "$bootstrapScripts;$env:PATH"
}