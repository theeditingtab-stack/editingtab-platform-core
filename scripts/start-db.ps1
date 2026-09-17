param([switch]$TestDatabase)
$ErrorActionPreference = 'Stop'
if ((Get-Location).Path -ne (Split-Path $PSScriptRoot -Parent)) {
    throw 'Run this script from the project root.'
}
$service = 'db'
$portKey = 'CORE_DB_PORT'
$port = 15432
if ($TestDatabase) {
    $service = 'db-test'
    $portKey = 'CORE_TEST_DB_PORT'
    $port = 15433
}
# Read only the port entry, never display the .env or resolved Compose secrets.
if (Test-Path -LiteralPath '.env') {
    $portLine = Get-Content -LiteralPath '.env' | Where-Object { $_ -match "^$portKey=\d+$" }
    if ($portLine) { $port = [int](($portLine | Select-Object -Last 1) -split '=', 2)[1] }
}
$portOverride = [Environment]::GetEnvironmentVariable($portKey)
if ($portOverride) { $port = [int]$portOverride }
if ($port -lt 1 -or $port -gt 65535) { throw 'Invalid host port.' }
if ($TestDatabase -and $port -eq 15432) { throw 'Test database cannot use the default development port.' }

# Check exact project resource names for conflicting ownership before startup.
foreach ($resource in @(
    @{ Kind = 'volume'; Name = 'editingtab-core-dev_core_postgres_data' },
    @{ Kind = 'network'; Name = 'editingtab-core-dev_default' }
)) {
    $names = & docker $resource.Kind ls --format '{{.Name}}'
    if ($LASTEXITCODE -ne 0) { throw 'Docker resource inspection failed.' }
    if ($names -contains $resource.Name) {
        $labelsJson = & docker $resource.Kind inspect $resource.Name --format '{{json .Labels}}'
        if ($LASTEXITCODE -ne 0) { throw 'Docker label inspection failed.' }
        $labels = $labelsJson | ConvertFrom-Json
        if ($labels.'com.docker.compose.project' -ne 'editingtab-core-dev') {
            throw "Conflicting resource ownership: $($resource.Name)"
        }
    }
}
$existingNames = & docker ps -a --filter "name=editingtab-core-dev-$service-1" --format '{{.Names}}'
if ($LASTEXITCODE -ne 0) { throw 'Docker container inspection failed.' }
$ownedNames = & docker ps -a --filter 'label=com.docker.compose.project=editingtab-core-dev' --filter "label=com.docker.compose.service=$service" --format '{{.Names}}'
if ($LASTEXITCODE -ne 0) { throw 'Docker project inspection failed.' }
foreach ($name in $existingNames) {
    if ($name -eq "editingtab-core-dev-$service-1" -and $ownedNames -notcontains $name) {
        throw "Conflicting container ownership: $name"
    }
}
$running = & docker compose --profile test ps --status running -q $service
if ($LASTEXITCODE -ne 0) { throw 'Compose inspection failed.' }
if ($running) {
    $existingBinding = & docker compose --profile test port $service 5432
    if ($LASTEXITCODE -ne 0) { throw 'Port binding inspection failed.' }
    if ($existingBinding -ne "127.0.0.1:$port") {
        throw 'Service is already running on a different port. Stop only this project service before changing its binding.'
    }
}
else {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
    $listener.Server.ExclusiveAddressUse = $true
    try { $listener.Start() }
    catch { throw "Host port $port is unavailable. Choose a free project port; do not stop unrelated services." }
    finally { $listener.Stop() }
}
& docker compose --profile test up -d --wait $service
if ($LASTEXITCODE -ne 0) { throw 'Database startup failed.' }