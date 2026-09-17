param([int]$Port = 15433)
$ErrorActionPreference = 'Stop'
# Explicit test-only settings. No developer .env is loaded by pytest.
$testValues = @{
    CORE_TEST_DB_HOST = '127.0.0.1'
    CORE_TEST_DB_PORT = [string]$Port
    CORE_TEST_DB_NAME = 'editingtab_core_test'
    CORE_TEST_DB_USERNAME = 'editingtab_test'
    CORE_TEST_DB_PASSWORD = 'editingtab-test-only'
}
$previous = @{}
try {
    foreach ($key in $testValues.Keys) {
        $previous[$key] = [Environment]::GetEnvironmentVariable($key)
        [Environment]::SetEnvironmentVariable($key, $testValues[$key])
    }
    & uv run --locked pytest --integration tests/integration
    if ($LASTEXITCODE -ne 0) { throw 'Integration tests failed.' }
}
finally {
    foreach ($key in $testValues.Keys) {
        [Environment]::SetEnvironmentVariable($key, $previous[$key])
    }
}