$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.env')) {
    Copy-Item '.env.example' '.env'
    $tokenBytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    $token = [Convert]::ToHexString($tokenBytes).ToLowerInvariant()
    $contents = Get-Content '.env' -Raw
    $contents = $contents.Replace('replace_with_a_long_random_secret', $token)
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path (Get-Location) '.env'), $contents, $utf8NoBom)
    Write-Host 'Created .env and generated MCP_BEARER_TOKEN.' -ForegroundColor Green
    Write-Host 'Next: edit .env and set BRAVE_SEARCH_API_KEY, then run: docker compose up -d --build'
} else {
    Write-Host '.env already exists; leaving it unchanged.' -ForegroundColor Yellow
    Write-Host 'Next: verify MCP_BEARER_TOKEN and BRAVE_SEARCH_API_KEY, then run: docker compose up -d --build'
}
