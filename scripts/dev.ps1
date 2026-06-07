param([string]$cmd = "help")
$REDIS_CLI = if ($env:NRVQ_REDIS_CLI) { $env:NRVQ_REDIS_CLI } else { "C:\Program Files\Memurai\memurai-cli.exe" }
$PSQL = if ($env:NRVQ_PSQL) { $env:NRVQ_PSQL } else { "C:\Program Files\PostgreSQL\18\bin\psql.exe" }
$DB_PORT = if ($env:NRVQ_DB_PORT) { $env:NRVQ_DB_PORT } else { "5433" }

switch ($cmd) {
    "api" {
        # Clear shell-level NRVQ_* vars to ensure .env.local wins for local development.
        Get-ChildItem env: | Where-Object { $_.Name -like "NRVQ_*" } | ForEach-Object {
            Remove-Item "env:$($_.Name)"
        }
        if (Test-Path ".env.local") {
            Get-Content ".env.local" | ForEach-Object {
                $line = $_.Trim()
                if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) { return }
                $parts = $line.Split("=", 2)
                $key = $parts[0].Trim()
                $value = $parts[1].Trim().Trim('"').Trim("'")
                if ($key) { Set-Item -Path "env:$key" -Value $value }
            }
            if ($env:NRVQ_DB_POOL_SIZE -and -not $env:NRVQ_PG_POOL_SIZE) {
                $env:NRVQ_PG_POOL_SIZE = $env:NRVQ_DB_POOL_SIZE
            }
            if ($env:NRVQ_DB_POOL_SIZE) {
                # config.py currently resolves pool size from unprefixed PG_POOL_SIZE alias.
                $env:PG_POOL_SIZE = $env:NRVQ_DB_POOL_SIZE
            }
        }
        Write-Host "Cleared shell NRVQ_* env vars; using .env.local" -ForegroundColor Yellow
        python -m uvicorn norviq.api.main:app --host 127.0.0.1 --port 8080 --reload
    }
    "ui" {
        Push-Location ui
        try { npm run dev } finally { Pop-Location }
    }
    "setup" {
        .\scripts\dev-setup.ps1
    }
    "test" {
        $env:NRVQ_API_URL = "http://127.0.0.1:8080"
        python -m pytest tests/attacks/ -v
    }
    "test:all" {
        Write-Host "Running all Norviq tests locally..." -ForegroundColor Cyan

        Write-Host "`n[1/4] Backend unit tests" -ForegroundColor Yellow
        python -m pytest tests/engine/ -v --tb=short
        if ($LASTEXITCODE -ne 0) { Write-Host "Backend unit tests FAILED" -ForegroundColor Red; exit 1 }

        Write-Host "`n[2/4] Backend integration tests" -ForegroundColor Yellow
        python -m pytest tests/integration/ -v --tb=short
        if ($LASTEXITCODE -ne 0) { Write-Host "Integration tests FAILED" -ForegroundColor Red; exit 1 }

        Write-Host "`n[3/4] UI tests" -ForegroundColor Yellow
        Push-Location ui
        npm run test:run
        $uiExit = $LASTEXITCODE
        Pop-Location
        if ($uiExit -ne 0) { Write-Host "UI tests FAILED" -ForegroundColor Red; exit 1 }

        Write-Host "`n[4/4] Attack regression (requires local API running)" -ForegroundColor Yellow
        python -m pytest tests/attacks/ -v --tb=line 2>&1 | Select-Object -Last 3

        Write-Host "`nAll tests done." -ForegroundColor Green
    }
    "seed" {
        python scripts/seed-local-policies.py
    }
    "psql" {
        & $PSQL -U norviq -h 127.0.0.1 -p $DB_PORT -d norviq
    }
    "redis" {
        & $REDIS_CLI -h 127.0.0.1 -p 6379
    }
    default {
        Write-Host "Usage: .\scripts\dev.ps1 <cmd>" -ForegroundColor Cyan
        Write-Host "Commands:" -ForegroundColor Yellow
        Write-Host "  setup  - first-time setup (check tools, create DB, migrate, seed)" -ForegroundColor White
        Write-Host "  api    - start FastAPI server" -ForegroundColor White
        Write-Host "  ui     - start Vite dev server" -ForegroundColor White
        Write-Host "  test   - run attack tests against local API" -ForegroundColor White
        Write-Host "  test:all - run all backend + UI tests locally" -ForegroundColor White
        Write-Host "  seed   - re-seed policies from comprehensive.rego" -ForegroundColor White
        Write-Host "  psql   - open psql shell" -ForegroundColor White
        Write-Host "  redis  - open redis-cli" -ForegroundColor White
    }
}

