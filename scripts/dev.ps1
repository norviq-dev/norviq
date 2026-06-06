param([string]$cmd = "help")
$REDIS_CLI = if ($env:NRVQ_REDIS_CLI) { $env:NRVQ_REDIS_CLI } else { "C:\Program Files\Memurai\memurai-cli.exe" }
$PSQL = if ($env:NRVQ_PSQL) { $env:NRVQ_PSQL } else { "C:\Program Files\PostgreSQL\18\bin\psql.exe" }
$DB_PORT = if ($env:NRVQ_DB_PORT) { $env:NRVQ_DB_PORT } else { "5433" }

switch ($cmd) {
    "api" {
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
        Write-Host "  seed   - re-seed policies from comprehensive.rego" -ForegroundColor White
        Write-Host "  psql   - open psql shell" -ForegroundColor White
        Write-Host "  redis  - open redis-cli" -ForegroundColor White
    }
}
