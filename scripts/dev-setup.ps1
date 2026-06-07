# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
# Norviq local dev setup for Windows + Memurai + PostgreSQL 18

Write-Host "Norviq local dev setup" -ForegroundColor Cyan

if (-not (Test-Path ".env.local")) {
    Write-Host "  .env.local missing. Copy .env.local.example first." -ForegroundColor Red
    exit 1
}

function Get-EnvLocalValue([string]$key) {
    $line = Get-Content ".env.local" | Select-String "^$key="
    if (-not $line) { return "" }
    return ($line.ToString().Split("=", 2)[1]).Trim()
}

# Tool path overrides
$REDIS_CLI = if ($env:NRVQ_REDIS_CLI) { $env:NRVQ_REDIS_CLI } else { "C:\Program Files\Memurai\memurai-cli.exe" }
$PSQL = if ($env:NRVQ_PSQL) { $env:NRVQ_PSQL } else { "C:\Program Files\PostgreSQL\18\bin\psql.exe" }
$DB_PORT = if ($env:NRVQ_DB_PORT) { $env:NRVQ_DB_PORT } else { "5433" }

$dbHost = Get-EnvLocalValue "NRVQ_DB_HOST"
if (-not $dbHost) { $dbHost = "127.0.0.1" }
$dbPort = Get-EnvLocalValue "NRVQ_DB_PORT"
if (-not $dbPort) { $dbPort = $DB_PORT }
$dbUser = Get-EnvLocalValue "NRVQ_DB_USER"
if (-not $dbUser) { $dbUser = "norviq" }
$dbName = Get-EnvLocalValue "NRVQ_DB_NAME"
if (-not $dbName) { $dbName = "norviq" }
$dbPassword = Get-EnvLocalValue "NRVQ_DB_PASSWORD"

# Check Memurai
Write-Host "`nChecking Memurai..." -ForegroundColor Yellow
try {
    $redisPing = & $REDIS_CLI -h 127.0.0.1 -p 6379 PING
    if ($redisPing -eq "PONG") {
        Write-Host "  Memurai: OK" -ForegroundColor Green
    } else {
        Write-Host "  Memurai: NOT RESPONDING" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "  Memurai not installed or not running" -ForegroundColor Red
    exit 1
}

# Check PostgreSQL
Write-Host "`nChecking PostgreSQL..." -ForegroundColor Yellow
$env:PGPASSWORD = $dbPassword
try {
    $pgVer = & $PSQL -U $dbUser -h $dbHost -p $dbPort -d $dbName -c "SELECT 1;" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  PostgreSQL: OK" -ForegroundColor Green
    } else {
        Write-Host "  PostgreSQL connection failed: $pgVer" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "  PostgreSQL not installed or not running" -ForegroundColor Red
    exit 1
}

# Create database if not exists
Write-Host "`nCreating database..." -ForegroundColor Yellow
& $PSQL -U $dbUser -h $dbHost -p $dbPort -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$dbName'" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Failed to query databases." -ForegroundColor Red
    exit 1
}
$exists = & $PSQL -U $dbUser -h $dbHost -p $dbPort -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$dbName'"
if (-not $exists) {
    & $PSQL -U $dbUser -h $dbHost -p $dbPort -d postgres -c "CREATE DATABASE $dbName;" 2>&1 | Out-Null
}
Write-Host "  Database: ready" -ForegroundColor Green

# Run migrations
Write-Host "`nRunning Alembic migrations..." -ForegroundColor Yellow
if (-not (Test-Path "alembic.ini")) {
    Write-Host "  alembic.ini not found; skipping migrations for local setup." -ForegroundColor Yellow
} else {
    if (Get-Command alembic -ErrorAction SilentlyContinue) {
        & alembic upgrade head
    } else {
        $pythonExe = (& python -c "import sys; print(sys.executable)").Trim()
        $pythonDir = Split-Path $pythonExe -Parent
        $alembicExe = Join-Path $pythonDir "Scripts\alembic.exe"
        if (Test-Path $alembicExe) {
            & $alembicExe upgrade head
        } else {
            Write-Host "  Alembic executable not found in PATH or Python Scripts." -ForegroundColor Red
            exit 1
        }
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Migrations failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "  Migrations: applied" -ForegroundColor Green
}

# Seed comprehensive policy
Write-Host "`nSeeding policies..." -ForegroundColor Yellow
python scripts/seed-local-policies.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Policy seed failed (continuing local setup). Re-run: .\scripts\dev.ps1 seed" -ForegroundColor Yellow
    $global:LASTEXITCODE = 0
} else {
    Write-Host "  Policies: loaded" -ForegroundColor Green
}

Write-Host "`nDone. Start the API with:" -ForegroundColor Cyan
Write-Host "  python -m uvicorn norviq.api.main:app --host 127.0.0.1 --port 8080" -ForegroundColor White

