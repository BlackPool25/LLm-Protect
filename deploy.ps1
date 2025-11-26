# LLM-Protect Deployment Script for Windows
# Run with: powershell -ExecutionPolicy Bypass -File deploy.ps1

$ErrorActionPreference = "Stop"

Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║     LLM-Protect Deployment Script v1.0.0             ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

try {
    $dockerVersion = docker --version
    Write-Host "✓ Docker found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker not found. Please install Docker Desktop first." -ForegroundColor Red
    exit 1
}

try {
    $composeVersion = docker-compose --version
    Write-Host "✓ Docker Compose found: $composeVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker Compose not found. Please install Docker Compose first." -ForegroundColor Red
    exit 1
}

Write-Host ""

# Check if .env exists
if (-not (Test-Path .env)) {
    Write-Host "⚠ .env file not found. Creating from template..." -ForegroundColor Yellow
    
    # Generate random API key
    $apiKey = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
    
    $envContent = @"
# LLM-Protect Environment Configuration
# Generated on $(Get-Date)

# Layer-0 API Key (IMPORTANT: Change this in production!)
LAYER0_API_KEY=$apiKey

# Grafana admin password
GRAFANA_PASSWORD=admin

# Logging
LOG_LEVEL=INFO

# Workers
UVICORN_WORKERS=4
"@
    
    $envContent | Out-File -FilePath .env -Encoding utf8
    
    Write-Host "✓ Created .env file with random API key" -ForegroundColor Green
    Write-Host "  API Key: $apiKey" -ForegroundColor Yellow
    Write-Host "  Please review and update .env file before production deployment!" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "✓ .env file found" -ForegroundColor Green
    Write-Host ""
}

# Menu
Write-Host "What would you like to do?" -ForegroundColor Yellow
Write-Host "1) Deploy all services (recommended)"
Write-Host "2) Deploy Layer-0 only"
Write-Host "3) Deploy Input Prep only"
Write-Host "4) Stop all services"
Write-Host "5) View logs"
Write-Host "6) Run tests"
Write-Host "7) Clean up (remove containers and volumes)"
Write-Host "8) Show service status"
Write-Host "9) Exit"
Write-Host ""

$choice = Read-Host "Enter choice [1-9]"

switch ($choice) {
    1 {
        Write-Host "Starting all services..." -ForegroundColor Green
        docker-compose up -d
        Write-Host ""
        Write-Host "✓ All services started!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Services available at:" -ForegroundColor Yellow
        Write-Host "  • Input Prep API: http://localhost:8080/docs"
        Write-Host "  • Layer-0 API: http://localhost:8000/docs"
        Write-Host "  • Grafana: http://localhost:3000 (admin/admin)"
        Write-Host "  • Prometheus: http://localhost:9090"
        Write-Host ""
        Write-Host "View logs with: docker-compose logs -f" -ForegroundColor Yellow
    }
    
    2 {
        Write-Host "Starting Layer-0 service..." -ForegroundColor Green
        docker-compose up -d layer0
        Write-Host "✓ Layer-0 started!" -ForegroundColor Green
        Write-Host "  • API: http://localhost:8000/docs"
    }
    
    3 {
        Write-Host "Starting Input Prep service..." -ForegroundColor Green
        docker-compose up -d inputprep
        Write-Host "✓ Input Prep started!" -ForegroundColor Green
        Write-Host "  • API: http://localhost:8080/docs"
    }
    
    4 {
        Write-Host "Stopping all services..." -ForegroundColor Yellow
        docker-compose down
        Write-Host "✓ All services stopped" -ForegroundColor Green
    }
    
    5 {
        Write-Host "Showing logs (Ctrl+C to exit)..." -ForegroundColor Green
        docker-compose logs -f
    }
    
    6 {
        Write-Host "Running tests..." -ForegroundColor Green
        
        if (Get-Command poetry -ErrorAction SilentlyContinue) {
            poetry run pytest tests/ -v --tb=short
        } else {
            Write-Host "Poetry not found. Please install Poetry or run tests manually." -ForegroundColor Yellow
        }
    }
    
    7 {
        $confirm = Read-Host "⚠ This will remove all containers and volumes. Are you sure? [y/N]"
        if ($confirm -eq "y" -or $confirm -eq "Y") {
            docker-compose down -v
            Write-Host "✓ Cleanup complete" -ForegroundColor Green
        } else {
            Write-Host "Cleanup cancelled" -ForegroundColor Yellow
        }
    }
    
    8 {
        Write-Host "Service Status:" -ForegroundColor Green
        docker-compose ps
        Write-Host ""
        Write-Host "Health Checks:" -ForegroundColor Green
        
        # Check Layer-0
        try {
            $null = Invoke-WebRequest -Uri http://localhost:8000/health/live -UseBasicParsing -TimeoutSec 2
            Write-Host "  ✓ Layer-0: healthy" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Layer-0: unhealthy or not running" -ForegroundColor Red
        }
        
        # Check Input Prep
        try {
            $null = Invoke-WebRequest -Uri http://localhost:8080/health -UseBasicParsing -TimeoutSec 2
            Write-Host "  ✓ Input Prep: healthy" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Input Prep: unhealthy or not running" -ForegroundColor Red
        }
        
        # Check Prometheus
        try {
            $null = Invoke-WebRequest -Uri http://localhost:9090/-/healthy -UseBasicParsing -TimeoutSec 2
            Write-Host "  ✓ Prometheus: healthy" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Prometheus: unhealthy or not running" -ForegroundColor Red
        }
        
        # Check Grafana
        try {
            $null = Invoke-WebRequest -Uri http://localhost:3000/api/health -UseBasicParsing -TimeoutSec 2
            Write-Host "  ✓ Grafana: healthy" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Grafana: unhealthy or not running" -ForegroundColor Red
        }
    }
    
    9 {
        Write-Host "Goodbye!" -ForegroundColor Green
        exit 0
    }
    
    default {
        Write-Host "Invalid choice" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
