#!/bin/bash
# LLM-Protect Deployment Script
# This script helps deploy the LLM-Protect system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     LLM-Protect Deployment Script v1.0.0             ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker not found. Please install Docker first.${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose not found. Please install Docker Compose first.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker found: $(docker --version)${NC}"
echo -e "${GREEN}✓ Docker Compose found: $(docker-compose --version)${NC}"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠ .env file not found. Creating from template...${NC}"
    
    # Generate random API key
    API_KEY=$(openssl rand -hex 32)
    
    cat > .env << EOF
# LLM-Protect Environment Configuration
# Generated on $(date)

# Layer-0 API Key (IMPORTANT: Change this in production!)
LAYER0_API_KEY=${API_KEY}

# Grafana admin password
GRAFANA_PASSWORD=admin

# Logging
LOG_LEVEL=INFO

# Workers
UVICORN_WORKERS=4
EOF
    
    echo -e "${GREEN}✓ Created .env file with random API key${NC}"
    echo -e "${YELLOW}  API Key: ${API_KEY}${NC}"
    echo -e "${YELLOW}  Please review and update .env file before production deployment!${NC}"
    echo ""
else
    echo -e "${GREEN}✓ .env file found${NC}"
    echo ""
fi

# Menu
echo -e "${YELLOW}What would you like to do?${NC}"
echo "1) Deploy all services (recommended)"
echo "2) Deploy Layer-0 only"
echo "3) Deploy Input Prep only"
echo "4) Stop all services"
echo "5) View logs"
echo "6) Run tests"
echo "7) Clean up (remove containers and volumes)"
echo "8) Show service status"
echo "9) Exit"
echo ""
read -p "Enter choice [1-9]: " choice

case $choice in
    1)
        echo -e "${GREEN}Starting all services...${NC}"
        docker-compose up -d
        echo ""
        echo -e "${GREEN}✓ All services started!${NC}"
        echo ""
        echo -e "${YELLOW}Services available at:${NC}"
        echo "  • Input Prep API: http://localhost:8080/docs"
        echo "  • Layer-0 API: http://localhost:8000/docs"
        echo "  • Grafana: http://localhost:3000 (admin/admin)"
        echo "  • Prometheus: http://localhost:9090"
        echo ""
        echo -e "${YELLOW}View logs with: docker-compose logs -f${NC}"
        ;;
    
    2)
        echo -e "${GREEN}Starting Layer-0 service...${NC}"
        docker-compose up -d layer0
        echo -e "${GREEN}✓ Layer-0 started!${NC}"
        echo "  • API: http://localhost:8000/docs"
        ;;
    
    3)
        echo -e "${GREEN}Starting Input Prep service...${NC}"
        docker-compose up -d inputprep
        echo -e "${GREEN}✓ Input Prep started!${NC}"
        echo "  • API: http://localhost:8080/docs"
        ;;
    
    4)
        echo -e "${YELLOW}Stopping all services...${NC}"
        docker-compose down
        echo -e "${GREEN}✓ All services stopped${NC}"
        ;;
    
    5)
        echo -e "${GREEN}Showing logs (Ctrl+C to exit)...${NC}"
        docker-compose logs -f
        ;;
    
    6)
        echo -e "${GREEN}Running tests...${NC}"
        
        # Check if Poetry is installed
        if command -v poetry &> /dev/null; then
            poetry run pytest tests/ -v --tb=short
        else
            echo -e "${YELLOW}Poetry not found. Running tests in Docker...${NC}"
            docker run --rm -v $(pwd):/app -w /app python:3.11-slim \
                bash -c "pip install -q poetry && poetry install --with dev && poetry run pytest tests/ -v"
        fi
        ;;
    
    7)
        echo -e "${RED}⚠ This will remove all containers and volumes. Are you sure? [y/N]${NC}"
        read -p "" confirm
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            docker-compose down -v
            echo -e "${GREEN}✓ Cleanup complete${NC}"
        else
            echo -e "${YELLOW}Cleanup cancelled${NC}"
        fi
        ;;
    
    8)
        echo -e "${GREEN}Service Status:${NC}"
        docker-compose ps
        echo ""
        echo -e "${GREEN}Health Checks:${NC}"
        
        # Check Layer-0
        if curl -s -f http://localhost:8000/health/live > /dev/null 2>&1; then
            echo -e "  ${GREEN}✓ Layer-0: healthy${NC}"
        else
            echo -e "  ${RED}✗ Layer-0: unhealthy or not running${NC}"
        fi
        
        # Check Input Prep
        if curl -s -f http://localhost:8080/health > /dev/null 2>&1; then
            echo -e "  ${GREEN}✓ Input Prep: healthy${NC}"
        else
            echo -e "  ${RED}✗ Input Prep: unhealthy or not running${NC}"
        fi
        
        # Check Prometheus
        if curl -s -f http://localhost:9090/-/healthy > /dev/null 2>&1; then
            echo -e "  ${GREEN}✓ Prometheus: healthy${NC}"
        else
            echo -e "  ${RED}✗ Prometheus: unhealthy or not running${NC}"
        fi
        
        # Check Grafana
        if curl -s -f http://localhost:3000/api/health > /dev/null 2>&1; then
            echo -e "  ${GREEN}✓ Grafana: healthy${NC}"
        else
            echo -e "  ${RED}✗ Grafana: unhealthy or not running${NC}"
        fi
        ;;
    
    9)
        echo -e "${GREEN}Goodbye!${NC}"
        exit 0
        ;;
    
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Done!${NC}"
