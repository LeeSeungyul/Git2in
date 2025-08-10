#!/bin/bash
# Docker development helper script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${PROJECT_ROOT}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_help() {
    echo "Git2in Docker Development Helper"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  up        Start all services"
    echo "  down      Stop all services"
    echo "  restart   Restart all services"
    echo "  build     Build Docker images"
    echo "  logs      Show logs (follow mode)"
    echo "  shell     Open shell in API container"
    echo "  exec      Execute command in API container"
    echo "  ps        List running containers"
    echo "  clean     Stop and remove all containers, volumes"
    echo "  test      Run tests in container"
    echo "  lint      Run linters in container"
    echo ""
}

# Check if docker and docker-compose are installed
check_requirements() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed${NC}"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}Error: docker-compose is not installed${NC}"
        exit 1
    fi
}

# Commands
case "$1" in
    up)
        echo -e "${GREEN}Starting Git2in services...${NC}"
        docker-compose up -d
        echo -e "${GREEN}Services started. API available at http://localhost:8000${NC}"
        docker-compose ps
        ;;
    
    down)
        echo -e "${YELLOW}Stopping Git2in services...${NC}"
        docker-compose down
        ;;
    
    restart)
        echo -e "${YELLOW}Restarting Git2in services...${NC}"
        docker-compose restart
        ;;
    
    build)
        echo -e "${GREEN}Building Docker images...${NC}"
        docker-compose build --no-cache
        ;;
    
    logs)
        service="${2:-}"
        if [ -z "$service" ]; then
            docker-compose logs -f --tail=100
        else
            docker-compose logs -f --tail=100 "$service"
        fi
        ;;
    
    shell)
        echo -e "${GREEN}Opening shell in git2in-api container...${NC}"
        docker-compose exec git2in-api /bin/bash
        ;;
    
    exec)
        shift
        docker-compose exec git2in-api "$@"
        ;;
    
    ps)
        docker-compose ps
        ;;
    
    clean)
        echo -e "${RED}Warning: This will remove all containers and volumes!${NC}"
        read -p "Are you sure? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker-compose down -v --remove-orphans
            echo -e "${GREEN}Cleanup complete${NC}"
        fi
        ;;
    
    test)
        echo -e "${GREEN}Running tests...${NC}"
        docker-compose exec git2in-api pytest tests/ -v
        ;;
    
    lint)
        echo -e "${GREEN}Running linters...${NC}"
        docker-compose exec git2in-api sh -c "black --check src/ && pylint src/"
        ;;
    
    *)
        print_help
        ;;
esac