#!/bin/bash
# =============================================================================
# GitHub Security Scanner - Setup Script
# Configures local development environment
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_deps=()
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        missing_deps+=("docker-compose")
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # Check Node.js (optional for frontend development)
    if ! command -v node &> /dev/null; then
        log_warning "Node.js not found. Required for frontend development."
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_error "Please install them and run this script again."
        exit 1
    fi
    
    log_success "All prerequisites satisfied!"
}

# Create environment file
create_env_file() {
    log_info "Creating environment file..."
    
    if [ -f ".env" ]; then
        log_warning ".env file already exists. Backing up to .env.backup"
        cp .env .env.backup
    fi
    
    # Generate secure passwords
    DB_PASSWORD=$(openssl rand -hex 16)
    SECRET_KEY=$(openssl rand -hex 32)
    
    cat > .env << EOF
# =============================================================================
# GitHub Security Scanner - Environment Configuration
# Generated on $(date)
# =============================================================================

# Database
POSTGRES_USER=gss
POSTGRES_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=gss_db

# Redis
REDIS_URL=redis://redis:6379/0

# Application
GSS_SECRET_KEY=${SECRET_KEY}
GSS_AUTH_ENABLED=true
GSS_ADMIN_USER=admin
GSS_ADMIN_PASS=admin

# GitHub (Add your token here)
GITHUB_TOKEN=

# Logging
LOG_LEVEL=INFO

# CORS
GSS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173,http://localhost:80

# Worker settings
WORKER_CONCURRENCY=4
WORKER_REPLICAS=2
SCAN_TIMEOUT=3600

# Monitoring (optional)
GRAFANA_USER=admin
GRAFANA_PASSWORD=admin
EOF

    log_success "Environment file created: .env"
    log_warning "Remember to add your GITHUB_TOKEN to .env"
}

# Build Docker images
build_images() {
    log_info "Building Docker images..."
    
    docker compose build --no-cache
    
    log_success "Docker images built successfully!"
}

# Start services
start_services() {
    log_info "Starting services..."
    
    docker compose up -d
    
    log_info "Waiting for services to be healthy..."
    sleep 10
    
    # Check health
    if curl -sf http://localhost:8000/api/health > /dev/null; then
        log_success "API is healthy!"
    else
        log_warning "API health check failed. Check logs with: docker compose logs api"
    fi
    
    log_success "Services started!"
}

# Run database migrations
run_migrations() {
    log_info "Running database setup..."
    
    # Wait for database to be ready
    docker compose exec -T postgres pg_isready -U gss -d gss_db
    
    # The init-db.sql will run automatically on first start
    log_success "Database setup complete!"
}

# Install Python dependencies for local development
setup_python_dev() {
    log_info "Setting up Python development environment..."
    
    python3 -m venv .venv 2>/dev/null || true
    source .venv/bin/activate 2>/dev/null || true
    
    pip install -e ".[dev]"
    
    log_success "Python development environment ready!"
}

# Setup frontend for development
setup_frontend() {
    log_info "Setting up frontend..."
    
    if [ -d "frontend" ]; then
        cd frontend
        npm install
        cd ..
        log_success "Frontend dependencies installed!"
    else
        log_warning "Frontend directory not found"
    fi
}

# Main setup
main() {
    echo ""
    echo "========================================"
    echo "  GitHub Security Scanner Setup"
    echo "========================================"
    echo ""
    
    check_prerequisites
    create_env_file
    
    read -p "Do you want to build Docker images now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        build_images
    fi
    
    read -p "Do you want to start the services? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        start_services
    fi
    
    read -p "Do you want to setup Python dev environment? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        setup_python_dev
    fi
    
    read -p "Do you want to setup frontend? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        setup_frontend
    fi
    
    echo ""
    echo "========================================"
    echo "  Setup Complete!"
    echo "========================================"
    echo ""
    echo "Next steps:"
    echo "  1. Add your GITHUB_TOKEN to .env"
    echo "  2. Start services: docker compose up -d"
    echo "  3. Access the dashboard: http://localhost"
    echo "  4. API documentation: http://localhost:8000/docs"
    echo ""
    echo "Useful commands:"
    echo "  docker compose logs -f          # View logs"
    echo "  docker compose ps               # Check status"
    echo "  docker compose down             # Stop services"
    echo "  docker compose up --scale worker=4  # Scale workers"
    echo ""
}

# Run main function
main "$@"
