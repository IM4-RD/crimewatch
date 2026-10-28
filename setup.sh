#!/bin/bash
# CrimeWatch — Quick Setup & Deployment Script
# Usage: bash setup.sh [dev|prod]

set -e

MODE=${1:-dev}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "════════════════════════════════════════════════════════════════"
echo "🛡️  CrimeWatch — Setup & Deployment"
echo "════════════════════════════════════════════════════════════════"
echo "Mode: $MODE"
echo ""

# ── COLORS ───────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}ℹ${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠${NC} $1"; }
error()   { echo -e "${RED}✗${NC} $1"; }

# ── REQUIREMENTS CHECK ───────────────────────────────────────────
info "Checking requirements…"

if ! command -v docker &> /dev/null; then
    error "Docker not found. Install from https://docker.com"
    exit 1
fi
success "Docker installed: $(docker --version)"

if ! command -v docker-compose &> /dev/null; then
    error "Docker Compose not found"
    exit 1
fi
success "Docker Compose installed: $(docker-compose --version)"

# ── CREATE .env ──────────────────────────────────────────────────
if [ "$MODE" = "dev" ]; then
    ENV_FILE="$SCRIPT_DIR/.env"
    ENV_TEMPLATE="$SCRIPT_DIR/backend/.env.example"
else
    ENV_FILE="$SCRIPT_DIR/.env.production"
    ENV_TEMPLATE="$SCRIPT_DIR/.env.production"
fi

if [ ! -f "$ENV_FILE" ]; then
    info "Creating $ENV_FILE…"
    cp "$ENV_TEMPLATE" "$ENV_FILE"
    
    # Generate random secret
    if command -v python3 &> /dev/null; then
        SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
        sed -i "s/change_me_generate_with_python/$SECRET/" "$ENV_FILE"
        success "Generated random SECRET_KEY"
    fi
    
    warn "Please edit $ENV_FILE with your settings:"
    warn "  - DB_PASS (MySQL password)"
    warn "  - MYSQL_ROOT_PASSWORD"
    warn "  - ALLOWED_ORIGINS (for CORS)"
fi

# ── BUILD IMAGES ────────────────────────────────────────────────
info "Building Docker images…"
if [ "$MODE" = "dev" ]; then
    docker-compose build --no-cache
else
    docker-compose -f docker-compose.yml build
fi
success "Docker images built"

# ── NETWORK ─────────────────────────────────────────────────────
info "Creating Docker network…"
docker network create crimewatch_net 2>/dev/null || true
success "Network ready"

# ── START SERVICES ──────────────────────────────────────────────
info "Starting services…"
if [ "$MODE" = "dev" ]; then
    docker-compose up -d
    sleep 5
else
    docker-compose -f docker-compose.yml up -d
    sleep 10
fi
success "Services started"

# ── WAIT FOR MYSQL ──────────────────────────────────────────────
info "Waiting for MySQL…"
for i in {1..30}; do
    if docker exec crimewatch-mysql mysqladmin ping -h localhost >/dev/null 2>&1; then
        success "MySQL is ready"
        break
    fi
    echo -n "."
    sleep 1
done

# ── INIT DATABASE ────────────────────────────────────────────────
info "Initializing database…"
docker exec crimewatch-mysql mysql -u root -p$(grep MYSQL_ROOT_PASSWORD $ENV_FILE | cut -d= -f2) -e "USE crimewatch; SELECT COUNT(*) FROM users;" >/dev/null 2>&1 && success "Database initialized" || warn "Database initialization may need manual verification"

# ── WAIT FOR API ─────────────────────────────────────────────────
info "Waiting for API…"
for i in {1..30}; do
    if curl -f http://localhost:8000/api/health >/dev/null 2>&1; then
        success "API is ready"
        break
    fi
    echo -n "."
    sleep 1
done

# ── GENERATE RSA KEYS ────────────────────────────────────────────
info "Checking RSA keys…"
if [ ! -f "$SCRIPT_DIR/backend/keys/private.pem" ]; then
    info "Generating RSA key pair for E2E encryption…"
    docker exec crimewatch-api python3 << 'PYEOF'
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key_dir = '/app/keys'
os.makedirs(key_dir, exist_ok=True)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

with open(f'{key_dir}/private.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

with open(f'{key_dir}/public.pem', 'wb') as f:
    f.write(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print('RSA keys generated')
PYEOF
    success "RSA keys generated"
else
    success "RSA keys already exist"
fi

# ── HEALTH CHECK ────────────────────────────────────────────────
info "Running health checks…"
HEALTH=$(curl -s http://localhost:8000/api/health)
if echo "$HEALTH" | grep -q '"status":"ok"'; then
    success "API health check passed"
    echo "  $HEALTH" | python3 -m json.tool 2>/dev/null || echo "  $HEALTH"
else
    warn "API health check returned: $HEALTH"
fi

# ── SUMMARY ──────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✓ CrimeWatch is running!"
echo "════════════════════════════════════════════════════════════════"
echo ""

if [ "$MODE" = "dev" ]; then
    echo -e "${GREEN}Development mode${NC}"
    echo "  Frontend:  http://localhost"
    echo "  API:       http://localhost:8000"
    echo "  API Docs:  http://localhost:8000/api/docs"
    echo "  MySQL:     localhost:3306"
    echo ""
    echo "Test accounts:"
    echo "  public@crimewatch.ke   / public123"
    echo "  officer@crimewatch.ke  / officer123"
    echo "  admin@crimewatch.ke    / admin123"
    echo ""
    echo "Useful commands:"
    echo "  docker-compose logs -f backend        # Watch API logs"
    echo "  docker-compose down                   # Stop all services"
    echo "  docker-compose up -d                  # Start all services"
else
    echo -e "${GREEN}Production mode${NC}"
    echo "  Configure NGINX with SSL certificates"
    echo "  Update firewall rules"
    echo "  Set up backups for MySQL and media storage"
    echo "  Monitor logs in docker-compose"
fi

echo ""
echo "Documentation: see README.md"
echo ""
