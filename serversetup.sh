#!/bin/bash

# ========================================
# NuboLink API - Automated Server Setup
# ========================================
# 
# This script automatically configures a fresh Ubuntu/Debian server
# with everything needed to run NuboLink API in production
#
# Usage: 
#   curl -sSL https://raw.githubusercontent.com/Lagunasporte/nuboprotect/main/setupserver.sh | bash
#   or
#   wget -qO- https://raw.githubusercontent.com/Lagunasporte/nuboprotect/setupserver.sh | bash
#
# Requirements:
# - Fresh Ubuntu 20.04+ or Debian 11+ server
# - Root access or sudo privileges
# - Domain name pointing to your server IP (for SSL)
#
# ========================================

set -euo pipefail

# Configuration variables
REPO_URL="https://github.com/Lagunasporte/nuboprotect.git"
PROJECT_DIR="/opt/nubolink-api"
SERVICE_USER="nubolink"
DOMAIN=""
EMAIL=""
NODE_VERSION="18"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

log_step() {
    echo -e "\n${PURPLE}🔧 $1${NC}"
    echo "$(printf '=%.0s' {1..60})"
}

# Error handler
error_exit() {
    log_error "Error on line $1"
    log_error "Setup failed! Check the logs above for details."
    exit 1
}

trap 'error_exit $LINENO' ERR

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root. This is acceptable for initial setup."
    else
        log_error "This script requires sudo privileges."
        exit 1
    fi
}

# Get user input for configuration
get_configuration() {
    log_step "Configuration Setup"
    
    echo -e "${CYAN}Please provide the following information:${NC}"
    echo ""
    
    # Domain name
    read -p "🌐 Domain name (e.g., api.nubolink.com): " DOMAIN
    while [[ -z "$DOMAIN" ]]; do
        log_warning "Domain name is required for SSL certificate"
        read -p "🌐 Domain name: " DOMAIN
    done
    
    # Email for Let's Encrypt
    read -p "📧 Email for SSL certificate (Let's Encrypt): " EMAIL
    while [[ -z "$EMAIL" ]]; do
        log_warning "Email is required for SSL certificate"
        read -p "📧 Email: " EMAIL
    done
    
    # GitHub repository (optional custom)
    read -p "📦 GitHub repository URL [$REPO_URL]: " CUSTOM_REPO
    if [[ -n "$CUSTOM_REPO" ]]; then
        REPO_URL="$CUSTOM_REPO"
    fi
    
    echo ""
    log_info "Configuration:"
    log_info "Domain: $DOMAIN"
    log_info "Email: $EMAIL"
    log_info "Repository: $REPO_URL"
    log_info "Project Directory: $PROJECT_DIR"
    echo ""
    
    read -p "Continue with this configuration? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Setup cancelled by user"
        exit 0
    fi
}

# System update and basic packages
update_system() {
    log_step "Updating System Packages"
    
    apt-get update -y
    apt-get upgrade -y
    
    # Install essential packages
    apt-get install -y \
        curl \
        wget \
        git \
        unzip \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        ufw \
        fail2ban \
        htop \
        nano \
        vim \
        tree \
        jq \
        sqlite3
    
    log_success "System packages updated"
}

# Install Node.js
install_nodejs() {
    log_step "Installing Node.js $NODE_VERSION"
    
    # Add NodeSource repository
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -
    
    # Install Node.js
    apt-get install -y nodejs
    
    # Verify installation
    NODE_VER=$(node --version)
    NPM_VER=$(npm --version)
    
    log_success "Node.js $NODE_VER installed"
    log_success "npm $NPM_VER installed"
    
    # Install global packages
    npm install -g pm2 @nestjs/cli nodemon
    
    log_success "Global npm packages installed"
}

# Install and configure Nginx
install_nginx() {
    log_step "Installing and Configuring Nginx"
    
    apt-get install -y nginx
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default
    
    # Create Nginx configuration for NuboLink API
    cat > /etc/nginx/sites-available/nubolink-api << EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    # Redirect HTTP to HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    # SSL Configuration (will be configured by Certbot)
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    # Proxy settings
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_cache_bypass \$http_upgrade;
    
    # API routes
    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_read_timeout 60s;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
    }
    
    # Health check endpoint (bypass rate limiting)
    location /health {
        proxy_pass http://127.0.0.1:3001;
        access_log off;
    }
    
    # Static files cache
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        proxy_pass http://127.0.0.1:3001;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Security.txt
    location /.well-known/security.txt {
        return 301 https://github.com/yourusername/nubolink-api/security;
    }
    
    # Deny access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ \.(env|log|sqlite|db)$ {
        deny all;
    }
}
EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/nubolink-api /etc/nginx/sites-enabled/
    
    # Test Nginx configuration
    nginx -t
    
    log_success "Nginx configured for $DOMAIN"
}

# Install SSL certificate with Let's Encrypt
install_ssl() {
    log_step "Installing SSL Certificate"
    
    # Install Certbot
    apt-get install -y certbot python3-certbot-nginx
    
    # Temporarily start Nginx without SSL for domain verification
    sed -i 's/listen 443 ssl/listen 443/g' /etc/nginx/sites-available/nubolink-api
    sed -i '/ssl_certificate/d' /etc/nginx/sites-available/nubolink-api
    systemctl reload nginx
    
    # Obtain SSL certificate
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email $EMAIL --redirect
    
    # Restore SSL configuration
    cat > /etc/nginx/sites-available/nubolink-api << EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    # Include SSL configuration from Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_cache_bypass \$http_upgrade;
    
    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_read_timeout 60s;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
    }
    
    location /health {
        proxy_pass http://127.0.0.1:3001;
        access_log off;
    }
    
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        proxy_pass http://127.0.0.1:3001;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    location ~ /\. {
        deny all;
    }
    
    location ~ \.(env|log|sqlite|db)$ {
        deny all;
    }
}
EOF
    
    # Reload Nginx
    systemctl reload nginx
    
    # Setup auto-renewal
    crontab -l | { cat; echo "0 12 * * * /usr/bin/certbot renew --quiet"; } | crontab -
    
    log_success "SSL certificate installed for $DOMAIN"
}

# Create service user
create_service_user() {
    log_step "Creating Service User"
    
    # Create user if doesn't exist
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd --system --shell /bin/bash --home $PROJECT_DIR --create-home $SERVICE_USER
        log_success "Created user: $SERVICE_USER"
    else
        log_info "User $SERVICE_USER already exists"
    fi
    
    # Add to necessary groups
    usermod -a -G www-data $SERVICE_USER
}

# Clone and setup project
setup_project() {
    log_step "Setting Up NuboLink API Project"
    
    # Clone repository
    if [[ -d "$PROJECT_DIR" ]]; then
        log_info "Project directory exists, updating..."
        cd $PROJECT_DIR
        sudo -u $SERVICE_USER git pull origin main
    else
        log_info "Cloning repository..."
        sudo -u $SERVICE_USER git clone $REPO_URL $PROJECT_DIR
        cd $PROJECT_DIR
    fi
    
    # Set ownership
    chown -R $SERVICE_USER:$SERVICE_USER $PROJECT_DIR
    
    # Install npm dependencies
    log_info "Installing npm dependencies..."
    sudo -u $SERVICE_USER npm install --production
    
    log_success "Project setup completed"
}

# Configure environment
configure_environment() {
    log_step "Configuring Environment"
    
    cd $PROJECT_DIR
    
    # Create .env file if it doesn't exist
    if [[ ! -f .env ]]; then
        sudo -u $SERVICE_USER cp .env.example .env
        
        # Generate JWT secret
        JWT_SECRET=$(openssl rand -base64 64)
        
        # Update .env file with production values
        sudo -u $SERVICE_USER sed -i "s/NODE_ENV=development/NODE_ENV=production/" .env
        sudo -u $SERVICE_USER sed -i "s/PORT=3001/PORT=3001/" .env
        sudo -u $SERVICE_USER sed -i "s/change-this-super-secret-jwt-key-in-production/$JWT_SECRET/" .env
        
        log_success "Environment file configured"
    else
        log_info "Environment file already exists"
    fi
    
    # Create necessary directories
    sudo -u $SERVICE_USER mkdir -p logs database backups temp uploads
    
    # Set proper permissions
    chmod 755 $PROJECT_DIR
    chmod 644 $PROJECT_DIR/.env
    chmod -R 755 $PROJECT_DIR/logs
    chmod -R 755 $PROJECT_DIR/backups
}

# Setup PM2 process manager
setup_pm2() {
    log_step "Configuring PM2 Process Manager"
    
    cd $PROJECT_DIR
    
    # Create PM2 ecosystem file
    cat > ecosystem.config.js << EOF
module.exports = {
  apps: [{
    name: 'nubolink-api',
    script: 'server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3001
    },
    log_file: './logs/app.log',
    out_file: './logs/out.log',
    error_file: './logs/error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true,
    max_memory_restart: '1G',
    node_args: '--max_old_space_size=1024',
    watch: false,
    ignore_watch: ['node_modules', 'logs', 'backups'],
    min_uptime: '10s',
    max_restarts: 10,
    restart_delay: 4000
  }]
};
EOF
    
    chown $SERVICE_USER:$SERVICE_USER ecosystem.config.js
    
    # Setup PM2 startup script
    sudo -u $SERVICE_USER pm2 startup
    
    log_success "PM2 configured"
}

# Configure firewall
configure_firewall() {
    log_step "Configuring Firewall"
    
    # Reset UFW
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (be careful!)
    ufw allow ssh
    
    # Allow HTTP/HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow specific ports if needed
    # ufw allow 51820/udp  # WireGuard
    
    # Enable firewall
    ufw --force enable
    
    log_success "Firewall configured"
}

# Configure Fail2Ban
configure_fail2ban() {
    log_step "Configuring Fail2Ban"
    
    # Create custom jail for API
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[nginx-http-auth]
enabled = true

[nginx-noscript]
enabled = true

[nginx-badbots]
enabled = true

[nginx-noproxy]
enabled = true

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s

[nubolink-api]
enabled = true
port = http,https
filter = nubolink-api
logpath = $PROJECT_DIR/logs/app.log
maxretry = 10
EOF

    # Create filter for API
    cat > /etc/fail2ban/filter.d/nubolink-api.conf << EOF
[Definition]
failregex = ^.*\[ERROR\].*Auth.*failed.*<HOST>.*$
            ^.*\[ERROR\].*Invalid.*credentials.*<HOST>.*$
            ^.*\[ERROR\].*Too many.*requests.*<HOST>.*$
ignoreregex =
EOF
    
    # Restart Fail2Ban
    systemctl restart fail2ban
    
    log_success "Fail2Ban configured"
}

# Setup automated backups
setup_backups() {
    log_step "Setting Up Automated Backups"
    
    # Create backup script
    cat > /usr/local/bin/nubolink-backup.sh << 'EOF'
#!/bin/bash

PROJECT_DIR="/opt/nubolink-api"
BACKUP_DIR="$PROJECT_DIR/backups"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
cp "$PROJECT_DIR/database/nubolink.sqlite" "$BACKUP_DIR/nubolink_backup_$DATE.sqlite"

# Backup environment file
cp "$PROJECT_DIR/.env" "$BACKUP_DIR/env_backup_$DATE"

# Compress old backups
find $BACKUP_DIR -name "*.sqlite" -mtime +7 -exec gzip {} \;

# Remove old backups
find $BACKUP_DIR -name "*backup*" -mtime +$RETENTION_DAYS -delete

# Log
echo "[$(date)] Backup completed: $BACKUP_DIR/nubolink_backup_$DATE.sqlite"
EOF
    
    chmod +x /usr/local/bin/nubolink-backup.sh
    
    # Add to crontab for service user
    (sudo -u $SERVICE_USER crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/nubolink-backup.sh") | sudo -u $SERVICE_USER crontab -
    
    log_success "Automated backups configured (daily at 2 AM)"
}

# Initialize application
initialize_app() {
    log_step "Initializing Application"
    
    cd $PROJECT_DIR
    
    # Run setup script
    sudo -u $SERVICE_USER npm run setup
    
    log_success "Application initialized"
}

# Start services
start_services() {
    log_step "Starting Services"
    
    cd $PROJECT_DIR
    
    # Start application with PM2
    sudo -u $SERVICE_USER pm2 start ecosystem.config.js
    sudo -u $SERVICE_USER pm2 save
    
    # Start and enable services
    systemctl enable nginx
    systemctl restart nginx
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_success "All services started"
}

# Verify installation
verify_installation() {
    log_step "Verifying Installation"
    
    # Check services
    if systemctl is-active --quiet nginx; then
        log_success "Nginx is running"
    else
        log_error "Nginx is not running"
    fi
    
    if systemctl is-active --quiet fail2ban; then
        log_success "Fail2Ban is running"
    else
        log_warning "Fail2Ban is not running"
    fi
    
    # Check PM2
    if sudo -u $SERVICE_USER pm2 list | grep -q "nubolink-api"; then
        log_success "NuboLink API is running with PM2"
    else
        log_error "NuboLink API is not running"
    fi
    
    # Check SSL
    if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
        log_success "SSL certificate is installed"
    else
        log_warning "SSL certificate not found"
    fi
    
    # Test API endpoint
    sleep 5
    if curl -sf "https://$DOMAIN/health" > /dev/null; then
        log_success "API is responding to HTTPS requests"
    else
        log_warning "API health check failed"
    fi
}

# Display final information
show_completion_info() {
    log_step "Setup Complete!"
    
    echo ""
    log_success "NuboLink API has been successfully installed!"
    echo ""
    log_info "🌐 API URL: https://$DOMAIN"
    log_info "📊 Health Check: https://$DOMAIN/health"
    log_info "📚 API Documentation: https://$DOMAIN/api"
    echo ""
    log_info "🔐 Test User Credentials:"
    log_info "   Email: test@nubolink.com"
    log_info "   Password: TestPassword123!"
    echo ""
    log_info "📁 Project Directory: $PROJECT_DIR"
    log_info "👤 Service User: $SERVICE_USER"
    log_info "📝 Logs: $PROJECT_DIR/logs/"
    log_info "💾 Backups: $PROJECT_DIR/backups/"
    echo ""
    log_info "🔧 Management Commands:"
    log_info "   sudo -u $SERVICE_USER pm2 status"
    log_info "   sudo -u $SERVICE_USER pm2 logs"
    log_info "   sudo -u $SERVICE_USER pm2 restart nubolink-api"
    log_info "   sudo systemctl reload nginx"
    echo ""
    log_warning "🚨 Important:"
    log_warning "1. Change the test user password in production"
    log_warning "2. Configure your Mikrotik server details in $PROJECT_DIR/.env"
    log_warning "3. Review firewall rules if needed"
    log_warning "4. Monitor logs regularly"
    echo ""
    log_success "Happy VPN serving! 🚀"
}

# Main execution
main() {
    echo ""
    echo "🚀 NuboLink API - Automated Server Setup"
    echo "========================================"
    echo ""
    
    check_root
    get_configuration
    update_system
    install_nodejs
    install_nginx
    install_ssl
    create_service_user
    setup_project
    configure_environment
    setup_pm2
    configure_firewall
    configure_fail2ban
    setup_backups
    initialize_app
    start_services
    verify_installation
    show_completion_info
}

# Execute main function
main "$@"
