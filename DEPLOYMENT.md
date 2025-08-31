# Lumina Export Automation - Complete Deployment Guide

## 📋 Table of Contents
1. [System Architecture](#system-architecture)
2. [Prerequisites](#prerequisites)
3. [DigitalOcean Setup](#digitalocean-setup)
4. [Docker Deployment](#docker-deployment)
5. [Manual Installation](#manual-installation)
6. [Configuration](#configuration)
7. [Security Setup](#security-setup)
8. [Monitoring & Maintenance](#monitoring--maintenance)
9. [API Documentation](#api-documentation)

## 🏗️ System Architecture

```
┌─────────────────────┐     ┌─────────────────────┐
│   Web Dashboard     │────▶│    Nginx Proxy      │
│   (React/HTML)      │     │   (SSL/Load Bal)   │
└─────────────────────┘     └─────────────────────┘
                                     │
                                     ▼
┌─────────────────────┐     ┌─────────────────────┐
│   Express API       │────▶│     Redis Queue     │
│   (Node.js)         │     │   (Bull/Caching)    │
└─────────────────────┘     └─────────────────────┘
         │                           │
         ▼                           ▼
┌─────────────────────┐     ┌─────────────────────┐
│  Puppeteer Workers  │     │   PostgreSQL DB     │
│  (Headless Chrome)  │     │   (Metadata/Users)  │
└─────────────────────┘     └─────────────────────┘
         │
         ▼
┌─────────────────────┐     ┌─────────────────────┐
│  Cloudflare R2      │────▶│   Email Service     │
│  (File Storage)     │     │   (Notifications)   │
└─────────────────────┘     └─────────────────────┘
```

## 📦 Prerequisites

- DigitalOcean account
- Cloudflare account (for R2 storage)
- SMTP email service (Gmail, SendGrid, etc.)
- Domain name (optional but recommended)
- Basic Linux/Docker knowledge

## 🚀 DigitalOcean Setup

### 1. Create Droplet

```bash
# Recommended Specifications
- Type: CPU-Optimized
- Size: 4 vCPU / 8GB RAM
- OS: Ubuntu 22.04 LTS
- Region: Choose closest to users
- Additional Storage: 100GB Block Storage
```

### 2. Initial Server Setup

```bash
# Connect to your droplet
ssh root@your-droplet-ip

# Update system
apt update && apt upgrade -y

# Create non-root user
adduser lumina
usermod -aG sudo lumina

# Setup firewall
ufw allow OpenSSH
ufw allow 80
ufw allow 443
ufw enable

# Install essential packages
apt install -y curl git vim htop nginx certbot python3-certbot-nginx
```

## 🐳 Docker Deployment (Recommended)

### 1. Docker Compose Configuration

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    container_name: lumina-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
      - ./frontend:/usr/share/nginx/html
    depends_on:
      - api
    restart: always

  api:
    build: ./backend
    container_name: lumina-api
    environment:
      NODE_ENV: production
      PORT: 3000
      REDIS_HOST: redis
      REDIS_PORT: 6379
      POSTGRES_HOST: postgres
      POSTGRES_PORT: 5432
      POSTGRES_DB: lumina
      POSTGRES_USER: lumina
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      JWT_SECRET: ${JWT_SECRET}
      ENCRYPTION_KEY: ${ENCRYPTION_KEY}
      SMTP_HOST: ${SMTP_HOST}
      SMTP_PORT: ${SMTP_PORT}
      SMTP_USER: ${SMTP_USER}
      SMTP_PASS: ${SMTP_PASS}
      R2_ENDPOINT: ${R2_ENDPOINT}
      R2_ACCESS_KEY: ${R2_ACCESS_KEY}
      R2_SECRET_KEY: ${R2_SECRET_KEY}
      R2_BUCKET: ${R2_BUCKET}
    volumes:
      - ./temp:/app/temp
      - ./logs:/app/logs
    depends_on:
      - redis
      - postgres
    restart: always

  redis:
    image: redis:7-alpine
    container_name: lumina-redis
    volumes:
      - redis-data:/data
    restart: always

  postgres:
    image: postgres:15-alpine
    container_name: lumina-postgres
    environment:
      POSTGRES_DB: lumina
      POSTGRES_USER: lumina
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    restart: always

  chrome:
    image: browserless/chrome:latest
    container_name: lumina-chrome
    environment:
      CONNECTION_TIMEOUT: 60000
      MAX_CONCURRENT_SESSIONS: 3
      ENABLE_CORS: true
      TOKEN: ${BROWSERLESS_TOKEN}
    ports:
      - "3001:3000"
    restart: always

volumes:
  redis-data:
  postgres-data:
```

### 2. Dockerfile for API

Create `backend/Dockerfile`:

```dockerfile
FROM node:20-slim

# Install Chrome dependencies
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    ca-certificates \
    fonts-liberation \
    libappindicator3-1 \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Chrome
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p temp logs data

# Run as non-root user
RUN groupadd -r lumina && useradd -r -g lumina lumina
RUN chown -R lumina:lumina /app
USER lumina

EXPOSE 3000

CMD ["node", "server.js"]
```

### 3. Environment Variables

Create `.env` file:

```bash
# Database
POSTGRES_PASSWORD=your-secure-postgres-password

# Security
JWT_SECRET=your-super-secret-jwt-key-min-32-chars
ENCRYPTION_KEY=your-256-bit-encryption-key-in-hex

# Email (Gmail example)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-specific-password

# Cloudflare R2
R2_ENDPOINT=https://your-account-id.r2.cloudflarestorage.com
R2_ACCESS_KEY=your-r2-access-key
R2_SECRET_KEY=your-r2-secret-key
R2_BUCKET=lumina-exports

# Browserless
BROWSERLESS_TOKEN=your-secure-token
```

### 4. Deploy with Docker

```bash
# Clone repository
git clone https://github.com/your-repo/lumina-export.git
cd lumina-export

# Create environment file
cp .env.example .env
# Edit .env with your values

# Build and start containers
docker-compose up -d

# Check logs
docker-compose logs -f

# Scale workers if needed
docker-compose up -d --scale chrome=3
```

## 🔧 Manual Installation

If you prefer manual installation without Docker:

### 1. Install Dependencies

```bash
# Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# PostgreSQL
sudo apt install postgresql postgresql-contrib

# Redis
sudo apt install redis-server

# PM2
sudo npm install -g pm2

# Chrome
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
sudo sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list'
sudo apt update
sudo apt install google-chrome-stable
```

### 2. Setup Application

```bash
# Clone and setup
cd /opt
sudo git clone https://github.com/your-repo/lumina-export.git
cd lumina-export
sudo npm install

# Create directories
sudo mkdir -p temp logs data
sudo chown -R www-data:www-data /opt/lumina-export

# Setup PM2
sudo pm2 start ecosystem.config.js
sudo pm2 save
sudo pm2 startup
```

### 3. Nginx Configuration

Create `/etc/nginx/sites-available/lumina`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Frontend
    location / {
        root /opt/lumina-export/frontend;
        try_files $uri /index.html;
    }

    # API
    location /api {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts for long-running exports
        proxy_connect_timeout 600;
        proxy_send_timeout 600;
        proxy_read_timeout 600;
    }
}
```

## ⚙️ Configuration

### PM2 Configuration

Create `ecosystem.config.js`:

```javascript
module.exports = {
  apps: [{
    name: 'lumina-api',
    script: './backend/server.js',
    instances: 1,
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    error_file: './logs/error.log',
    out_file: './logs/out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
    max_memory_restart: '2G',
    autorestart: true,
    watch: false,
    max_restarts: 10,
    min_uptime: '10s'
  }]
};
```

### Database Schema

Create `init.sql`:

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Settings table
CREATE TABLE settings (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    settings JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Jobs table
CREATE TABLE jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    name VARCHAR(255),
    status VARCHAR(50),
    progress INTEGER DEFAULT 0,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    duration INTEGER,
    file_count INTEGER,
    download_url TEXT,
    error TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_jobs_user_id ON jobs(user_id);
CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_created_at ON jobs(created_at DESC);
```

## 🔒 Security Setup

### 1. SSL Certificate

```bash
# Using Let's Encrypt
sudo certbot --nginx -d your-domain.com
```

### 2. Firewall Rules

```bash
# Configure UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 3. Security Best Practices

```bash
# Fail2ban
sudo apt install fail2ban
sudo systemctl enable fail2ban

# Create jail.local
sudo nano /etc/fail2ban/jail.local
```

Add:
```ini
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime = 3600
```

## 📊 Monitoring & Maintenance

### 1. Health Check Script

Create `scripts/health-check.sh`:

```bash
#!/bin/bash

API_URL="http://localhost:3000/health"
SLACK_WEBHOOK="your-slack-webhook-url"

# Check API health
response=$(curl -s -o /dev/null -w "%{http_code}" $API_URL)

if [ $response -ne 200 ]; then
    # Send alert
    curl -X POST $SLACK_WEBHOOK \
        -H 'Content-Type: application/json' \
        -d '{"text":"⚠️ Lumina API is down! Status code: '$response'"}'
    
    # Restart service
    pm2 restart lumina-api
fi
```

### 2. Backup Script

Create `scripts/backup.sh`:

```bash
#!/bin/bash

BACKUP_DIR="/backups/lumina"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
pg_dump -U lumina lumina > $BACKUP_DIR/db_$DATE.sql

# Backup application data
tar -czf $BACKUP_DIR/data_$DATE.tar.gz /opt/lumina-export/data

# Upload to R2 (optional)
aws s3 cp $BACKUP_DIR/db_$DATE.sql s3://your-backup-bucket/
aws s3 cp $BACKUP_DIR/data_$DATE.tar.gz s3://your-backup-bucket/

# Clean old backups (keep last 7 days)
find $BACKUP_DIR -type f -mtime +7 -delete
```

### 3. Monitoring Dashboard

```bash
# Install Prometheus and Grafana
docker run -d -p 9090:9090 --name prometheus prom/prometheus
docker run -d -p 3002:3000 --name grafana grafana/grafana

# Configure PM2 metrics
pm2 install pm2-metrics
```

## 📚 API Documentation

### Authentication Endpoints

```http
POST /api/auth/send-code
Content-Type: application/json

{
  "email": "user@example.com"
}
```

```http
POST /api/auth/verify
Content-Type: application/json

{
  "email": "user@example.com",
  "code": "123456"
}
```

### Job Management

```http
POST /api/jobs/create
Authorization: Bearer {token}
Content-Type: application/json

{
  "reportUrls": [
    "https://townsquarelumina.com/lumina/view/reports/max?reportType=addressableDisplay"
  ],
  "reportType": "addressableDisplay"
}
```

```http
GET /api/jobs
Authorization: Bearer {token}

GET /api/jobs/{jobId}
Authorization: Bearer {token}

POST /api/jobs/{jobId}/retry
Authorization: Bearer {token}

DELETE /api/jobs/{jobId}
Authorization: Bearer {token}
```

### Settings Management

```http
GET /api/settings
Authorization: Bearer {token}

POST /api/settings
Authorization: Bearer {token}
Content-Type: application/json

{
  "luminaCredentials": {
    "username": "user@company.com",
    "password": "password"
  },
  "reportTypes": [...],
  "notifications": {...},
  "schedule": {...}
}
```

## 🚦 Performance Optimization

### 1. Redis Configuration

Edit `/etc/redis/redis.conf`:

```conf
maxmemory 2gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

### 2. PostgreSQL Tuning

Edit `/etc/postgresql/15/main/postgresql.conf`:

```conf
shared_buffers = 2GB
effective_cache_size = 6GB
maintenance_work_mem = 512MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 10MB
min_wal_size = 1GB
max_wal_size = 4GB
```

### 3. System Limits

Edit `/etc/security/limits.conf`:

```conf
* soft nofile 65535
* hard nofile 65535
* soft nproc 32768
* hard nproc 32768
```

## 🎯 Quick Start Commands

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop services
docker-compose down

# Restart specific service
docker-compose restart api

# Scale workers
docker-compose up -d --scale chrome=5

# Backup database
docker exec lumina-postgres pg_dump -U lumina lumina > backup.sql

# Clear cache
docker exec lumina-api npm run cache:clear

# Run health check
curl http://localhost:3000/health
```

## 📞 Support & Troubleshooting

### Common Issues

1. **Chrome crashes**: Increase shared memory
   ```bash
   docker run --shm-size=2g ...
   ```

2. **Redis connection refused**: Check Redis is running
   ```bash
   sudo systemctl status redis
   ```

3. **Nginx 502 Bad Gateway**: Check API is running
   ```bash
   pm2 status
   pm2 logs lumina-api
   ```

4. **Job stuck in queue**: Check Redis and restart queue
   ```bash
   redis-cli FLUSHDB
   pm2 restart lumina-api
   ```

## 📈 Scaling Considerations

- **Horizontal Scaling**: Add more droplets behind a load balancer
- **Vertical Scaling**: Upgrade to larger droplet (8 vCPU / 16GB RAM)
- **Database Scaling**: Use managed PostgreSQL with read replicas
- **Storage Scaling**: Implement S3-compatible object storage
- **Queue Scaling**: Use Redis Cluster for high availability

## 🔄 Updates & Maintenance

```bash
# Update application
cd /opt/lumina-export
git pull origin main
npm install
pm2 restart lumina-api

# Update system packages
apt update && apt upgrade -y

# Update Docker images
docker-compose pull
docker-compose up -d

# Check for security updates
apt list --upgradable
```

## 📝 License & Credits

This system is designed for automating Lumina CSV exports with enterprise-grade reliability and security.

---

**Version**: 2.0.0  
**Last Updated**: January 2025  
**Maintained By**: Your DevOps Team
