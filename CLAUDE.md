# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Development
- `node backend/server.js` - Start the Express API server (port 3000)
- `npm start` - Alias for starting the server
- `npm install` - Install dependencies (Bull, Express, Puppeteer, etc.)

### Production (PM2)
- `pm2 start backend/server.js --name lumina-api` - Start in production mode
- `pm2 stop lumina-api` - Stop the application
- `pm2 restart lumina-api` - Restart the application
- `pm2 logs lumina-api` - View application logs

### Queue Management
- Redis must be running for the Bull queue system to work
- Queue stats available at `/health` endpoint
- Clear cache via API: `POST /api/cache/clear`

### Docker (from DEPLOYMENT.md)
- `docker-compose up -d` - Start all services
- `docker-compose logs -f api` - View API logs
- `docker-compose restart api` - Restart API service

## Architecture

This is a **Lumina CSV Export Automation System** with the following key components:

### Backend (`backend/server.js`)
- **Express API** - RESTful API for dashboard operations
- **Bull Queue System** - Redis-based job queue for async export processing
- **Puppeteer Scraper** - Headless Chrome automation for Lumina platform interaction
- **Email Service** - Nodemailer for authentication codes and notifications
- **Encryption Service** - AES-256-GCM for credential protection
- **Storage Service** - AWS S3-compatible (Cloudflare R2) file storage
- **JSON File Database** - Simple file-based storage (production uses PostgreSQL)

### Frontend (`frontend/index.html`)
- **Single HTML file** with React components loaded via CDN
- **Real-time dashboard** for job monitoring and management
- **Settings interface** for Lumina credentials and export configuration

### Data Flow
1. User authenticates via email verification codes
2. Configures Lumina credentials (encrypted) and export settings
3. Creates export jobs for specific report types
4. Bull queue processes jobs using Puppeteer
5. Files are scraped from Lumina tables, compressed, and uploaded to R2
6. Users receive email notifications and download links

### Key Services Integration
- **Lumina Platform**: Target system for data scraping (townsquarelumina.com)
- **Redis**: Queue management and caching
- **Cloudflare R2**: File storage with presigned URLs
- **SMTP**: Email notifications and authentication

### Report Types Supported
- `addressableDisplay` - Addressable display advertising reports
- `callPerformance` - Call tracking performance data
- `retargeting` - Retargeting campaign metrics  
- `searchMarketing` - Search marketing analytics

### Configuration
Environment variables required:
- `REDIS_HOST`, `REDIS_PORT` - Queue backend
- `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS` - Email service
- `R2_ENDPOINT`, `R2_ACCESS_KEY`, `R2_SECRET_KEY`, `R2_BUCKET` - Storage
- `JWT_SECRET`, `ENCRYPTION_KEY` - Security keys

### File Structure
- `/backend/server.js` - Main application logic (30K+ lines)
- `/frontend/index.html` - React dashboard UI
- `/data/` - JSON database files (users, settings, jobs)
- `/temp/` - Temporary download directory
- `/logs/` - Application logs
- `DEPLOYMENT.md` - Comprehensive production deployment guide

## Development Notes

### Scraping Implementation
The Puppeteer scraper targets Material-UI DataGrid tables using:
- `.MuiDataGrid-root` selectors for table detection
- `button[aria-label="more"]` for export menu access
- Dynamic waiting for `Download CSV` menu items
- Automated file downloads and compression

### Security Features
- Email-based passwordless authentication
- JWT tokens for session management
- AES-256-GCM credential encryption
- Rate limiting and helmet.js protection
- Secure file handling and cleanup

### Queue System
- Exponential backoff retry strategy
- Configurable concurrency limits
- Progress tracking and real-time updates
- Automatic cleanup of temp files
- Email notifications on completion/failure

### Database Schema (Production)
Uses PostgreSQL with tables for:
- `users` - Authentication and user management
- `settings` - Per-user configuration (encrypted credentials)
- `jobs` - Export job history and metadata

The current implementation uses JSON files for simplicity but is designed to migrate to PostgreSQL for production deployment.