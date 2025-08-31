// server.js - Complete Backend API for Lumina Dashboard
const express = require('express');
const cors = require('cors');
const Bull = require('bull');
const Redis = require('ioredis');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const puppeteer = require('puppeteer');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const fs = require('fs-extra');
const path = require('path');
const archiver = require('archiver');
const { v4: uuid } = require('uuid');
const Papa = require('papaparse');
const AWS = require('aws-sdk');
const winston = require('winston');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');

// Initialize Express
const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());

// Configuration
const config = {
    port: process.env.PORT || 3000,
    redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
    },
    jwt: {
        secret: process.env.JWT_SECRET || 'your-super-secret-key-change-this',
        expiresIn: '24h'
    },
    email: {
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: process.env.SMTP_PORT || 587,
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
    r2: {
        endpoint: process.env.R2_ENDPOINT,
        accessKeyId: process.env.R2_ACCESS_KEY,
        secretAccessKey: process.env.R2_SECRET_KEY,
        bucket: process.env.R2_BUCKET || 'lumina-exports',
    },
    lumina: {
        baseUrl: 'https://townsquarelumina.com',
        loginUrl: 'https://townsquarelumina.com/login',
    },
    encryption: {
        algorithm: 'aes-256-gcm',
        key: process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
    }
};

// Logger Setup
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

// Database (using JSON file for simplicity - replace with PostgreSQL in production)
class Database {
    constructor() {
        this.dbPath = path.join(__dirname, 'data');
        this.usersFile = path.join(this.dbPath, 'users.json');
        this.settingsFile = path.join(this.dbPath, 'settings.json');
        this.jobsFile = path.join(this.dbPath, 'jobs.json');
        this.init();
    }

    init() {
        fs.ensureDirSync(this.dbPath);
        if (!fs.existsSync(this.usersFile)) {
            fs.writeJsonSync(this.usersFile, {});
        }
        if (!fs.existsSync(this.settingsFile)) {
            fs.writeJsonSync(this.settingsFile, {});
        }
        if (!fs.existsSync(this.jobsFile)) {
            fs.writeJsonSync(this.jobsFile, []);
        }
    }

    getUsers() {
        return fs.readJsonSync(this.usersFile);
    }

    saveUser(email, data) {
        const users = this.getUsers();
        users[email] = data;
        fs.writeJsonSync(this.usersFile, users);
    }

    getSettings(userId) {
        const settings = fs.readJsonSync(this.settingsFile);
        return settings[userId] || this.getDefaultSettings();
    }

    saveSettings(userId, settings) {
        const allSettings = fs.readJsonSync(this.settingsFile);
        allSettings[userId] = settings;
        fs.writeJsonSync(this.settingsFile, allSettings);
    }

    getDefaultSettings() {
        return {
            luminaCredentials: {
                username: '',
                password: ''
            },
            reportTypes: [
                { id: 1, name: 'addressableDisplay', enabled: true, tables: [] },
                { id: 2, name: 'callPerformance', enabled: true, tables: [] },
                { id: 3, name: 'retargeting', enabled: false, tables: [] },
                { id: 4, name: 'searchMarketing', enabled: true, tables: [] },
            ],
            fileHeaders: {
                includeTimestamp: true,
                includeMetadata: true,
                customPrefix: 'LUMINA_',
            },
            notifications: {
                emailEnabled: true,
                emailAddress: '',
                slackEnabled: false,
                slackWebhook: '',
                onSuccess: true,
                onFailure: true,
            },
            schedule: {
                enabled: false,
                frequency: 'daily',
                time: '09:00',
                timezone: 'America/New_York',
            },
            advanced: {
                maxRetries: 3,
                timeout: 60000,
                concurrency: 3,
                keepFiles: 7,
            }
        };
    }

    addJob(job) {
        const jobs = fs.readJsonSync(this.jobsFile);
        jobs.push(job);
        // Keep only last 1000 jobs
        if (jobs.length > 1000) {
            jobs.shift();
        }
        fs.writeJsonSync(this.jobsFile, jobs);
    }

    getJobs(userId, filters = {}) {
        const jobs = fs.readJsonSync(this.jobsFile);
        return jobs.filter(job => job.userId === userId);
    }
}

const db = new Database();

// Redis & Queue Setup
const redis = new Redis(config.redis);
const exportQueue = new Bull('export-queue', {
    redis: config.redis
});

// Email Service
class EmailService {
    constructor() {
        this.transporter = nodemailer.createTransport({
            host: config.email.host,
            port: config.email.port,
            secure: false,
            auth: {
                user: config.email.user,
                pass: config.email.pass,
            }
        });
        this.verificationCodes = new Map();
    }

    async sendVerificationCode(email) {
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        this.verificationCodes.set(email, {
            code,
            expires: Date.now() + 600000 // 10 minutes
        });

        await this.transporter.sendMail({
            from: '"Lumina Export Dashboard" <noreply@lumina-export.com>',
            to: email,
            subject: 'Your Verification Code',
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #6B46C1;">Lumina Export Dashboard</h2>
                    <p>Your verification code is:</p>
                    <h1 style="color: #6B46C1; font-size: 36px; letter-spacing: 5px;">${code}</h1>
                    <p>This code will expire in 10 minutes.</p>
                    <hr style="border: 1px solid #e5e5e5; margin: 20px 0;">
                    <p style="color: #666; font-size: 12px;">If you didn't request this code, please ignore this email.</p>
                </div>
            `
        });

        return code;
    }

    verifyCode(email, code) {
        const stored = this.verificationCodes.get(email);
        if (!stored) return false;
        if (Date.now() > stored.expires) {
            this.verificationCodes.delete(email);
            return false;
        }
        if (stored.code === code) {
            this.verificationCodes.delete(email);
            return true;
        }
        return false;
    }

    async sendJobNotification(email, job, status) {
        const subject = status === 'completed' 
            ? `✅ Export Job Completed: ${job.name}`
            : `❌ Export Job Failed: ${job.name}`;

        const html = `
            <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
                <h2 style="color: ${status === 'completed' ? '#10B981' : '#EF4444'};">
                    ${subject}
                </h2>
                <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0;">
                    <p><strong>Job ID:</strong> ${job.id}</p>
                    <p><strong>Started:</strong> ${new Date(job.startTime).toLocaleString()}</p>
                    <p><strong>Duration:</strong> ${job.duration}s</p>
                    ${status === 'completed' ? `
                        <p><strong>Files:</strong> ${job.fileCount}</p>
                        <p><strong>Download:</strong> <a href="${job.downloadUrl}">Click here to download</a></p>
                    ` : `
                        <p><strong>Error:</strong> ${job.error}</p>
                    `}
                </div>
            </div>
        `;

        await this.transporter.sendMail({
            from: '"Lumina Export Dashboard" <noreply@lumina-export.com>',
            to: email,
            subject,
            html
        });
    }
}

const emailService = new EmailService();

// Encryption Service
class EncryptionService {
    encrypt(text) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(
            config.encryption.algorithm,
            Buffer.from(config.encryption.key, 'hex'),
            iv
        );
        
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag();
        
        return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
    }

    decrypt(text) {
        const parts = text.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const encrypted = parts[2];
        
        const decipher = crypto.createDecipheriv(
            config.encryption.algorithm,
            Buffer.from(config.encryption.key, 'hex'),
            iv
        );
        
        decipher.setAuthTag(authTag);
        
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    }
}

const encryptionService = new EncryptionService();

// Lumina Scraper Service
class LuminaScraper {
    constructor() {
        this.browser = null;
    }

    async init() {
        this.browser = await puppeteer.launch({
            headless: 'new',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--window-size=1920,1080'
            ]
        });
    }

    async authenticate(credentials) {
        const page = await this.browser.newPage();
        
        try {
            await page.goto(config.lumina.loginUrl, { waitUntil: 'networkidle2' });
            
            await page.type('#username', credentials.username);
            await page.type('#password', credentials.password);
            await page.click('#login-button');
            
            await page.waitForNavigation({ waitUntil: 'networkidle2' });
            
            const cookies = await page.cookies();
            const jwt = await page.evaluate(() => {
                return localStorage.getItem('jwt') || sessionStorage.getItem('jwt');
            });
            
            await page.close();
            
            return { cookies, jwt, success: true };
        } catch (error) {
            logger.error('Authentication failed:', error);
            await page.close();
            return { success: false, error: error.message };
        }
    }

    async scrapeReport(reportUrl, session, downloadPath) {
        const page = await this.browser.newPage();
        
        await page.setCookie(...session.cookies);
        
        // Set download behavior
        await page._client.send('Page.setDownloadBehavior', {
            behavior: 'allow',
            downloadPath: downloadPath
        });
        
        try {
            await page.goto(reportUrl, { waitUntil: 'networkidle2', timeout: 60000 });
            
            // Wait for tables to load
            await page.waitForSelector('.MuiDataGrid-root', { timeout: 30000 });
            
            // Execute the table detection and export logic
            const result = await page.evaluate(() => {
                const tables = [];
                const moreButtons = document.querySelectorAll('button[aria-label="more"]');
                
                moreButtons.forEach((button, index) => {
                    const container = button.closest('[class*="card"]');
                    const titleEl = container?.querySelector('p, h1, h2, h3');
                    const title = titleEl?.textContent?.trim() || `Table ${index + 1}`;
                    
                    if (!['unknown table', 'table 1', 'table 2'].includes(title.toLowerCase())) {
                        // Click the button to open menu
                        button.click();
                        
                        // Wait a moment for menu to appear
                        setTimeout(() => {
                            const menuItems = document.querySelectorAll('[role="menuitem"]');
                            const downloadItem = Array.from(menuItems).find(item => 
                                item.textContent.includes('Download CSV')
                            );
                            if (downloadItem) {
                                downloadItem.click();
                                tables.push({ title, success: true });
                            }
                        }, 500);
                    }
                });
                
                return tables;
            });
            
            // Wait for downloads to complete
            await page.waitForTimeout(5000);
            await page.close();
            
            return { success: true, tables: result };
        } catch (error) {
            logger.error('Scraping failed:', error);
            await page.close();
            return { success: false, error: error.message };
        }
    }

    async cleanup() {
        if (this.browser) {
            await this.browser.close();
        }
    }
}

// Storage Service
class StorageService {
    constructor() {
        this.s3 = new AWS.S3({
            endpoint: config.r2.endpoint,
            accessKeyId: config.r2.accessKeyId,
            secretAccessKey: config.r2.secretAccessKey,
            s3ForcePathStyle: true,
            signatureVersion: 'v4',
        });
    }

    async uploadToR2(filePath, key) {
        const fileStream = fs.createReadStream(filePath);
        
        const uploadParams = {
            Bucket: config.r2.bucket,
            Key: key,
            Body: fileStream,
            ContentType: 'application/zip'
        };
        
        await this.s3.upload(uploadParams).promise();
        
        // Generate presigned URL (valid for 7 days)
        const url = await this.s3.getSignedUrlPromise('getObject', {
            Bucket: config.r2.bucket,
            Key: key,
            Expires: 604800
        });
        
        return url;
    }

    async compressFiles(files, outputPath) {
        const archive = archiver('zip', { zlib: { level: 9 } });
        const output = fs.createWriteStream(outputPath);
        
        return new Promise((resolve, reject) => {
            output.on('close', () => resolve(outputPath));
            archive.on('error', reject);
            
            archive.pipe(output);
            
            files.forEach(file => {
                archive.file(file.path, { name: file.name });
            });
            
            archive.finalize();
        });
    }
}

const storageService = new StorageService();

// API Routes

// Authentication
app.post('/api/auth/send-code', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }
        
        await emailService.sendVerificationCode(email);
        
        res.json({ success: true, message: 'Verification code sent' });
    } catch (error) {
        logger.error('Send code error:', error);
        res.status(500).json({ error: 'Failed to send verification code' });
    }
});

app.post('/api/auth/verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        
        if (!emailService.verifyCode(email, code)) {
            return res.status(401).json({ error: 'Invalid or expired code' });
        }
        
        // Create or get user
        const users = db.getUsers();
        if (!users[email]) {
            db.saveUser(email, {
                email,
                createdAt: new Date().toISOString(),
                id: uuid()
            });
        }
        
        const user = db.getUsers()[email];
        
        // Generate JWT
        const token = jwt.sign(
            { email, userId: user.id },
            config.jwt.secret,
            { expiresIn: config.jwt.expiresIn }
        );
        
        res.json({
            success: true,
            token,
            user: { email, id: user.id }
        });
    } catch (error) {
        logger.error('Verify error:', error);
        res.status(500).json({ error: 'Verification failed' });
    }
});

// Middleware for protected routes
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, config.jwt.secret);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Dashboard Stats
app.get('/api/dashboard/stats', authenticate, async (req, res) => {
    try {
        const jobs = db.getJobs(req.user.userId);
        
        const stats = {
            totalJobs: jobs.length,
            successRate: jobs.length > 0 
                ? (jobs.filter(j => j.status === 'completed').length / jobs.length * 100).toFixed(1)
                : 0,
            avgProcessTime: jobs.length > 0
                ? Math.round(jobs.reduce((acc, j) => acc + (j.duration || 0), 0) / jobs.length)
                : 0,
            activeJobs: await exportQueue.getActiveCount(),
            queuedJobs: await exportQueue.getWaitingCount(),
            recentJobs: jobs.slice(-10).reverse()
        };
        
        res.json(stats);
    } catch (error) {
        logger.error('Stats error:', error);
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

// Settings
app.get('/api/settings', authenticate, (req, res) => {
    const settings = db.getSettings(req.user.userId);
    // Don't send encrypted passwords
    if (settings.luminaCredentials.password) {
        settings.luminaCredentials.password = '••••••••';
    }
    res.json(settings);
});

app.post('/api/settings', authenticate, (req, res) => {
    try {
        const settings = req.body;
        
        // Encrypt password if changed
        if (settings.luminaCredentials.password && 
            settings.luminaCredentials.password !== '••••••••') {
            settings.luminaCredentials.password = encryptionService.encrypt(
                settings.luminaCredentials.password
            );
        } else {
            // Keep existing password
            const current = db.getSettings(req.user.userId);
            settings.luminaCredentials.password = current.luminaCredentials.password;
        }
        
        db.saveSettings(req.user.userId, settings);
        
        res.json({ success: true, message: 'Settings saved successfully' });
    } catch (error) {
        logger.error('Settings save error:', error);
        res.status(500).json({ error: 'Failed to save settings' });
    }
});

// Jobs
app.get('/api/jobs', authenticate, (req, res) => {
    const jobs = db.getJobs(req.user.userId);
    res.json(jobs);
});

app.post('/api/jobs/create', authenticate, async (req, res) => {
    try {
        const { reportUrls, reportType } = req.body;
        const settings = db.getSettings(req.user.userId);
        
        if (!settings.luminaCredentials.username) {
            return res.status(400).json({ error: 'Lumina credentials not configured' });
        }
        
        const jobId = uuid();
        const job = await exportQueue.add('export', {
            id: jobId,
            userId: req.user.userId,
            reportUrls,
            reportType,
            settings,
            createdAt: new Date().toISOString()
        }, {
            attempts: settings.advanced.maxRetries,
            backoff: {
                type: 'exponential',
                delay: 5000
            },
            timeout: settings.advanced.timeout
        });
        
        res.json({
            success: true,
            jobId: job.id,
            status: 'queued'
        });
    } catch (error) {
        logger.error('Job creation error:', error);
        res.status(500).json({ error: 'Failed to create job' });
    }
});

app.get('/api/jobs/:jobId', authenticate, async (req, res) => {
    try {
        const job = await exportQueue.getJob(req.params.jobId);
        
        if (!job) {
            return res.status(404).json({ error: 'Job not found' });
        }
        
        const state = await job.getState();
        const progress = job.progress();
        
        res.json({
            id: job.id,
            status: state,
            progress,
            data: job.data,
            result: job.returnvalue,
            failedReason: job.failedReason
        });
    } catch (error) {
        logger.error('Job status error:', error);
        res.status(500).json({ error: 'Failed to get job status' });
    }
});

app.post('/api/jobs/:jobId/retry', authenticate, async (req, res) => {
    try {
        const job = await exportQueue.getJob(req.params.jobId);
        
        if (!job) {
            return res.status(404).json({ error: 'Job not found' });
        }
        
        await job.retry();
        
        res.json({ success: true, message: 'Job requeued' });
    } catch (error) {
        logger.error('Job retry error:', error);
        res.status(500).json({ error: 'Failed to retry job' });
    }
});

app.delete('/api/jobs/:jobId', authenticate, async (req, res) => {
    try {
        const job = await exportQueue.getJob(req.params.jobId);
        
        if (!job) {
            return res.status(404).json({ error: 'Job not found' });
        }
        
        await job.remove();
        
        res.json({ success: true, message: 'Job cancelled' });
    } catch (error) {
        logger.error('Job cancel error:', error);
        res.status(500).json({ error: 'Failed to cancel job' });
    }
});

// Cache Management
app.post('/api/cache/clear', authenticate, async (req, res) => {
    try {
        await redis.flushdb();
        
        // Clear temp files
        const tempDir = path.join(__dirname, 'temp');
        await fs.emptyDir(tempDir);
        
        res.json({ success: true, message: 'Cache cleared successfully' });
    } catch (error) {
        logger.error('Cache clear error:', error);
        res.status(500).json({ error: 'Failed to clear cache' });
    }
});

// Health Check
app.get('/health', async (req, res) => {
    const health = {
        status: 'healthy',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        queue: {
            waiting: await exportQueue.getWaitingCount(),
            active: await exportQueue.getActiveCount(),
            completed: await exportQueue.getCompletedCount(),
            failed: await exportQueue.getFailedCount()
        },
        timestamp: Date.now()
    };
    
    res.json(health);
});

// Queue Processor
exportQueue.process(config.advanced?.concurrency || 3, async (job) => {
    const { id, userId, reportUrls, settings } = job.data;
    const scraper = new LuminaScraper();
    
    try {
        await scraper.init();
        job.progress(10);
        
        // Decrypt credentials
        const credentials = {
            username: settings.luminaCredentials.username,
            password: encryptionService.decrypt(settings.luminaCredentials.password)
        };
        
        // Authenticate
        const auth = await scraper.authenticate(credentials);
        if (!auth.success) {
            throw new Error('Authentication failed: ' + auth.error);
        }
        job.progress(20);
        
        // Create download directory
        const downloadPath = path.join(__dirname, 'temp', id);
        await fs.ensureDir(downloadPath);
        
        // Scrape each report
        const allFiles = [];
        for (let i = 0; i < reportUrls.length; i++) {
            const result = await scraper.scrapeReport(reportUrls[i], auth, downloadPath);
            if (result.success) {
                const files = await fs.readdir(downloadPath);
                allFiles.push(...files.map(f => ({
                    name: f,
                    path: path.join(downloadPath, f)
                })));
            }
            job.progress(20 + (60 * (i + 1) / reportUrls.length));
        }
        
        // Compress files
        const zipPath = path.join(__dirname, 'temp', `${id}.zip`);
        await storageService.compressFiles(allFiles, zipPath);
        job.progress(80);
        
        // Upload to R2
        const downloadUrl = await storageService.uploadToR2(
            zipPath,
            `exports/${userId}/${id}.zip`
        );
        job.progress(90);
        
        // Clean up temp files
        await fs.remove(downloadPath);
        await fs.remove(zipPath);
        
        // Save job to database
        const jobRecord = {
            id,
            userId,
            name: `Export ${new Date().toLocaleDateString()}`,
            status: 'completed',
            startTime: job.timestamp,
            endTime: Date.now(),
            duration: Math.round((Date.now() - job.timestamp) / 1000),
            fileCount: allFiles.length,
            downloadUrl,
            createdAt: new Date().toISOString()
        };
        
        db.addJob(jobRecord);
        
        // Send notification
        if (settings.notifications.emailEnabled && settings.notifications.onSuccess) {
            await emailService.sendJobNotification(
                settings.notifications.emailAddress,
                jobRecord,
                'completed'
            );
        }
        
        job.progress(100);
        return jobRecord;
        
    } catch (error) {
        logger.error('Job processing error:', error);
        
        const jobRecord = {
            id,
            userId,
            name: `Export ${new Date().toLocaleDateString()}`,
            status: 'failed',
            startTime: job.timestamp,
            endTime: Date.now(),
            duration: Math.round((Date.now() - job.timestamp) / 1000),
            error: error.message,
            createdAt: new Date().toISOString()
        };
        
        db.addJob(jobRecord);
        
        // Send failure notification
        if (settings.notifications.emailEnabled && settings.notifications.onFailure) {
            await emailService.sendJobNotification(
                settings.notifications.emailAddress,
                jobRecord,
                'failed'
            );
        }
        
        throw error;
    } finally {
        await scraper.cleanup();
    }
});

// Schedule Manager
class ScheduleManager {
    constructor() {
        this.jobs = new Map();
    }

    start() {
        // Check all users' schedules every minute
        cron.schedule('* * * * *', async () => {
            const users = db.getUsers();
            
            for (const email in users) {
                const user = users[email];
                const settings = db.getSettings(user.id);
                
                if (settings.schedule.enabled) {
                    const jobKey = `${user.id}-${settings.schedule.frequency}`;
                    
                    if (!this.jobs.has(jobKey)) {
                        this.scheduleUserJobs(user.id, settings);
                    }
                }
            }
        });
    }

    scheduleUserJobs(userId, settings) {
        const { frequency, time } = settings.schedule;
        let cronExpression;
        
        const [hour, minute] = time.split(':');
        
        switch(frequency) {
            case 'hourly':
                cronExpression = `${minute} * * * *`;
                break;
            case 'daily':
                cronExpression = `${minute} ${hour} * * *`;
                break;
            case 'weekly':
                cronExpression = `${minute} ${hour} * * 1`;
                break;
            case 'monthly':
                cronExpression = `${minute} ${hour} 1 * *`;
                break;
            default:
                return;
        }
        
        const job = cron.schedule(cronExpression, async () => {
            // Get enabled report types
            const enabledReports = settings.reportTypes.filter(r => r.enabled);
            
            for (const report of enabledReports) {
                await exportQueue.add('export', {
                    id: uuid(),
                    userId,
                    reportUrls: [`${config.lumina.baseUrl}/lumina/view/reports/max?reportType=${report.name}`],
                    reportType: report.name,
                    settings,
                    scheduled: true,
                    createdAt: new Date().toISOString()
                });
            }
        });
        
        this.jobs.set(`${userId}-${frequency}`, job);
    }
}

const scheduleManager = new ScheduleManager();

// Start server
app.listen(config.port, () => {
    logger.info(`Server running on port ${config.port}`);
    scheduleManager.start();
    logger.info('Schedule manager started');
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    logger.info('SIGTERM signal received: closing HTTP server');
    
    await exportQueue.close();
    await redis.quit();
    
    process.exit(0);
});

module.exports = app;
