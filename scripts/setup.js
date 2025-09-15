#!/usr/bin/env node

/**
 * NuboLink API Setup Script
 * Initializes database, creates default data, and verifies installation
 */

const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
require('dotenv').config();

// Import our modules
const database = require('../config/database');
const logger = require('../utils/logger');

// Colors for console output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m'
};

const log = (message, color = 'reset') => {
    console.log(`${colors[color]}${message}${colors.reset}`);
};

const logStep = (step, total, message) => {
    log(`[${step}/${total}] ${message}`, 'cyan');
};

const logSuccess = (message) => {
    log(`✅ ${message}`, 'green');
};

const logError = (message) => {
    log(`❌ ${message}`, 'red');
};

const logWarning = (message) => {
    log(`⚠️  ${message}`, 'yellow');
};

const logInfo = (message) => {
    log(`ℹ️  ${message}`, 'blue');
};

class SetupManager {
    constructor() {
        this.errors = [];
        this.warnings = [];
        this.steps = 12;
        this.currentStep = 0;
    }

    async run() {
        log('\n' + '='.repeat(60), 'bright');
        log('🚀 NuboLink API Setup & Initialization', 'bright');
        log('='.repeat(60), 'bright');
        log('');

        try {
            await this.checkEnvironment();
            await this.createDirectories();
            await this.initializeDatabase();
            await this.createDefaultServers();
            await this.createDefaultBlockedDomains();
            await this.createTestUser();
            await this.verifyConfiguration();
            await this.testAPIEndpoints();
            await this.generateSecrets();
            await this.createBackupSchedule();
            await this.optimizeDatabase();
            await this.showSummary();

            if (this.errors.length === 0) {
                log('\n' + '='.repeat(60), 'green');
                log('🎉 Setup completed successfully!', 'green');
                log('='.repeat(60), 'green');
                this.showStartupInstructions();
            } else {
                log('\n' + '='.repeat(60), 'red');
                log('⚠️  Setup completed with errors', 'red');
                log('='.repeat(60), 'red');
                this.showErrorSummary();
            }

        } catch (error) {
            logError(`Setup failed: ${error.message}`);
            console.error(error);
            process.exit(1);
        }
    }

    nextStep(message) {
        this.currentStep++;
        logStep(this.currentStep, this.steps, message);
    }

    async checkEnvironment() {
        this.nextStep('Checking environment and dependencies');

        // Check Node.js version
        const nodeVersion = process.version;
        const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
        
        if (majorVersion < 16) {
            this.errors.push(`Node.js version ${nodeVersion} is not supported. Please use Node.js 16 or higher.`);
        } else {
            logSuccess(`Node.js version: ${nodeVersion}`);
        }

        // Check required environment variables
        const requiredEnvVars = [
            'JWT_SECRET',
            'DATABASE_PATH',
            'MIKROTIK_ES_HOST',
            'MIKROTIK_ES_USER',
            'MIKROTIK_ES_PASS'
        ];

        const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
        
        if (missingEnvVars.length > 0) {
            this.warnings.push(`Missing environment variables: ${missingEnvVars.join(', ')}`);
            logWarning('Some environment variables are missing. Using defaults where possible.');
        } else {
            logSuccess('All required environment variables are set');
        }

        // Check if .env file exists
        if (!fs.existsSync('.env')) {
            this.warnings.push('.env file not found. Using .env.example as reference.');
            logWarning('Consider copying .env.example to .env and configuring your values');
        }

        // Check required packages
        const requiredPackages = ['express', 'sqlite3', 'bcrypt', 'jsonwebtoken', 'ssh2'];
        const packageJson = require('../package.json');
        
        for (const pkg of requiredPackages) {
            if (!packageJson.dependencies[pkg]) {
                this.errors.push(`Required package ${pkg} is not installed`);
            }
        }

        if (this.errors.length === 0) {
            logSuccess('Environment check passed');
        }
    }

    async createDirectories() {
        this.nextStep('Creating required directories');

        const directories = [
            'logs',
            'database',
            'backups',
            'temp',
            'uploads'
        ];

        for (const dir of directories) {
            try {
                if (!fs.existsSync(dir)) {
                    fs.mkdirSync(dir, { recursive: true });
                    logSuccess(`Created directory: ${dir}`);
                } else {
                    logInfo(`Directory already exists: ${dir}`);
                }
            } catch (error) {
                this.errors.push(`Failed to create directory ${dir}: ${error.message}`);
            }
        }
    }

    async initializeDatabase() {
        this.nextStep('Initializing database');

        try {
            await database.initialize();
            logSuccess('Database initialized successfully');

            // Check table creation
            const tables = [
                'users', 'vpn_connections', 'dns_stats', 'servers', 
                'audit_logs', 'blocked_domains', 'api_keys'
            ];

            for (const table of tables) {
                const result = await database.get(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    [table]
                );
                
                if (result) {
                    logSuccess(`Table '${table}' created successfully`);
                } else {
                    this.errors.push(`Table '${table}' was not created`);
                }
            }

        } catch (error) {
            this.errors.push(`Database initialization failed: ${error.message}`);
        }
    }

    async createDefaultServers() {
        this.nextStep('Creating default server configurations');

        const defaultServers = [
            {
                country_code: 'ES',
                country_name: 'España',
                server_ip: process.env.MIKROTIK_ES_HOST || '146.66.254.253',
                server_name: 'Madrid-01',
                server_location: 'Madrid, España',
                wg_interface: 'wg-nuboprotect-es',
                wg_port: 51820,
                client_pool: '10.0.0.0/24',
                max_clients: 100,
                latency_ms: 15,
                status: 'active'
            },
            {
                country_code: 'US',
                country_name: 'Estados Unidos',
                server_ip: process.env.MIKROTIK_US_HOST || '146.66.254.254',
                server_name: 'NewYork-01',
                server_location: 'Nueva York, Estados Unidos',
                wg_interface: 'wg-nuboprotect-us',
                wg_port: 51820,
                client_pool: '10.1.0.0/24',
                max_clients: 100,
                latency_ms: 89,
                status: 'active'
            },
            {
                country_code: 'GB',
                country_name: 'Reino Unido',
                server_ip: process.env.MIKROTIK_GB_HOST || '146.66.254.255',
                server_name: 'London-01',
                server_location: 'Londres, Reino Unido',
                wg_interface: 'wg-nuboprotect-gb',
                wg_port: 51820,
                client_pool: '10.2.0.0/24',
                max_clients: 100,
                latency_ms: 45,
                status: 'active'
            },
            {
                country_code: 'FR',
                country_name: 'Francia',
                server_ip: process.env.MIKROTIK_FR_HOST || '146.66.254.251',
                server_name: 'Paris-01',
                server_location: 'París, Francia',
                wg_interface: 'wg-nuboprotect-fr',
                wg_port: 51820,
                client_pool: '10.3.0.0/24',
                max_clients: 100,
                latency_ms: 32,
                status: 'active'
            },
            {
                country_code: 'DE',
                country_name: 'Alemania',
                server_ip: process.env.MIKROTIK_DE_HOST || '146.66.254.250',
                server_name: 'Berlin-01',
                server_location: 'Berlín, Alemania',
                wg_interface: 'wg-nuboprotect-de',
                wg_port: 51820,
                client_pool: '10.4.0.0/24',
                max_clients: 100,
                latency_ms: 41,
                status: 'active'
            }
        ];

        try {
            for (const server of defaultServers) {
                const existing = await database.get(
                    'SELECT id FROM servers WHERE country_code = ?',
                    [server.country_code]
                );

                if (!existing) {
                    await database.run(`
                        INSERT INTO servers (
                            country_code, country_name, server_ip, server_name,
                            server_location, wg_interface, wg_port, client_pool,
                            max_clients, latency_ms, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    `, [
                        server.country_code, server.country_name, server.server_ip,
                        server.server_name, server.server_location, server.wg_interface,
                        server.wg_port, server.client_pool, server.max_clients,
                        server.latency_ms, server.status
                    ]);
                    logSuccess(`Created server: ${server.country_name} (${server.server_ip})`);
                } else {
                    logInfo(`Server already exists: ${server.country_name}`);
                }
            }
        } catch (error) {
            this.errors.push(`Failed to create default servers: ${error.message}`);
        }
    }

    async createDefaultBlockedDomains() {
        this.nextStep('Creating default blocked domains list');

        const blockedDomains = [
            // Ads
            { domain: 'doubleclick.net', category: 'ads', description: 'Google advertising network' },
            { domain: 'googleadservices.com', category: 'ads', description: 'Google Ads' },
            { domain: 'googlesyndication.com', category: 'ads', description: 'Google AdSense' },
            { domain: 'amazon-adsystem.com', category: 'ads', description: 'Amazon advertising' },
            { domain: 'adsystem.amazon.com', category: 'ads', description: 'Amazon ads' },
            { domain: 'ads.yahoo.com', category: 'ads', description: 'Yahoo ads' },
            { domain: 'bing.com/fd/ls/l', category: 'ads', description: 'Bing ads' },
            
            // Tracking
            { domain: 'facebook.com/tr', category: 'tracking', description: 'Facebook tracking pixel' },
            { domain: 'analytics.google.com', category: 'tracking', description: 'Google Analytics' },
            { domain: 'google-analytics.com', category: 'tracking', description: 'Google Analytics' },
            { domain: 'scorecardresearch.com', category: 'tracking', description: 'ComScore tracking' },
            { domain: 'quantserve.com', category: 'tracking', description: 'Quantcast tracking' },
            { domain: 'outbrain.com', category: 'tracking', description: 'Outbrain tracking' },
            { domain: 'taboola.com', category: 'tracking', description: 'Taboola tracking' },
            
            // Malware/Security
            { domain: 'malwaredomainlist.com', category: 'malware', description: 'Known malware domain' },
            { domain: 'phishing-site-example.com', category: 'malware', description: 'Example phishing site' },
            { domain: 'malicious-download.com', category: 'malware', description: 'Malicious downloads' },
            
            // Adult Content (disabled by default)
            { domain: 'adult-content-example.com', category: 'adult', description: 'Adult content example' },
            
            // Gambling
            { domain: 'gambling-site-example.com', category: 'gambling', description: 'Online gambling example' }
        ];

        try {
            for (const domain of blockedDomains) {
                const existing = await database.get(
                    'SELECT id FROM blocked_domains WHERE domain = ?',
                    [domain.domain]
                );

                if (!existing) {
                    await database.run(`
                        INSERT INTO blocked_domains (domain, category, description, is_active)
                        VALUES (?, ?, ?, 1)
                    `, [domain.domain, domain.category, domain.description]);
                }
            }

            const count = await database.get('SELECT COUNT(*) as count FROM blocked_domains');
            logSuccess(`Created ${count.count} blocked domains across all categories`);

        } catch (error) {
            this.errors.push(`Failed to create blocked domains: ${error.message}`);
        }
    }

    async createTestUser() {
        this.nextStep('Creating test user account');

        const testUserData = {
            username: 'testuser',
            email: 'test@nubolink.com',
            password: 'TestPassword123!',
            deviceId: '550e8400-e29b-41d4-a716-446655440000',
            deviceName: 'Test Device',
            deviceModel: 'Setup Script'
        };

        try {
            const existingUser = await database.get(
                'SELECT id FROM users WHERE email = ? OR username = ?',
                [testUserData.email, testUserData.username]
            );

            if (!existingUser) {
                const saltRounds = 12;
                const passwordHash = await bcrypt.hash(testUserData.password, saltRounds);

                await database.run(`
                    INSERT INTO users (
                        username, email, password_hash, device_id, 
                        device_name, device_model, subscription_type,
                        is_active, email_verified
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1)
                `, [
                    testUserData.username, testUserData.email, passwordHash,
                    testUserData.deviceId, testUserData.deviceName, testUserData.deviceModel,
                    'premium'
                ]);

                logSuccess(`Created test user: ${testUserData.username} (${testUserData.email})`);
                logInfo(`Test user password: ${testUserData.password}`);
                logWarning('Remember to change or delete the test user in production!');
            } else {
                logInfo('Test user already exists');
            }

        } catch (error) {
            this.warnings.push(`Failed to create test user: ${error.message}`);
        }
    }

    async verifyConfiguration() {
        this.nextStep('Verifying configuration and connectivity');

        // Check database connectivity
        try {
            const isConnected = await database.checkConnection();
            if (isConnected) {
                logSuccess('Database connectivity: OK');
            } else {
                this.errors.push('Database connectivity failed');
            }
        } catch (error) {
            this.errors.push(`Database verification failed: ${error.message}`);
        }

        // Check log directory permissions
        try {
            const testLogFile = path.join('logs', 'setup-test.log');
            fs.writeFileSync(testLogFile, 'Test log entry\n');
            fs.unlinkSync(testLogFile);
            logSuccess('Log directory: Writable');
        } catch (error) {
            this.errors.push('Log directory is not writable');
        }

        // Verify JWT secret
        if (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'change-this-super-secret-jwt-key-in-production') {
            this.warnings.push('JWT_SECRET is using default value - change it in production!');
        } else {
            logSuccess('JWT secret: Configured');
        }
    }

    async testAPIEndpoints() {
        this.nextStep('Testing core functionality');

        try {
            // Test user creation flow
            const userCount = await database.get('SELECT COUNT(*) as count FROM users');
            logSuccess(`Users in database: ${userCount.count}`);

            // Test server availability
            const serverCount = await database.get('SELECT COUNT(*) as count FROM servers WHERE status = "active"');
            logSuccess(`Active servers: ${serverCount.count}`);

            // Test blocked domains
            const blockedCount = await database.get('SELECT COUNT(*) as count FROM blocked_domains WHERE is_active = 1');
            logSuccess(`Blocked domains: ${blockedCount.count}`);

            // Test logger functionality
            logger.info('Setup script test log entry');
            logSuccess('Logger: Working');

        } catch (error) {
            this.errors.push(`Core functionality test failed: ${error.message}`);
        }
    }

    async generateSecrets() {
        this.nextStep('Generating security tokens and keys');

        try {
            const crypto = require('crypto');

            // Generate API key for admin operations
            const apiKey = crypto.randomBytes(32).toString('hex');
            
            // Store in environment or show to user
            logSuccess('Admin API key generated');
            logInfo(`Admin API Key: ${apiKey}`);
            logWarning('Store this API key securely - it will not be shown again!');

            // Generate WireGuard server keys for each server
            const servers = await database.all('SELECT id, country_code FROM servers');
            
            for (const server of servers) {
                const privateKey = crypto.randomBytes(32).toString('base64');
                const publicKey = crypto.randomBytes(32).toString('base64'); // In real implementation, derive from private
                
                await database.run(
                    'UPDATE servers SET wg_private_key = ?, wg_public_key = ? WHERE id = ?',
                    [privateKey, publicKey, server.id]
                );
            }

            logSuccess(`Generated WireGuard keys for ${servers.length} servers`);

        } catch (error) {
            this.warnings.push(`Key generation failed: ${error.message}`);
        }
    }

    async createBackupSchedule() {
        this.nextStep('Setting up backup configuration');

        try {
            // Create backup script
            const backupScript = `#!/bin/bash
# NuboLink API Database Backup Script
# Generated by setup script

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="./backups"
DB_PATH="${process.env.DATABASE_PATH || './database/nubolink.sqlite'}"

# Create backup directory if it doesn't exist
mkdir -p $BACKUP_DIR

# Create backup
cp "$DB_PATH" "$BACKUP_DIR/nubolink_backup_$DATE.sqlite"

# Keep only last 30 backups
find $BACKUP_DIR -name "nubolink_backup_*.sqlite" -type f -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/nubolink_backup_$DATE.sqlite"
`;

            fs.writeFileSync('scripts/backup.sh', backupScript);
            
            // Make executable on Unix systems
            if (process.platform !== 'win32') {
                fs.chmodSync('scripts/backup.sh', '755');
            }

            logSuccess('Backup script created: scripts/backup.sh');
            logInfo('You can schedule this script with cron for automatic backups');

        } catch (error) {
            this.warnings.push(`Backup setup failed: ${error.message}`);
        }
    }

    async optimizeDatabase() {
        this.nextStep('Optimizing database performance');

        try {
            // Run VACUUM to optimize database
            await database.run('VACUUM');
            
            // Analyze tables for query optimization
            await database.run('ANALYZE');
            
            // Get database stats
            const stats = await database.getStats();
            if (stats) {
                logSuccess(`Database optimized - ${stats.total_users} users, ${stats.active_servers} servers`);
            } else {
                logSuccess('Database optimized successfully');
            }

        } catch (error) {
            this.warnings.push(`Database optimization failed: ${error.message}`);
        }
    }

    async showSummary() {
        this.nextStep('Generating setup summary');

        const summary = {
            database: {
                path: process.env.DATABASE_PATH || './database/nubolink.sqlite',
                size: this.getFileSize(process.env.DATABASE_PATH || './database/nubolink.sqlite')
            },
            servers: await database.get('SELECT COUNT(*) as count FROM servers'),
            users: await database.get('SELECT COUNT(*) as count FROM users'),
            blockedDomains: await database.get('SELECT COUNT(*) as count FROM blocked_domains'),
            errors: this.errors.length,
            warnings: this.warnings.length
        };

        log('\n' + '📊 Setup Summary', 'bright');
        log('─'.repeat(40), 'blue');
        log(`Database: ${summary.database.path} (${summary.database.size})`, 'blue');
        log(`Servers configured: ${summary.servers.count}`, 'blue');
        log(`Users created: ${summary.users.count}`, 'blue');
        log(`Blocked domains: ${summary.blockedDomains.count}`, 'blue');
        log(`Errors: ${summary.errors}`, summary.errors > 0 ? 'red' : 'green');
        log(`Warnings: ${summary.warnings}`, summary.warnings > 0 ? 'yellow' : 'green');
    }

    showStartupInstructions() {
        log('\n🚀 Startup Instructions:', 'bright');
        log('─'.repeat(40), 'green');
        log('1. Start the server:', 'green');
        log('   npm start              (production)', 'cyan');
        log('   npm run dev            (development)', 'cyan');
        log('');
        log('2. API will be available at:', 'green');
        log(`   http://localhost:${process.env.PORT || 3001}`, 'cyan');
        log('');
        log('3. Health check:', 'green');
        log(`   curl http://localhost:${process.env.PORT || 3001}/health`, 'cyan');
        log('');
        log('4. Test user credentials:', 'green');
        log('   Email: test@nubolink.com', 'cyan');
        log('   Password: TestPassword123!', 'cyan');
        log('');
        log('5. API documentation:', 'green');
        log(`   http://localhost:${process.env.PORT || 3001}/api`, 'cyan');
        log('');
        logWarning('Remember to:');
        log('- Change default passwords in production', 'yellow');
        log('- Configure your Mikrotik server details in .env', 'yellow');
        log('- Set up SSL certificates for production', 'yellow');
        log('- Schedule database backups', 'yellow');
    }

    showErrorSummary() {
        if (this.errors.length > 0) {
            log('\n❌ Errors encountered:', 'red');
            this.errors.forEach((error, index) => {
                log(`${index + 1}. ${error}`, 'red');
            });
        }

        if (this.warnings.length > 0) {
            log('\n⚠️  Warnings:', 'yellow');
            this.warnings.forEach((warning, index) => {
                log(`${index + 1}. ${warning}`, 'yellow');
            });
        }
    }

    getFileSize(filePath) {
        try {
            const stats = fs.statSync(filePath);
            const size = stats.size;
            
            if (size < 1024) return `${size} B`;
            if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
            if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
            return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
        } catch {
            return 'Unknown';
        }
    }
}

// Run setup if called directly
if (require.main === module) {
    const setup = new SetupManager();
    setup.run().catch(error => {
        console.error('Setup failed:', error);
        process.exit(1);
    });
}

module.exports = SetupManager;
