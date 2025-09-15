const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const logger = require('../utils/logger');

class Database {
    constructor() {
        this.db = null;
        this.dbPath = process.env.DATABASE_PATH || './database/nubolink.sqlite';
        this.isConnected = false;
    }

    async initialize() {
        return new Promise((resolve, reject) => {
            try {
                // Ensure database directory exists
                const dbDir = path.dirname(this.dbPath);
                if (!fs.existsSync(dbDir)) {
                    fs.mkdirSync(dbDir, { recursive: true });
                    logger.info(`Created database directory: ${dbDir}`);
                }

                // Create database connection
                this.db = new sqlite3.Database(this.dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
                    if (err) {
                        logger.error('Database connection failed:', err);
                        reject(err);
                    } else {
                        logger.info(`Connected to SQLite database: ${this.dbPath}`);
                        this.isConnected = true;
                        
                        // Enable foreign keys
                        this.db.run('PRAGMA foreign_keys = ON;', (err) => {
                            if (err) {
                                logger.warn('Failed to enable foreign keys:', err);
                            } else {
                                logger.debug('Foreign keys enabled');
                            }
                        });
                        
                        // Set journal mode to WAL for better concurrency
                        this.db.run('PRAGMA journal_mode = WAL;', (err) => {
                            if (err) {
                                logger.warn('Failed to set WAL mode:', err);
                            } else {
                                logger.debug('WAL mode enabled');
                            }
                        });
                        
                        this.createTables().then(resolve).catch(reject);
                    }
                });
            } catch (error) {
                logger.error('Database initialization error:', error);
                reject(error);
            }
        });
    }

    async createTables() {
        const startTime = Date.now();
        
        try {
            const schemas = [
                // Users table
                `CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    device_id TEXT,
                    device_name TEXT,
                    device_model TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    subscription_type TEXT DEFAULT 'free',
                    subscription_expires_at DATETIME,
                    max_connections INTEGER DEFAULT 1,
                    bytes_used INTEGER DEFAULT 0,
                    bytes_limit INTEGER DEFAULT 10737418240, -- 10GB default
                    last_login_at DATETIME,
                    last_ip TEXT,
                    email_verified BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )`,
                
                // VPN connections table
                `CREATE TABLE IF NOT EXISTS vpn_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    country_code TEXT NOT NULL,
                    country_name TEXT NOT NULL,
                    server_ip TEXT NOT NULL,
                    server_name TEXT,
                    client_ip TEXT,
                    client_port INTEGER,
                    public_key TEXT,
                    private_key TEXT, -- Encrypted
                    endpoint TEXT,
                    allowed_ips TEXT DEFAULT '0.0.0.0/0,::/0',
                    keep_alive INTEGER DEFAULT 25,
                    mtu INTEGER DEFAULT 1420,
                    status TEXT DEFAULT 'disconnected', -- connected, disconnected, connecting, error
                    connected_at DATETIME,
                    disconnected_at DATETIME,
                    duration_seconds INTEGER DEFAULT 0,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    last_handshake DATETIME,
                    disconnect_reason TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )`,
                
                // DNS statistics table
                `CREATE TABLE IF NOT EXISTS dns_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    queries_total INTEGER DEFAULT 0,
                    queries_blocked INTEGER DEFAULT 0,
                    queries_allowed INTEGER DEFAULT 0,
                    top_blocked_domains TEXT, -- JSON array
                    date DATE DEFAULT CURRENT_DATE,
                    hour INTEGER DEFAULT (strftime('%H', 'now')),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )`,
                
                // Server status table
                `CREATE TABLE IF NOT EXISTS servers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    country_code TEXT NOT NULL,
                    country_name TEXT NOT NULL,
                    server_ip TEXT NOT NULL,
                    server_name TEXT,
                    server_location TEXT,
                    wg_interface TEXT,
                    wg_port INTEGER DEFAULT 51820,
                    wg_public_key TEXT,
                    wg_private_key TEXT, -- Encrypted
                    client_pool TEXT, -- IP range for clients
                    max_clients INTEGER DEFAULT 100,
                    current_clients INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active', -- active, maintenance, disabled
                    cpu_usage REAL DEFAULT 0,
                    memory_usage REAL DEFAULT 0,
                    bandwidth_usage INTEGER DEFAULT 0,
                    latency_ms INTEGER DEFAULT 0,
                    last_check DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )`,
                
                // Audit log table
                `CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    resource_type TEXT, -- user, vpn, dns, server
                    resource_id TEXT,
                    details TEXT, -- JSON
                    ip_address TEXT,
                    user_agent TEXT,
                    success BOOLEAN DEFAULT 1,
                    error_message TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
                )`,
                
                // Blocked domains table
                `CREATE TABLE IF NOT EXISTS blocked_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    category TEXT, -- ads, tracking, malware, adult, etc.
                    description TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    block_count INTEGER DEFAULT 0,
                    last_blocked DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )`,
                
                // API keys table (for future use)
                `CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    key_hash TEXT UNIQUE NOT NULL,
                    name TEXT,
                    permissions TEXT, -- JSON array
                    last_used DATETIME,
                    expires_at DATETIME,
                    is_active BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )`
            ];

            // Create indexes for better performance
            const indexes = [
                'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);',
                'CREATE INDEX IF NOT EXISTS idx_users_device_id ON users(device_id);',
                'CREATE INDEX IF NOT EXISTS idx_vpn_connections_user_id ON vpn_connections(user_id);',
                'CREATE INDEX IF NOT EXISTS idx_vpn_connections_status ON vpn_connections(status);',
                'CREATE INDEX IF NOT EXISTS idx_vpn_connections_country ON vpn_connections(country_code);',
                'CREATE INDEX IF NOT EXISTS idx_dns_stats_user_id ON dns_stats(user_id);',
                'CREATE INDEX IF NOT EXISTS idx_dns_stats_date ON dns_stats(date);',
                'CREATE INDEX IF NOT EXISTS idx_servers_country ON servers(country_code);',
                'CREATE INDEX IF NOT EXISTS idx_servers_status ON servers(status);',
                'CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);',
                'CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);',
                'CREATE INDEX IF NOT EXISTS idx_blocked_domains_domain ON blocked_domains(domain);',
                'CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);'
            ];

            // Execute table creation
            for (const schema of schemas) {
                await this.run(schema);
            }
            
            // Execute index creation
            for (const index of indexes) {
                await this.run(index);
            }
            
            // Insert default data
            await this.insertDefaultData();
            
            const duration = Date.now() - startTime;
            logger.database('CREATE_TABLES', 'all', duration, true, { 
                tables: schemas.length, 
                indexes: indexes.length 
            });
            
            logger.info('Database tables and indexes created/verified successfully');
            
        } catch (error) {
            const duration = Date.now() - startTime;
            logger.database('CREATE_TABLES', 'all', duration, false, { error: error.message });
            throw error;
        }
    }

    async insertDefaultData() {
        try {
            // Insert default servers
            const defaultServers = [
                {
                    country_code: 'ES',
                    country_name: 'España',
                    server_ip: process.env.MIKROTIK_ES_HOST || '146.66.254.253',
                    server_name: 'Madrid-01',
                    server_location: 'Madrid, España',
                    wg_interface: 'wg-nuboprotect-es',
                    client_pool: '10.0.0.0/24',
                    latency_ms: 15
                },
                {
                    country_code: 'US',
                    country_name: 'Estados Unidos',
                    server_ip: process.env.MIKROTIK_US_HOST || '146.66.254.254',
                    server_name: 'NewYork-01',
                    server_location: 'Nueva York, Estados Unidos',
                    wg_interface: 'wg-nuboprotect-us',
                    client_pool: '10.1.0.0/24',
                    latency_ms: 89
                },
                {
                    country_code: 'GB',
                    country_name: 'Reino Unido',
                    server_ip: process.env.MIKROTIK_GB_HOST || '146.66.254.255',
                    server_name: 'London-01',
                    server_location: 'Londres, Reino Unido',
                    wg_interface: 'wg-nuboprotect-gb',
                    client_pool: '10.2.0.0/24',
                    latency_ms: 45
                }
            ];

            for (const server of defaultServers) {
                const existing = await this.get('SELECT id FROM servers WHERE country_code = ?', [server.country_code]);
                if (!existing) {
                    await this.run(`
                        INSERT INTO servers (
                            country_code, country_name, server_ip, server_name, 
                            server_location, wg_interface, client_pool, latency_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    `, [
                        server.country_code, server.country_name, server.server_ip,
                        server.server_name, server.server_location, server.wg_interface,
                        server.client_pool, server.latency_ms
                    ]);
                    logger.debug(`Inserted default server: ${server.country_name}`);
                }
            }

            // Insert common blocked domains
            const blockedDomains = [
                { domain: 'doubleclick.net', category: 'ads' },
                { domain: 'googleadservices.com', category: 'ads' },
                { domain: 'googlesyndication.com', category: 'ads' },
                { domain: 'amazon-adsystem.com', category: 'ads' },
                { domain: 'facebook.com/tr', category: 'tracking' },
                { domain: 'analytics.google.com', category: 'tracking' }
            ];

            for (const blocked of blockedDomains) {
                const existing = await this.get('SELECT id FROM blocked_domains WHERE domain = ?', [blocked.domain]);
                if (!existing) {
                    await this.run(`
                        INSERT INTO blocked_domains (domain, category) VALUES (?, ?)
                    `, [blocked.domain, blocked.category]);
                }
            }

            logger.debug('Default data inserted successfully');
            
        } catch (error) {
            logger.warn('Error inserting default data:', error);
            // Non-critical error, don't throw
        }
    }

    async run(sql, params = []) {
        const startTime = Date.now();
        
        return new Promise((resolve, reject) => {
            this.db.run(sql, params, function(err) {
                const duration = Date.now() - startTime;
                
                if (err) {
                    logger.database('RUN', 'unknown', duration, false, { 
                        error: err.message, 
                        sql: sql.substring(0, 100) 
                    });
                    reject(err);
                } else {
                    logger.database('RUN', 'unknown', duration, true, { 
                        lastID: this.lastID, 
                        changes: this.changes 
                    });
                    resolve({ id: this.lastID, changes: this.changes });
                }
            });
        });
    }

    async get(sql, params = []) {
        const startTime = Date.now();
        
        return new Promise((resolve, reject) => {
            this.db.get(sql, params, (err, row) => {
                const duration = Date.now() - startTime;
                
                if (err) {
                    logger.database('GET', 'unknown', duration, false, { 
                        error: err.message, 
                        sql: sql.substring(0, 100) 
                    });
                    reject(err);
                } else {
                    logger.database('GET', 'unknown', duration, true, { 
                        hasResult: !!row 
                    });
                    resolve(row);
                }
            });
        });
    }

    async all(sql, params = []) {
        const startTime = Date.now();
        
        return new Promise((resolve, reject) => {
            this.db.all(sql, params, (err, rows) => {
                const duration = Date.now() - startTime;
                
                if (err) {
                    logger.database('ALL', 'unknown', duration, false, { 
                        error: err.message, 
                        sql: sql.substring(0, 100) 
                    });
                    reject(err);
                } else {
                    logger.database('ALL', 'unknown', duration, true, { 
                        rowCount: rows.length 
                    });
                    resolve(rows);
                }
            });
        });
    }

    async checkConnection() {
        try {
            await this.get('SELECT 1 as test');
            return true;
        } catch (error) {
            logger.error('Database connection check failed:', error);
            return false;
        }
    }

    async backup(backupPath) {
        return new Promise((resolve, reject) => {
            const backup = new sqlite3.Database(backupPath);
            
            this.db.backup(backup, (err) => {
                backup.close();
                
                if (err) {
                    logger.error('Database backup failed:', err);
                    reject(err);
                } else {
                    logger.info(`Database backup created: ${backupPath}`);
                    resolve(backupPath);
                }
            });
        });
    }

    async getStats() {
        try {
            const stats = await this.get(`
                SELECT 
                    (SELECT COUNT(*) FROM users) as total_users,
                    (SELECT COUNT(*) FROM users WHERE is_active = 1) as active_users,
                    (SELECT COUNT(*) FROM vpn_connections WHERE status = 'connected') as active_connections,
                    (SELECT COUNT(*) FROM servers WHERE status = 'active') as active_servers,
                    (SELECT SUM(bytes_sent + bytes_received) FROM vpn_connections) as total_bytes
            `);
            
            return stats;
        } catch (error) {
            logger.error('Error getting database stats:', error);
            return null;
        }
    }

    async close() {
        return new Promise((resolve, reject) => {
            if (this.db && this.isConnected) {
                this.db.close((err) => {
                    if (err) {
                        logger.error('Database close error:', err);
                        reject(err);
                    } else {
                        logger.info('Database connection closed');
                        this.isConnected = false;
                        resolve();
                    }
                });
            } else {
                resolve();
            }
        });
    }
}

// Export singleton instance
module.exports = new Database();
