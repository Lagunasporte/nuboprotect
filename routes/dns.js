const express = require('express');
const Joi = require('joi');
const dns = require('dns').promises;

const database = require('../config/database');
const logger = require('../utils/logger');
const { authMiddleware, auditLog } = require('../middleware/auth');
const { asyncErrorHandler, validationError, createError, notFoundError } = require('../middleware/errorHandler');

const router = express.Router();

// Validation schemas
const enableDNSSchema = Joi.object({
    servers: Joi.array()
        .items(Joi.string().ip())
        .min(1)
        .max(4)
        .optional(),
    
    customFiltering: Joi.object({
        ads: Joi.boolean().default(true),
        tracking: Joi.boolean().default(true),
        malware: Joi.boolean().default(true),
        adult: Joi.boolean().default(false),
        gambling: Joi.boolean().default(false)
    }).optional(),
    
    customDomains: Joi.array()
        .items(Joi.string().domain())
        .max(100)
        .optional()
});

const blockDomainSchema = Joi.object({
    domain: Joi.string()
        .domain()
        .required()
        .messages({
            'string.domain': 'Must be a valid domain name',
            'any.required': 'Domain is required'
        }),
    
    category: Joi.string()
        .valid('ads', 'tracking', 'malware', 'adult', 'gambling', 'custom', 'spam')
        .default('custom'),
    
    description: Joi.string()
        .max(255)
        .optional()
});

const unblockDomainSchema = Joi.object({
    domain: Joi.string()
        .domain()
        .required()
});

const queryStatsSchema = Joi.object({
    timeframe: Joi.string()
        .valid('hour', 'day', 'week', 'month')
        .default('day'),
    
    startDate: Joi.date()
        .iso()
        .optional(),
    
    endDate: Joi.date()
        .iso()
        .optional()
});

// DNS Server configurations
const DNS_SERVERS = {
    nubolink: {
        primary: process.env.DNS_PRIMARY || '146.66.254.253',
        secondary: process.env.DNS_SECONDARY || '146.66.254.252',
        name: 'NuboLink DNS',
        description: 'Secure DNS with ad and tracker blocking',
        features: ['ad-blocking', 'tracking-protection', 'malware-protection']
    },
    cloudflare: {
        primary: '1.1.1.1',
        secondary: '1.0.0.1',
        name: 'Cloudflare DNS',
        description: 'Fast and privacy-focused DNS',
        features: ['fast', 'privacy-focused']
    },
    google: {
        primary: '8.8.8.8',
        secondary: '8.8.4.4',
        name: 'Google DNS',
        description: 'Reliable public DNS service',
        features: ['reliable', 'fast']
    },
    quad9: {
        primary: '9.9.9.9',
        secondary: '149.112.112.112',
        name: 'Quad9 DNS',
        description: 'DNS with malware blocking',
        features: ['malware-protection', 'privacy']
    },
    opendns: {
        primary: '208.67.222.222',
        secondary: '208.67.220.220',
        name: 'OpenDNS',
        description: 'DNS with content filtering options',
        features: ['content-filtering', 'parental-controls']
    }
};

// Helper function to check DNS server response time
const checkDNSLatency = async (server) => {
    const startTime = Date.now();
    
    try {
        await dns.resolve('google.com', 'A');
        return Date.now() - startTime;
    } catch (error) {
        logger.warn(`DNS latency check failed for ${server}:`, error.message);
        return -1; // Indicate failure
    }
};

// Helper function to get blocked domains by category
const getBlockedDomainsByCategory = async () => {
    const domains = await database.all(`
        SELECT domain, category, block_count 
        FROM blocked_domains 
        WHERE is_active = 1 
        ORDER BY category, block_count DESC
    `);
    
    return domains.reduce((acc, domain) => {
        if (!acc[domain.category]) {
            acc[domain.category] = [];
        }
        acc[domain.category].push({
            domain: domain.domain,
            blockCount: domain.block_count
        });
        return acc;
    }, {});
};

// Helper function to update DNS stats
const updateDNSStats = async (userId, queriesTotal, queriesBlocked) => {
    const now = new Date();
    const date = now.toISOString().split('T')[0];
    const hour = now.getHours();
    
    // Try to update existing record
    const updated = await database.run(`
        UPDATE dns_stats 
        SET queries_total = queries_total + ?,
            queries_blocked = queries_blocked + ?,
            queries_allowed = queries_allowed + ?
        WHERE user_id = ? AND date = ? AND hour = ?
    `, [queriesTotal, queriesBlocked, queriesTotal - queriesBlocked, userId, date, hour]);
    
    // If no record was updated, create new one
    if (updated.changes === 0) {
        await database.run(`
            INSERT INTO dns_stats (
                user_id, queries_total, queries_blocked, queries_allowed,
                date, hour
            ) VALUES (?, ?, ?, ?, ?, ?)
        `, [userId, queriesTotal, queriesBlocked, queriesTotal - queriesBlocked, date, hour]);
    }
};

/**
 * GET /api/dns/servers
 * Get available DNS servers with performance metrics
 */
router.get('/servers', authMiddleware, asyncErrorHandler(async (req, res) => {
    const servers = [];
    
    // Test latency for each DNS server
    for (const [key, config] of Object.entries(DNS_SERVERS)) {
        const primaryLatency = await checkDNSLatency(config.primary);
        const secondaryLatency = await checkDNSLatency(config.secondary);
        
        servers.push({
            id: key,
            name: config.name,
            description: config.description,
            features: config.features,
            servers: {
                primary: {
                    ip: config.primary,
                    latency: primaryLatency,
                    status: primaryLatency > 0 ? 'online' : 'offline'
                },
                secondary: {
                    ip: config.secondary,
                    latency: secondaryLatency,
                    status: secondaryLatency > 0 ? 'online' : 'offline'
                }
            },
            averageLatency: primaryLatency > 0 && secondaryLatency > 0 
                ? Math.round((primaryLatency + secondaryLatency) / 2)
                : Math.max(primaryLatency, secondaryLatency),
            recommended: key === 'nubolink' || (primaryLatency > 0 && primaryLatency < 50)
        });
    }
    
    // Sort by average latency
    servers.sort((a, b) => {
        if (a.averageLatency === -1) return 1;
        if (b.averageLatency === -1) return -1;
        return a.averageLatency - b.averageLatency;
    });
    
    logger.dns('GET_SERVERS', req.user.id, {
        serversCount: servers.length,
        onlineServers: servers.filter(s => s.averageLatency > 0).length
    });
    
    res.json({
        servers,
        recommended: servers.find(s => s.recommended),
        totalServers: servers.length
    });
}));

/**
 * POST /api/dns/enable
 * Enable DNS filtering with custom configuration
 */
router.post('/enable', authMiddleware, auditLog('DNS_ENABLE', 'dns'), asyncErrorHandler(async (req, res) => {
    // Validate request
    const { error, value } = enableDNSSchema.validate(req.body);
    if (error) {
        throw validationError('enableDNS', error.details[0].message);
    }
    
    const { servers, customFiltering, customDomains } = value;
    
    // Use default NuboLink DNS servers if none specified
    const dnsServers = servers || [
        DNS_SERVERS.nubolink.primary,
        DNS_SERVERS.nubolink.secondary
    ];
    
    // Default filtering settings
    const filtering = {
        ads: true,
        tracking: true,
        malware: true,
        adult: false,
        gambling: false,
        ...customFiltering
    };
    
    try {
        // Create DNS configuration record (in a real implementation, this would configure the actual DNS)
        const configResult = await database.run(`
            INSERT OR REPLACE INTO user_dns_config (
                user_id, enabled, servers, filtering_settings,
                custom_domains, created_at, updated_at
            ) VALUES (?, 1, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        `, [
            req.user.id,
            JSON.stringify(dnsServers),
            JSON.stringify(filtering),
            JSON.stringify(customDomains || [])
        ]);
        
        // Add custom domains to blocked list if provided
        if (customDomains && customDomains.length > 0) {
            for (const domain of customDomains) {
                await database.run(`
                    INSERT OR IGNORE INTO blocked_domains (domain, category, description)
                    VALUES (?, 'custom', 'User-added domain')
                `, [domain]);
            }
        }
        
        // Initialize DNS stats for today
        await updateDNSStats(req.user.id, 0, 0);
        
        logger.dns('DNS_ENABLED', req.user.id, {
            servers: dnsServers,
            filtering,
            customDomainsCount: customDomains?.length || 0
        });
        
        res.json({
            message: 'DNS filtering enabled successfully',
            configuration: {
                servers: dnsServers.map(server => {
                    const serverConfig = Object.values(DNS_SERVERS).find(
                        config => config.primary === server || config.secondary === server
                    );
                    return {
                        ip: server,
                        name: serverConfig?.name || 'Custom DNS',
                        type: server === dnsServers[0] ? 'primary' : 'secondary'
                    };
                }),
                filtering,
                customDomains: customDomains || [],
                enabledAt: new Date().toISOString()
            }
        });
        
    } catch (error) {
        logger.dns('DNS_ENABLE_FAILED', req.user.id, {
            error: error.message,
            servers: dnsServers
        });
        
        throw createError('Failed to enable DNS filtering', 'DNS_CONFIG_ERROR', 500);
    }
}));

/**
 * POST /api/dns/disable
 * Disable DNS filtering
 */
router.post('/disable', authMiddleware, auditLog('DNS_DISABLE', 'dns'), asyncErrorHandler(async (req, res) => {
    try {
        // Update DNS configuration
        const result = await database.run(`
            UPDATE user_dns_config 
            SET enabled = 0, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        `, [req.user.id]);
        
        if (result.changes === 0) {
            return res.status(404).json({
                error: {
                    message: 'DNS configuration not found',
                    code: 'DNS_CONFIG_NOT_FOUND'
                }
            });
        }
        
        logger.dns('DNS_DISABLED', req.user.id, {
            disabledAt: new Date().toISOString()
        });
        
        res.json({
            message: 'DNS filtering disabled successfully',
            disabledAt: new Date().toISOString()
        });
        
    } catch (error) {
        logger.dns('DNS_DISABLE_FAILED', req.user.id, {
            error: error.message
        });
        
        throw createError('Failed to disable DNS filtering', 'DNS_CONFIG_ERROR', 500);
    }
}));

/**
 * GET /api/dns/status
 * Get current DNS configuration and status
 */
router.get('/status', authMiddleware, asyncErrorHandler(async (req, res) => {
    // Get DNS configuration
    const config = await database.get(`
        SELECT enabled, servers, filtering_settings, custom_domains, 
               created_at, updated_at
        FROM user_dns_config 
        WHERE user_id = ?
    `, [req.user.id]);
    
    if (!config) {
        return res.json({
            enabled: false,
            message: 'DNS filtering not configured'
        });
    }
    
    const servers = JSON.parse(config.servers);
    const filtering = JSON.parse(config.filtering_settings);
    const customDomains = JSON.parse(config.custom_domains);
    
    // Get today's stats
    const today = new Date().toISOString().split('T')[0];
    const stats = await database.get(`
        SELECT 
            SUM(queries_total) as total_queries,
            SUM(queries_blocked) as blocked_queries,
            SUM(queries_allowed) as allowed_queries
        FROM dns_stats 
        WHERE user_id = ? AND date = ?
    `, [req.user.id, today]);
    
    res.json({
        enabled: config.enabled === 1,
        configuration: {
            servers: servers.map(server => {
                const serverConfig = Object.values(DNS_SERVERS).find(
                    config => config.primary === server || config.secondary === server
                );
                return {
                    ip: server,
                    name: serverConfig?.name || 'Custom DNS',
                    type: server === servers[0] ? 'primary' : 'secondary'
                };
            }),
            filtering,
            customDomains,
            lastUpdated: config.updated_at
        },
        statistics: {
            today: {
                totalQueries: stats?.total_queries || 0,
                blockedQueries: stats?.blocked_queries || 0,
                allowedQueries: stats?.allowed_queries || 0,
                blockRate: stats?.total_queries > 0 
                    ? Math.round((stats.blocked_queries / stats.total_queries) * 100)
                    : 0
            }
        }
    });
}));

/**
 * GET /api/dns/stats
 * Get detailed DNS statistics
 */
router.get('/stats', authMiddleware, asyncErrorHandler(async (req, res) => {
    const { error, value } = queryStatsSchema.validate(req.query);
    if (error) {
        throw validationError('stats', error.details[0].message);
    }
    
    const { timeframe, startDate, endDate } = value;
    
    // Build date range
    let dateFilter = '';
    let params = [req.user.id];
    
    if (startDate && endDate) {
        dateFilter = 'AND date BETWEEN ? AND ?';
        params.push(startDate.toISOString().split('T')[0], endDate.toISOString().split('T')[0]);
    } else {
        // Default ranges based on timeframe
        const now = new Date();
        let startDateStr;
        
        switch (timeframe) {
            case 'hour':
                startDateStr = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];
                break;
            case 'day':
                startDateStr = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
                break;
            case 'week':
                startDateStr = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
                break;
            case 'month':
                startDateStr = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
                break;
            default:
                startDateStr = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
        }
        
        dateFilter = 'AND date >= ?';
        params.push(startDateStr);
    }
    
    // Get statistics
    const stats = await database.all(`
        SELECT 
            date, hour,
            SUM(queries_total) as total_queries,
            SUM(queries_blocked) as blocked_queries,
            SUM(queries_allowed) as allowed_queries
        FROM dns_stats 
        WHERE user_id = ? ${dateFilter}
        GROUP BY date, ${timeframe === 'hour' ? 'hour' : '1'}
        ORDER BY date DESC, hour DESC
        LIMIT 100
    `, params);
    
    // Get top blocked domains
    const topBlocked = await database.all(`
        SELECT domain, category, block_count, last_blocked
        FROM blocked_domains 
        WHERE is_active = 1 
        ORDER BY block_count DESC 
        LIMIT 10
    `);
    
    // Calculate totals
    const totals = stats.reduce((acc, stat) => ({
        totalQueries: acc.totalQueries + stat.total_queries,
        blockedQueries: acc.blockedQueries + stat.blocked_queries,
        allowedQueries: acc.allowedQueries + stat.allowed_queries
    }), { totalQueries: 0, blockedQueries: 0, allowedQueries: 0 });
    
    const blockRate = totals.totalQueries > 0 
        ? Math.round((totals.blockedQueries / totals.totalQueries) * 100)
        : 0;
    
    // Get blocked domains by category
    const blockedByCategory = await getBlockedDomainsByCategory();
    
    res.json({
        timeframe,
        period: {
            start: params[1] || null,
            end: params[2] || null
        },
        summary: {
            ...totals,
            blockRate,
            avgQueriesPerDay: stats.length > 0 ? Math.round(totals.totalQueries / stats.length) : 0
        },
        timeline: stats.map(stat => ({
            date: stat.date,
            hour: timeframe === 'hour' ? stat.hour : null,
            queries: {
                total: stat.total_queries,
                blocked: stat.blocked_queries,
                allowed: stat.allowed_queries,
                blockRate: stat.total_queries > 0 
                    ? Math.round((stat.blocked_queries / stat.total_queries) * 100)
                    : 0
            }
        })),
        topBlockedDomains: topBlocked.map(domain => ({
            domain: domain.domain,
            category: domain.category,
            blockCount: domain.block_count,
            lastBlocked: domain.last_blocked
        })),
        blockedByCategory
    });
}));

/**
 * POST /api/dns/block-domain
 * Add domain to custom block list
 */
router.post('/block-domain', authMiddleware, auditLog('DNS_BLOCK_DOMAIN', 'dns'), asyncErrorHandler(async (req, res) => {
    const { error, value } = blockDomainSchema.validate(req.body);
    if (error) {
        throw validationError('blockDomain', error.details[0].message);
    }
    
    const { domain, category, description } = value;
    
    try {
        // Check if domain is already blocked
        const existing = await database.get(`
            SELECT id, is_active FROM blocked_domains WHERE domain = ?
        `, [domain]);
        
        if (existing) {
            if (existing.is_active) {
                return res.status(409).json({
                    error: {
                        message: 'Domain is already blocked',
                        code: 'DOMAIN_ALREADY_BLOCKED',
                        domain
                    }
                });
            } else {
                // Reactivate previously blocked domain
                await database.run(`
                    UPDATE blocked_domains 
                    SET is_active = 1, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                `, [existing.id]);
            }
        } else {
            // Add new blocked domain
            await database.run(`
                INSERT INTO blocked_domains (domain, category, description, is_active)
                VALUES (?, ?, ?, 1)
            `, [domain, category, description]);
        }
        
        logger.dns('DOMAIN_BLOCKED', req.user.id, {
            domain,
            category,
            action: existing ? 'reactivated' : 'added'
        });
        
        res.json({
            message: 'Domain blocked successfully',
            domain: {
                name: domain,
                category,
                description,
                blockedAt: new Date().toISOString()
            }
        });
        
    } catch (error) {
        logger.dns('BLOCK_DOMAIN_FAILED', req.user.id, {
            domain,
            error: error.message
        });
        
        throw createError('Failed to block domain', 'DNS_BLOCK_ERROR', 500);
    }
}));

/**
 * POST /api/dns/unblock-domain
 * Remove domain from block list
 */
router.post('/unblock-domain', authMiddleware, auditLog('DNS_UNBLOCK_DOMAIN', 'dns'), asyncErrorHandler(async (req, res) => {
    const { error, value } = unblockDomainSchema.validate(req.body);
    if (error) {
        throw validationError('unblockDomain', error.details[0].message);
    }
    
    const { domain } = value;
    
    // Only allow unblocking custom domains (not system-wide blocks)
    const result = await database.run(`
        UPDATE blocked_domains 
        SET is_active = 0, updated_at = CURRENT_TIMESTAMP
        WHERE domain = ? AND category = 'custom'
    `, [domain]);
    
    if (result.changes === 0) {
        return res.status(404).json({
            error: {
                message: 'Domain not found in custom block list',
                code: 'DOMAIN_NOT_FOUND',
                domain
            }
        });
    }
    
    logger.dns('DOMAIN_UNBLOCKED', req.user.id, {
        domain,
        unblockedAt: new Date().toISOString()
    });
    
    res.json({
        message: 'Domain unblocked successfully',
        domain: {
            name: domain,
            unblockedAt: new Date().toISOString()
        }
    });
}));

/**
 * GET /api/dns/blocked-domains
 * Get list of blocked domains
 */
router.get('/blocked-domains', authMiddleware, asyncErrorHandler(async (req, res) => {
    const category = req.query.category;
    const customOnly = req.query.customOnly === 'true';
    
    let whereClause = 'WHERE is_active = 1';
    let params = [];
    
    if (category) {
        whereClause += ' AND category = ?';
        params.push(category);
    }
    
    if (customOnly) {
        whereClause += ' AND category = ?';
        params.push('custom');
    }
    
    const domains = await database.all(`
        SELECT domain, category, description, block_count, 
               last_blocked, created_at, updated_at
        FROM blocked_domains 
        ${whereClause}
        ORDER BY category, block_count DESC, domain ASC
    `, params);
    
    // Group by category
    const grouped = domains.reduce((acc, domain) => {
        if (!acc[domain.category]) {
            acc[domain.category] = [];
        }
        acc[domain.category].push({
            domain: domain.domain,
            description: domain.description,
            blockCount: domain.block_count,
            lastBlocked: domain.last_blocked,
            createdAt: domain.created_at,
            updatedAt: domain.updated_at
        });
        return acc;
    }, {});
    
    res.json({
        domains: grouped,
        totalDomains: domains.length,
        categories: Object.keys(grouped),
        summary: {
            ads: grouped.ads?.length || 0,
            tracking: grouped.tracking?.length || 0,
            malware: grouped.malware?.length || 0,
            adult: grouped.adult?.length || 0,
            gambling: grouped.gambling?.length || 0,
            custom: grouped.custom?.length || 0
        }
    });
}));

// Add this table creation to database.js if not exists
const ensureDNSConfigTable = async () => {
    try {
        await database.run(`
            CREATE TABLE IF NOT EXISTS user_dns_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                enabled BOOLEAN DEFAULT 0,
                servers TEXT, -- JSON array of DNS servers
                filtering_settings TEXT, -- JSON object of filtering preferences
                custom_domains TEXT, -- JSON array of custom blocked domains
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                UNIQUE(user_id)
            )
        `);
    } catch (error) {
        logger.warn('DNS config table creation ignored:', error.message);
    }
};

// Initialize DNS config table
ensureDNSConfigTable();

module.exports = router;
