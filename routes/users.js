const express = require('express');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const database = require('../config/database');
const logger = require('../utils/logger');
const { authMiddleware, requireSubscription, auditLog } = require('../middleware/auth');
const { asyncErrorHandler, validationError, createError, authError } = require('../middleware/errorHandler');

const router = express.Router();

// Validation schemas
const updateProfileSchema = Joi.object({
    username: Joi.string()
        .alphanum()
        .min(3)
        .max(30)
        .optional()
        .messages({
            'string.alphanum': 'Username must contain only alphanumeric characters',
            'string.min': 'Username must be at least 3 characters long',
            'string.max': 'Username must be less than 30 characters long'
        }),
    
    deviceName: Joi.string()
        .max(100)
        .optional(),
    
    deviceModel: Joi.string()
        .max(100)
        .optional()
});

const updateSubscriptionSchema = Joi.object({
    subscriptionType: Joi.string()
        .valid('free', 'premium', 'enterprise')
        .required()
        .messages({
            'any.only': 'Subscription type must be free, premium, or enterprise',
            'any.required': 'Subscription type is required'
        }),
    
    paymentMethod: Joi.string()
        .valid('card', 'paypal', 'crypto', 'admin')
        .optional(),
    
    transactionId: Joi.string()
        .max(255)
        .optional()
});

const updatePreferencesSchema = Joi.object({
    autoConnect: Joi.boolean().optional(),
    
    preferredCountry: Joi.string()
        .length(2)
        .uppercase()
        .optional(),
    
    preferredServer: Joi.string()
        .valid('auto', 'fastest', 'specific')
        .optional(),
    
    dnsFiltering: Joi.object({
        enabled: Joi.boolean().default(true),
        blockAds: Joi.boolean().default(true),
        blockTracking: Joi.boolean().default(true),
        blockMalware: Joi.boolean().default(true),
        blockAdult: Joi.boolean().default(false),
        blockGambling: Joi.boolean().default(false)
    }).optional(),
    
    notifications: Joi.object({
        email: Joi.boolean().default(true),
        push: Joi.boolean().default(true),
        security: Joi.boolean().default(true),
        marketing: Joi.boolean().default(false)
    }).optional()
});

const deleteAccountSchema = Joi.object({
    password: Joi.string()
        .required()
        .messages({
            'any.required': 'Password confirmation is required to delete account'
        }),
    
    reason: Joi.string()
        .max(500)
        .optional(),
    
    feedback: Joi.string()
        .max(1000)
        .optional()
});

// Helper function to get subscription limits
const getSubscriptionLimits = (subscriptionType) => {
    const limits = {
        free: {
            maxConnections: 1,
            bytesLimit: 10 * 1024 * 1024 * 1024, // 10 GB
            countries: ['ES'], // Only Spain
            features: ['basic-vpn', 'basic-dns']
        },
        premium: {
            maxConnections: 3,
            bytesLimit: 100 * 1024 * 1024 * 1024, // 100 GB
            countries: ['ES', 'US', 'GB', 'FR', 'DE'], // Top 5 countries
            features: ['advanced-vpn', 'advanced-dns', 'custom-dns', 'statistics']
        },
        enterprise: {
            maxConnections: 10,
            bytesLimit: 1000 * 1024 * 1024 * 1024, // 1000 GB
            countries: ['ES', 'US', 'GB', 'FR', 'DE', 'NL', 'CH', 'CA', 'JP', 'AU', 'SG', 'BR', 'IN', 'SE', 'NO'], // All countries
            features: ['enterprise-vpn', 'enterprise-dns', 'api-access', 'priority-support', 'custom-rules']
        }
    };
    
    return limits[subscriptionType] || limits.free;
};

/**
 * GET /api/users/profile
 * Get detailed user profile with usage statistics
 */
router.get('/profile', authMiddleware, asyncErrorHandler(async (req, res) => {
    // Get user details
    const user = await database.get(`
        SELECT 
            id, username, email, device_id, device_name, device_model,
            subscription_type, subscription_expires_at, max_connections,
            bytes_used, bytes_limit, last_login_at, created_at,
            email_verified, is_active
        FROM users 
        WHERE id = ?
    `, [req.user.id]);
    
    if (!user) {
        throw authError('User not found', 'USER_NOT_FOUND');
    }
    
    // Get connection statistics
    const connectionStats = await database.get(`
        SELECT 
            COUNT(*) as total_connections,
            COUNT(CASE WHEN status = 'connected' THEN 1 END) as active_connections,
            SUM(bytes_sent + bytes_received) as total_bytes_transferred,
            SUM(duration_seconds) as total_connection_time,
            MAX(connected_at) as last_connection,
            AVG(duration_seconds) as avg_session_duration
        FROM vpn_connections 
        WHERE user_id = ?
    `, [req.user.id]);
    
    // Get DNS statistics
    const dnsStats = await database.get(`
        SELECT 
            SUM(queries_total) as total_dns_queries,
            SUM(queries_blocked) as total_blocked_queries,
            SUM(queries_allowed) as total_allowed_queries
        FROM dns_stats 
        WHERE user_id = ?
    `, [req.user.id]);
    
    // Get subscription limits
    const subscriptionLimits = getSubscriptionLimits(user.subscription_type);
    
    // Get user preferences
    const preferences = await database.get(`
        SELECT preferences FROM user_preferences WHERE user_id = ?
    `, [req.user.id]);
    
    const userPreferences = preferences ? JSON.parse(preferences.preferences) : {
        autoConnect: false,
        preferredCountry: 'ES',
        preferredServer: 'auto',
        dnsFiltering: {
            enabled: true,
            blockAds: true,
            blockTracking: true,
            blockMalware: true,
            blockAdult: false,
            blockGambling: false
        },
        notifications: {
            email: true,
            push: true,
            security: true,
            marketing: false
        }
    };
    
    res.json({
        user: {
            id: user.id,
            username: user.username,
            email: user.email,
            device: {
                id: user.device_id,
                name: user.device_name,
                model: user.device_model
            },
            account: {
                emailVerified: user.email_verified === 1,
                isActive: user.is_active === 1,
                lastLogin: user.last_login_at,
                createdAt: user.created_at
            },
            subscription: {
                type: user.subscription_type,
                expiresAt: user.subscription_expires_at,
                limits: subscriptionLimits,
                current: {
                    maxConnections: user.max_connections,
                    bytesLimit: user.bytes_limit,
                    bytesUsed: user.bytes_used,
                    usagePercentage: Math.round((user.bytes_used / user.bytes_limit) * 100)
                }
            },
            preferences: userPreferences
        },
        statistics: {
            connections: {
                total: connectionStats?.total_connections || 0,
                active: connectionStats?.active_connections || 0,
                totalBytesTransferred: connectionStats?.total_bytes_transferred || 0,
                totalConnectionTime: connectionStats?.total_connection_time || 0,
                avgSessionDuration: connectionStats?.avg_session_duration || 0,
                lastConnection: connectionStats?.last_connection
            },
            dns: {
                totalQueries: dnsStats?.total_dns_queries || 0,
                blockedQueries: dnsStats?.total_blocked_queries || 0,
                allowedQueries: dnsStats?.total_allowed_queries || 0,
                blockRate: dnsStats?.total_dns_queries > 0 
                    ? Math.round((dnsStats.total_blocked_queries / dnsStats.total_dns_queries) * 100)
                    : 0
            }
        }
    });
}));

/**
 * PUT /api/users/profile
 * Update user profile information
 */
router.put('/profile', authMiddleware, auditLog('UPDATE_PROFILE', 'user'), asyncErrorHandler(async (req, res) => {
    // Validate request
    const { error, value } = updateProfileSchema.validate(req.body);
    if (error) {
        throw validationError('updateProfile', error.details[0].message);
    }
    
    const { username, deviceName, deviceModel } = value;
    const updates = {};
    const params = [];
    
    // Build dynamic update query
    if (username) {
        // Check if username is already taken
        const existingUser = await database.get(
            'SELECT id FROM users WHERE username = ? AND id != ?',
            [username, req.user.id]
        );
        
        if (existingUser) {
            throw createError('Username is already taken', 'USERNAME_TAKEN', 409);
        }
        
        updates.username = '?';
        params.push(username);
    }
    
    if (deviceName !== undefined) {
        updates.device_name = '?';
        params.push(deviceName);
    }
    
    if (deviceModel !== undefined) {
        updates.device_model = '?';
        params.push(deviceModel);
    }
    
    if (Object.keys(updates).length === 0) {
        return res.json({
            message: 'No changes to update',
            user: { id: req.user.id }
        });
    }
    
    // Add updated timestamp
    updates.updated_at = 'CURRENT_TIMESTAMP';
    params.push(req.user.id);
    
    // Build and execute update query
    const setClause = Object.entries(updates)
        .map(([key, value]) => `${key} = ${value}`)
        .join(', ');
    
    await database.run(
        `UPDATE users SET ${setClause} WHERE id = ?`,
        params
    );
    
    // Get updated user data
    const updatedUser = await database.get(
        'SELECT username, device_name, device_model, updated_at FROM users WHERE id = ?',
        [req.user.id]
    );
    
    logger.auth('PROFILE_UPDATED', req.user.id, true, {
        updatedFields: Object.keys(updates).filter(key => key !== 'updated_at'),
        username: updatedUser.username
    });
    
    res.json({
        message: 'Profile updated successfully',
        user: {
            id: req.user.id,
            username: updatedUser.username,
            device: {
                name: updatedUser.device_name,
                model: updatedUser.device_model
            },
            updatedAt: updatedUser.updated_at
        }
    });
}));

/**
 * PUT /api/users/subscription
 * Update user subscription (admin only or payment verification)
 */
router.put('/subscription', authMiddleware, auditLog('UPDATE_SUBSCRIPTION', 'user'), asyncErrorHandler(async (req, res) => {
    // Validate request
    const { error, value } = updateSubscriptionSchema.validate(req.body);
    if (error) {
        throw validationError('updateSubscription', error.details[0].message);
    }
    
    const { subscriptionType, paymentMethod, transactionId } = value;
    
    // For now, allow subscription updates (in production, verify payment)
    // TODO: Integrate with payment processor (Stripe, PayPal, etc.)
    
    const currentUser = await database.get(
        'SELECT subscription_type FROM users WHERE id = ?',
        [req.user.id]
    );
    
    if (currentUser.subscription_type === subscriptionType) {
        return res.json({
            message: 'Subscription is already at this level',
            subscription: { type: subscriptionType }
        });
    }
    
    // Get new subscription limits
    const newLimits = getSubscriptionLimits(subscriptionType);
    
    // Calculate expiration date (1 year from now for paid subscriptions)
    let expiresAt = null;
    if (subscriptionType !== 'free') {
        const expiration = new Date();
        expiration.setFullYear(expiration.getFullYear() + 1);
        expiresAt = expiration.toISOString();
    }
    
    // Update subscription
    await database.run(`
        UPDATE users 
        SET subscription_type = ?, 
            subscription_expires_at = ?,
            max_connections = ?,
            bytes_limit = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `, [
        subscriptionType,
        expiresAt,
        newLimits.maxConnections,
        newLimits.bytesLimit,
        req.user.id
    ]);
    
    // Log subscription change
    logger.auth('SUBSCRIPTION_UPDATED', req.user.id, true, {
        oldSubscription: currentUser.subscription_type,
        newSubscription: subscriptionType,
        paymentMethod,
        transactionId,
        expiresAt
    });
    
    res.json({
        message: 'Subscription updated successfully',
        subscription: {
            type: subscriptionType,
            expiresAt,
            limits: newLimits,
            paymentMethod,
            transactionId,
            updatedAt: new Date().toISOString()
        }
    });
}));

/**
 * PUT /api/users/preferences
 * Update user preferences
 */
router.put('/preferences', authMiddleware, auditLog('UPDATE_PREFERENCES', 'user'), asyncErrorHandler(async (req, res) => {
    // Validate request
    const { error, value } = updatePreferencesSchema.validate(req.body);
    if (error) {
        throw validationError('updatePreferences', error.details[0].message);
    }
    
    // Get current preferences
    const current = await database.get(
        'SELECT preferences FROM user_preferences WHERE user_id = ?',
        [req.user.id]
    );
    
    const currentPreferences = current ? JSON.parse(current.preferences) : {};
    
    // Merge with new preferences
    const updatedPreferences = {
        ...currentPreferences,
        ...value
    };
    
    // Save preferences
    if (current) {
        await database.run(
            'UPDATE user_preferences SET preferences = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?',
            [JSON.stringify(updatedPreferences), req.user.id]
        );
    } else {
        await database.run(
            'INSERT INTO user_preferences (user_id, preferences) VALUES (?, ?)',
            [req.user.id, JSON.stringify(updatedPreferences)]
        );
    }
    
    logger.auth('PREFERENCES_UPDATED', req.user.id, true, {
        updatedFields: Object.keys(value)
    });
    
    res.json({
        message: 'Preferences updated successfully',
        preferences: updatedPreferences,
        updatedAt: new Date().toISOString()
    });
}));

/**
 * GET /api/users/usage
 * Get detailed usage statistics
 */
router.get('/usage', authMiddleware, asyncErrorHandler(async (req, res) => {
    const timeframe = req.query.timeframe || 'month'; // day, week, month, year
    
    // Calculate date range
    const now = new Date();
    let startDate;
    
    switch (timeframe) {
        case 'day':
            startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
            break;
        case 'week':
            startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
            break;
        case 'month':
            startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
            break;
        case 'year':
            startDate = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);
            break;
        default:
            startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    }
    
    // Get VPN usage
    const vpnUsage = await database.all(`
        SELECT 
            DATE(connected_at) as date,
            COUNT(*) as connections,
            SUM(duration_seconds) as total_duration,
            SUM(bytes_sent + bytes_received) as total_bytes,
            country_code
        FROM vpn_connections 
        WHERE user_id = ? AND connected_at >= ?
        GROUP BY DATE(connected_at), country_code
        ORDER BY date DESC
    `, [req.user.id, startDate.toISOString()]);
    
    // Get DNS usage
    const dnsUsage = await database.all(`
        SELECT 
            date,
            SUM(queries_total) as total_queries,
            SUM(queries_blocked) as blocked_queries,
            SUM(queries_allowed) as allowed_queries
        FROM dns_stats 
        WHERE user_id = ? AND date >= ?
        GROUP BY date
        ORDER BY date DESC
    `, [req.user.id, startDate.toISOString().split('T')[0]]);
    
    // Get current subscription info
    const user = await database.get(
        'SELECT subscription_type, bytes_used, bytes_limit FROM users WHERE id = ?',
        [req.user.id]
    );
    
    // Calculate totals
    const totals = {
        vpn: {
            connections: vpnUsage.reduce((sum, day) => sum + day.connections, 0),
            duration: vpnUsage.reduce((sum, day) => sum + (day.total_duration || 0), 0),
            bytes: vpnUsage.reduce((sum, day) => sum + (day.total_bytes || 0), 0)
        },
        dns: {
            queries: dnsUsage.reduce((sum, day) => sum + day.total_queries, 0),
            blocked: dnsUsage.reduce((sum, day) => sum + day.blocked_queries, 0),
            allowed: dnsUsage.reduce((sum, day) => sum + day.allowed_queries, 0)
        }
    };
    
    // Group VPN usage by country
    const vpnByCountry = vpnUsage.reduce((acc, record) => {
        if (!acc[record.country_code]) {
            acc[record.country_code] = {
                connections: 0,
                duration: 0,
                bytes: 0
            };
        }
        acc[record.country_code].connections += record.connections;
        acc[record.country_code].duration += record.total_duration || 0;
        acc[record.country_code].bytes += record.total_bytes || 0;
        return acc;
    }, {});
    
    res.json({
        timeframe,
        period: {
            start: startDate.toISOString(),
            end: now.toISOString()
        },
        totals,
        subscription: {
            type: user.subscription_type,
            bytesUsed: user.bytes_used,
            bytesLimit: user.bytes_limit,
            usagePercentage: Math.round((user.bytes_used / user.bytes_limit) * 100)
        },
        vpn: {
            daily: vpnUsage,
            byCountry: vpnByCountry
        },
        dns: {
            daily: dnsUsage,
            blockRate: totals.dns.queries > 0 
                ? Math.round((totals.dns.blocked / totals.dns.queries) * 100)
                : 0
        }
    });
}));

/**
 * DELETE /api/users/account
 * Delete user account (requires password confirmation)
 */
router.delete('/account', authMiddleware, auditLog('DELETE_ACCOUNT', 'user'), asyncErrorHandler(async (req, res) => {
    // Validate request
    const { error, value } = deleteAccountSchema.validate(req.body);
    if (error) {
        throw validationError('deleteAccount', error.details[0].message);
    }
    
    const { password, reason, feedback } = value;
    
    // Verify password
    const user = await database.get(
        'SELECT password_hash FROM users WHERE id = ?',
        [req.user.id]
    );
    
    const passwordValid = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordValid) {
        logger.security('DELETE_ACCOUNT_INVALID_PASSWORD', 'high', {
            userId: req.user.id,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });
        
        throw authError('Invalid password', 'INVALID_PASSWORD');
    }
    
    try {
        // Start transaction-like cleanup
        
        // 1. Disconnect any active VPN connections
        await database.run(
            'UPDATE vpn_connections SET status = ?, disconnected_at = CURRENT_TIMESTAMP WHERE user_id = ? AND status = ?',
            ['disconnected', req.user.id, 'connected']
        );
        
        // 2. Disable DNS filtering
        await database.run(
            'UPDATE user_dns_config SET enabled = 0 WHERE user_id = ?',
            [req.user.id]
        );
        
        // 3. Log account deletion reason
        if (reason || feedback) {
            await database.run(`
                INSERT INTO user_feedback (
                    user_id, type, reason, feedback, created_at
                ) VALUES (?, 'account_deletion', ?, ?, CURRENT_TIMESTAMP)
            `, [req.user.id, reason, feedback]);
        }
        
        // 4. Mark user as inactive instead of deleting (for audit purposes)
        await database.run(`
            UPDATE users 
            SET is_active = 0, 
                email = CONCAT('deleted_', id, '_', email),
                username = CONCAT('deleted_', id, '_', username),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `, [req.user.id]);
        
        logger.auth('ACCOUNT_DELETED', req.user.id, true, {
            reason,
            hasFeedback: !!feedback,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });
        
        res.json({
            message: 'Account deleted successfully',
            deletedAt: new Date().toISOString(),
            note: 'Thank you for using NuboLink. Your data has been securely removed.'
        });
        
    } catch (error) {
        logger.error('Account deletion failed:', error);
        throw createError('Failed to delete account', 'DELETION_FAILED', 500);
    }
}));

// Ensure user preferences table exists
const ensureUserPreferencesTable = async () => {
    try {
        await database.run(`
            CREATE TABLE IF NOT EXISTS user_preferences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                preferences TEXT, -- JSON object
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                UNIQUE(user_id)
            )
        `);
        
        await database.run(`
            CREATE TABLE IF NOT EXISTS user_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                type TEXT NOT NULL, -- account_deletion, bug_report, feature_request
                reason TEXT,
                feedback TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        `);
    } catch (error) {
        logger.warn('User tables creation ignored:', error.message);
    }
};

// Initialize tables
ensureUserPreferencesTable();

module.exports = router;
