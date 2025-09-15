const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');
const database = require('../config/database');

/**
 * JWT Authentication Middleware
 * Validates JWT tokens and attaches user info to request
 */
const authMiddleware = async (req, res, next) => {
    try {
        // Extract token from Authorization header
        const authHeader = req.header('Authorization');
        const token = authHeader?.replace('Bearer ', '');
        
        if (!token) {
            logger.auth('TOKEN_MISSING', null, false, { 
                ip: req.ip, 
                userAgent: req.get('User-Agent'),
                endpoint: req.originalUrl 
            });
            
            return res.status(401).json({ 
                error: 'Access denied. No token provided.',
                code: 'NO_TOKEN'
            });
        }

        // Verify JWT token
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (jwtError) {
            let errorCode = 'INVALID_TOKEN';
            let errorMessage = 'Invalid token';
            
            if (jwtError.name === 'TokenExpiredError') {
                errorCode = 'TOKEN_EXPIRED';
                errorMessage = 'Token has expired';
            } else if (jwtError.name === 'JsonWebTokenError') {
                errorCode = 'MALFORMED_TOKEN';
                errorMessage = 'Malformed token';
            }
            
            logger.auth('TOKEN_INVALID', decoded?.userId || null, false, { 
                error: jwtError.message,
                tokenType: jwtError.name,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                endpoint: req.originalUrl
            });
            
            return res.status(401).json({ 
                error: errorMessage,
                code: errorCode
            });
        }

        // Validate token payload
        if (!decoded.userId || !decoded.email) {
            logger.auth('TOKEN_INVALID_PAYLOAD', decoded.userId || null, false, { 
                payload: decoded,
                ip: req.ip 
            });
            
            return res.status(401).json({ 
                error: 'Invalid token payload',
                code: 'INVALID_PAYLOAD'
            });
        }

        // Get user from database to verify they still exist and are active
        const user = await database.get(
            'SELECT id, username, email, is_active, subscription_type, device_id FROM users WHERE id = ?',
            [decoded.userId]
        );

        if (!user) {
            logger.auth('USER_NOT_FOUND', decoded.userId, false, { 
                tokenUserId: decoded.userId,
                ip: req.ip 
            });
            
            return res.status(401).json({ 
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        if (!user.is_active) {
            logger.auth('USER_INACTIVE', user.id, false, { 
                username: user.username,
                ip: req.ip 
            });
            
            return res.status(401).json({ 
                error: 'Account is disabled',
                code: 'ACCOUNT_DISABLED'
            });
        }

        // Check device_id if present in token (for device binding)
        if (decoded.deviceId && user.device_id && decoded.deviceId !== user.device_id) {
            logger.security('DEVICE_MISMATCH', 'medium', {
                userId: user.id,
                tokenDeviceId: decoded.deviceId,
                userDeviceId: user.device_id,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
            
            return res.status(401).json({ 
                error: 'Token is bound to a different device',
                code: 'DEVICE_MISMATCH'
            });
        }

        // Update last login timestamp
        try {
            await database.run(
                'UPDATE users SET last_login_at = CURRENT_TIMESTAMP, last_ip = ? WHERE id = ?',
                [req.ip, user.id]
            );
        } catch (updateError) {
            logger.warn('Failed to update last login info:', updateError);
            // Non-critical error, don't fail the auth
        }

        // Attach user info to request object
        req.user = {
            id: user.id,
            username: user.username,
            email: user.email,
            subscriptionType: user.subscription_type,
            deviceId: user.device_id,
            isActive: user.is_active,
            tokenIat: decoded.iat,
            tokenExp: decoded.exp
        };

        // Log successful authentication
        logger.auth('TOKEN_VALID', user.id, true, { 
            username: user.username,
            ip: req.ip,
            endpoint: req.originalUrl
        });

        next();

    } catch (error) {
        logger.error('Auth middleware error:', error);
        
        // Log security event for unexpected errors
        logger.security('AUTH_MIDDLEWARE_ERROR', 'high', {
            error: error.message,
            stack: error.stack,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            endpoint: req.originalUrl
        });
        
        res.status(500).json({ 
            error: 'Internal server error during authentication',
            code: 'AUTH_ERROR'
        });
    }
};

/**
 * Optional Authentication Middleware
 * Validates token if present, but doesn't fail if missing
 */
const optionalAuthMiddleware = async (req, res, next) => {
    const authHeader = req.header('Authorization');
    const token = authHeader?.replace('Bearer ', '');
    
    if (!token) {
        // No token provided, continue without user info
        req.user = null;
        return next();
    }

    // If token is provided, validate it
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await database.get(
            'SELECT id, username, email, is_active, subscription_type FROM users WHERE id = ? AND is_active = 1',
            [decoded.userId]
        );

        if (user) {
            req.user = {
                id: user.id,
                username: user.username,
                email: user.email,
                subscriptionType: user.subscription_type,
                isActive: user.is_active
            };
        } else {
            req.user = null;
        }
    } catch (error) {
        // Invalid token, but since it's optional, just continue without user
        req.user = null;
        logger.auth('OPTIONAL_TOKEN_INVALID', null, false, { 
            error: error.message,
            ip: req.ip 
        });
    }

    next();
};

/**
 * Role-based authorization middleware
 * Checks if user has required subscription level
 */
const requireSubscription = (requiredType = 'premium') => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ 
                error: 'Authentication required',
                code: 'AUTH_REQUIRED'
            });
        }

        const subscriptionLevels = {
            'free': 0,
            'premium': 1,
            'enterprise': 2
        };

        const userLevel = subscriptionLevels[req.user.subscriptionType] || 0;
        const requiredLevel = subscriptionLevels[requiredType] || 0;

        if (userLevel < requiredLevel) {
            logger.auth('INSUFFICIENT_SUBSCRIPTION', req.user.id, false, {
                userSubscription: req.user.subscriptionType,
                requiredSubscription: requiredType,
                endpoint: req.originalUrl
            });

            return res.status(403).json({ 
                error: `${requiredType} subscription required`,
                code: 'INSUFFICIENT_SUBSCRIPTION',
                userSubscription: req.user.subscriptionType,
                requiredSubscription: requiredType
            });
        }

        next();
    };
};

/**
 * Device validation middleware
 * Ensures requests come from registered device
 */
const requireRegisteredDevice = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({ 
                error: 'Authentication required',
                code: 'AUTH_REQUIRED'
            });
        }

        const deviceId = req.header('X-Device-ID') || req.user.deviceId;
        
        if (!deviceId) {
            return res.status(400).json({ 
                error: 'Device ID required',
                code: 'DEVICE_ID_REQUIRED'
            });
        }

        // Check if device is registered to this user
        const user = await database.get(
            'SELECT device_id FROM users WHERE id = ?',
            [req.user.id]
        );

        if (!user.device_id) {
            // First time device registration
            await database.run(
                'UPDATE users SET device_id = ? WHERE id = ?',
                [deviceId, req.user.id]
            );
            
            logger.auth('DEVICE_REGISTERED', req.user.id, true, { 
                deviceId: deviceId,
                ip: req.ip 
            });
            
            req.user.deviceId = deviceId;
        } else if (user.device_id !== deviceId) {
            logger.security('UNAUTHORIZED_DEVICE', 'high', {
                userId: req.user.id,
                registeredDevice: user.device_id,
                requestDevice: deviceId,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });

            return res.status(403).json({ 
                error: 'Device not authorized',
                code: 'DEVICE_NOT_AUTHORIZED'
            });
        }

        next();

    } catch (error) {
        logger.error('Device validation error:', error);
        res.status(500).json({ 
            error: 'Device validation failed',
            code: 'DEVICE_VALIDATION_ERROR'
        });
    }
};

/**
 * Rate limiting by user
 * Additional rate limiting based on user subscription
 */
const userRateLimit = (req, res, next) => {
    if (!req.user) {
        return next();
    }

    // Set rate limits based on subscription
    const limits = {
        'free': 50,      // 50 requests per 15 minutes
        'premium': 200,  // 200 requests per 15 minutes
        'enterprise': 1000 // 1000 requests per 15 minutes
    };

    const userLimit = limits[req.user.subscriptionType] || limits.free;
    
    // Add user-specific rate limit info to request
    req.userRateLimit = {
        max: userLimit,
        subscription: req.user.subscriptionType
    };

    next();
};

/**
 * Audit logging middleware
 * Logs important user actions
 */
const auditLog = (action, resourceType = null) => {
    return async (req, res, next) => {
        // Store original res.json to intercept response
        const originalJson = res.json;
        
        res.json = function(data) {
            // Log after response is sent
            setImmediate(async () => {
                try {
                    const success = res.statusCode < 400;
                    const details = {
                        method: req.method,
                        url: req.originalUrl,
                        statusCode: res.statusCode,
                        body: success ? null : data,
                        params: req.params,
                        query: req.query
                    };

                    await database.run(`
                        INSERT INTO audit_logs (
                            user_id, action, resource_type, resource_id, 
                            details, ip_address, user_agent, success, 
                            error_message
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    `, [
                        req.user?.id || null,
                        action,
                        resourceType,
                        req.params?.id || null,
                        JSON.stringify(details),
                        req.ip,
                        req.get('User-Agent'),
                        success ? 1 : 0,
                        success ? null : (data?.error || 'Unknown error')
                    ]);

                } catch (error) {
                    logger.error('Audit log error:', error);
                }
            });

            // Call original json method
            return originalJson.call(this, data);
        };

        next();
    };
};

module.exports = {
    authMiddleware,
    optionalAuthMiddleware,
    requireSubscription,
    requireRegisteredDevice,
    userRateLimit,
    auditLog
};
