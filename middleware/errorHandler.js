const logger = require('../utils/logger');

/**
 * Global Error Handler Middleware
 * Catches and handles all application errors
 */
const errorHandler = (err, req, res, next) => {
    // If response was already sent, delegate to default Express error handler
    if (res.headersSent) {
        return next(err);
    }

    // Log the error with context
    logger.logError(err, {
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user?.id || null,
        params: req.params,
        query: req.query,
        body: req.method !== 'GET' ? req.body : undefined
    });

    // Default error response
    let error = {
        message: err.message || 'Internal Server Error',
        code: err.code || 'INTERNAL_ERROR',
        timestamp: new Date().toISOString()
    };

    let statusCode = err.status || err.statusCode || 500;

    // Handle specific error types
    if (err.name === 'ValidationError') {
        // Joi validation errors
        statusCode = 400;
        error.code = 'VALIDATION_ERROR';
        error.message = 'Validation failed';
        
        if (err.details && Array.isArray(err.details)) {
            error.details = err.details.map(detail => ({
                field: detail.path?.join('.') || detail.context?.key,
                message: detail.message,
                value: detail.context?.value
            }));
        }
        
        logger.auth('VALIDATION_ERROR', req.user?.id || null, false, {
            validationErrors: error.details,
            endpoint: req.originalUrl
        });
    }
    
    else if (err.name === 'JsonWebTokenError') {
        // JWT errors
        statusCode = 401;
        error.code = 'INVALID_TOKEN';
        error.message = 'Invalid authentication token';
        
        logger.security('JWT_ERROR', 'medium', {
            jwtError: err.message,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            endpoint: req.originalUrl
        });
    }
    
    else if (err.name === 'TokenExpiredError') {
        // JWT token expired
        statusCode = 401;
        error.code = 'TOKEN_EXPIRED';
        error.message = 'Authentication token has expired';
        
        logger.auth('TOKEN_EXPIRED', req.user?.id || null, false, {
            expiredAt: err.expiredAt,
            endpoint: req.originalUrl
        });
    }
    
    else if (err.code && err.code.startsWith('SQLITE_')) {
        // SQLite database errors
        statusCode = 500;
        error.code = 'DATABASE_ERROR';
        
        if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            statusCode = 409;
            error.code = 'DUPLICATE_ENTRY';
            error.message = 'A record with this information already exists';
        } else if (err.code === 'SQLITE_CONSTRAINT_FOREIGNKEY') {
            statusCode = 400;
            error.code = 'INVALID_REFERENCE';
            error.message = 'Referenced record does not exist';
        } else if (err.code === 'SQLITE_CONSTRAINT') {
            statusCode = 400;
            error.code = 'CONSTRAINT_VIOLATION';
            error.message = 'Database constraint violation';
        } else {
            error.message = 'Database operation failed';
        }
        
        logger.database('ERROR', 'unknown', 0, false, {
            sqliteCode: err.code,
            sqliteMessage: err.message,
            endpoint: req.originalUrl
        });
    }
    
    else if (err.code === 'ECONNREFUSED') {
        // Connection refused (e.g., Mikrotik server down)
        statusCode = 503;
        error.code = 'SERVICE_UNAVAILABLE';
        error.message = 'External service temporarily unavailable';
        
        logger.error('Connection refused error:', {
            target: err.address + ':' + err.port,
            endpoint: req.originalUrl
        });
    }
    
    else if (err.code === 'ENOTFOUND') {
        // DNS resolution failed
        statusCode = 503;
        error.code = 'SERVICE_UNAVAILABLE';
        error.message = 'External service not reachable';
        
        logger.error('DNS resolution failed:', {
            hostname: err.hostname,
            endpoint: req.originalUrl
        });
    }
    
    else if (err.code === 'ETIMEDOUT') {
        // Request timeout
        statusCode = 504;
        error.code = 'TIMEOUT';
        error.message = 'Request timeout';
        
        logger.performance('TIMEOUT', 0, {
            endpoint: req.originalUrl,
            timeout: err.timeout || 'unknown'
        });
    }
    
    else if (err.type === 'entity.parse.failed') {
        // JSON parsing error
        statusCode = 400;
        error.code = 'INVALID_JSON';
        error.message = 'Invalid JSON in request body';
    }
    
    else if (err.type === 'entity.too.large') {
        // Request too large
        statusCode = 413;
        error.code = 'PAYLOAD_TOO_LARGE';
        error.message = 'Request payload too large';
    }
    
    else if (err.code === 'EBADCSRFTOKEN') {
        // CSRF token error
        statusCode = 403;
        error.code = 'INVALID_CSRF_TOKEN';
        error.message = 'Invalid CSRF token';
        
        logger.security('CSRF_TOKEN_ERROR', 'high', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            endpoint: req.originalUrl
        });
    }
    
    else if (err.status === 429) {
        // Rate limiting error
        statusCode = 429;
        error.code = 'RATE_LIMIT_EXCEEDED';
        error.message = 'Too many requests, please try again later';
        error.retryAfter = err.retryAfter || 900; // 15 minutes default
        
        logger.security('RATE_LIMIT_EXCEEDED', 'medium', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            endpoint: req.originalUrl,
            retryAfter: error.retryAfter
        });
    }
    
    else if (err.code === 'VPN_CONFIG_ERROR') {
        // Custom VPN configuration errors
        statusCode = 400;
        error.code = 'VPN_CONFIG_ERROR';
        error.message = err.message || 'VPN configuration error';
        
        logger.vpn('CONFIG_ERROR', req.user?.id || null, 'unknown', {
            error: err.message,
            endpoint: req.originalUrl
        });
    }
    
    else if (err.code === 'MIKROTIK_ERROR') {
        // Custom Mikrotik errors
        statusCode = 503;
        error.code = 'MIKROTIK_ERROR';
        error.message = 'Router communication error';
        
        logger.mikrotik('unknown', 'ERROR', false, {
            error: err.message,
            endpoint: req.originalUrl
        });
    }
    
    else if (err.code === 'DNS_CONFIG_ERROR') {
        // Custom DNS configuration errors
        statusCode = 400;
        error.code = 'DNS_CONFIG_ERROR';
        error.message = err.message || 'DNS configuration error';
        
        logger.dns('CONFIG_ERROR', req.user?.id || null, {
            error: err.message,
            endpoint: req.originalUrl
        });
    }

    // Handle specific HTTP errors
    else if (statusCode === 404) {
        error.code = 'NOT_FOUND';
        error.message = 'Resource not found';
    }
    
    else if (statusCode === 403) {
        error.code = 'FORBIDDEN';
        error.message = 'Access forbidden';
    }
    
    else if (statusCode === 401) {
        error.code = 'UNAUTHORIZED';
        error.message = 'Authentication required';
    }

    // Include stack trace in development
    if (process.env.NODE_ENV === 'development') {
        error.stack = err.stack;
        error.details = {
            name: err.name,
            code: err.code,
            status: err.status,
            path: req.path,
            method: req.method
        };
    }

    // Add request ID if available
    if (req.id) {
        error.requestId = req.id;
    }

    // Add user context if available
    if (req.user) {
        error.userId = req.user.id;
    }

    // Log security events for certain error types
    if (statusCode >= 400 && statusCode < 500) {
        const severity = statusCode === 401 || statusCode === 403 ? 'high' : 'medium';
        
        logger.security('HTTP_ERROR', severity, {
            statusCode,
            errorCode: error.code,
            userId: req.user?.id || null,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            endpoint: req.originalUrl,
            method: req.method
        });
    }

    // Send error response
    res.status(statusCode).json({ error });
};

/**
 * 404 Not Found Handler
 * Handles requests to non-existent endpoints
 */
const notFoundHandler = (req, res, next) => {
    const error = new Error(`Cannot ${req.method} ${req.originalUrl}`);
    error.status = 404;
    error.code = 'ENDPOINT_NOT_FOUND';
    
    logger.api(req.method, req.originalUrl, 404, 0, req.get('User-Agent'));
    
    // Log suspicious 404s (potential scanning)
    const suspiciousPatterns = [
        /admin/i, /wp-/i, /phpmyadmin/i, /.php$/i, 
        /config/i, /backup/i, /test/i, /dev/i,
        /api\/v[0-9]+/i, /\.env/i, /\.git/i
    ];
    
    const isSuspicious = suspiciousPatterns.some(pattern => 
        pattern.test(req.originalUrl)
    );
    
    if (isSuspicious) {
        logger.security('SUSPICIOUS_404', 'medium', {
            url: req.originalUrl,
            method: req.method,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });
    }
    
    res.status(404).json({
        error: {
            message: 'Endpoint not found',
            code: 'ENDPOINT_NOT_FOUND',
            path: req.originalUrl,
            method: req.method,
            timestamp: new Date().toISOString(),
            availableEndpoints: [
                'GET /health',
                'GET /api',
                'POST /api/auth/login',
                'POST /api/auth/register',
                'GET /api/vpn/countries',
                'GET /api/dns/servers'
            ]
        }
    });
};

/**
 * Async Error Wrapper
 * Wraps async route handlers to catch promise rejections
 */
const asyncErrorHandler = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

/**
 * Create custom error
 * Helper function to create errors with specific codes
 */
const createError = (message, code, status = 500, details = null) => {
    const error = new Error(message);
    error.code = code;
    error.status = status;
    if (details) {
        error.details = details;
    }
    return error;
};

/**
 * Validation error creator
 * Creates standardized validation errors
 */
const validationError = (field, message, value = null) => {
    const error = createError('Validation failed', 'VALIDATION_ERROR', 400);
    error.details = [{
        field,
        message,
        value
    }];
    return error;
};

/**
 * Authentication error creator
 */
const authError = (message = 'Authentication failed', code = 'AUTH_ERROR') => {
    return createError(message, code, 401);
};

/**
 * Authorization error creator
 */
const forbiddenError = (message = 'Access forbidden', code = 'FORBIDDEN') => {
    return createError(message, code, 403);
};

/**
 * Not found error creator
 */
const notFoundError = (resource = 'Resource') => {
    return createError(`${resource} not found`, 'NOT_FOUND', 404);
};

module.exports = {
    errorHandler,
    notFoundHandler,
    asyncErrorHandler,
    createError,
    validationError,
    authError,
    forbiddenError,
    notFoundError
};
