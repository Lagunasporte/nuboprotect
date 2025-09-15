const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Ensure logs directory exists
const logsDir = './logs';
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Custom format for console output
const consoleFormat = winston.format.combine(
    winston.format.timestamp({
        format: 'HH:mm:ss'
    }),
    winston.format.colorize({
        all: true,
        colors: {
            error: 'red',
            warn: 'yellow',
            info: 'cyan',
            debug: 'blue'
        }
    }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        let msg = `${timestamp} [${level}] ${message}`;
        
        // Add metadata if present
        if (Object.keys(meta).length > 0) {
            msg += ` ${JSON.stringify(meta)}`;
        }
        
        return msg;
    })
);

// Custom format for file output
const fileFormat = winston.format.combine(
    winston.format.timestamp({
        format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.prettyPrint()
);

// Create logger instance
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: fileFormat,
    defaultMeta: { 
        service: 'nubolink-api',
        pid: process.pid,
        version: process.env.npm_package_version || '1.0.0'
    },
    transports: [
        // Error log file
        new winston.transports.File({
            filename: path.join(logsDir, 'error.log'),
            level: 'error',
            maxsize: parseInt(process.env.LOG_MAX_SIZE?.replace('m', '')) * 1024 * 1024 || 5242880, // 5MB default
            maxFiles: parseInt(process.env.LOG_MAX_FILES) || 5,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.json()
            )
        }),
        
        // Combined log file
        new winston.transports.File({
            filename: path.join(logsDir, 'app.log'),
            maxsize: parseInt(process.env.LOG_MAX_SIZE?.replace('m', '')) * 1024 * 1024 || 5242880, // 5MB default
            maxFiles: parseInt(process.env.LOG_MAX_FILES) || 5
        }),
        
        // Daily rotate file (if enabled)
        ...(process.env.LOG_DATE_PATTERN ? [
            new winston.transports.File({
                filename: path.join(logsDir, `app-${new Date().toISOString().split('T')[0]}.log`),
                maxsize: 10485760, // 10MB
                maxFiles: 30 // Keep 30 days
            })
        ] : [])
    ],
    
    // Handle exceptions and rejections
    exceptionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'exceptions.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 5
        })
    ],
    
    rejectionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'rejections.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 5
        })
    ]
});

// Add console transport for development
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: consoleFormat
    }));
}

// Custom logging methods for different contexts
logger.api = (method, url, statusCode, responseTime, userAgent = '') => {
    logger.info('API Request', {
        method,
        url,
        statusCode,
        responseTime: `${responseTime}ms`,
        userAgent,
        timestamp: new Date().toISOString()
    });
};

logger.auth = (action, userId, success, details = {}) => {
    logger.info('Auth Event', {
        action,
        userId,
        success,
        details,
        timestamp: new Date().toISOString()
    });
};

logger.vpn = (action, userId, countryCode, details = {}) => {
    logger.info('VPN Event', {
        action,
        userId,
        countryCode,
        details,
        timestamp: new Date().toISOString()
    });
};

logger.dns = (action, userId, details = {}) => {
    logger.info('DNS Event', {
        action,
        userId,
        details,
        timestamp: new Date().toISOString()
    });
};

logger.security = (event, severity, details = {}) => {
    const logLevel = severity === 'critical' ? 'error' : 
                    severity === 'high' ? 'warn' : 'info';
    
    logger[logLevel]('Security Event', {
        event,
        severity,
        details,
        timestamp: new Date().toISOString()
    });
};

logger.performance = (operation, duration, details = {}) => {
    const logLevel = duration > 5000 ? 'warn' : 'info'; // Warn if operation takes more than 5 seconds
    
    logger[logLevel]('Performance', {
        operation,
        duration: `${duration}ms`,
        details,
        timestamp: new Date().toISOString()
    });
};

logger.database = (operation, table, duration, success, details = {}) => {
    logger.info('Database Operation', {
        operation,
        table,
        duration: `${duration}ms`,
        success,
        details,
        timestamp: new Date().toISOString()
    });
};

logger.mikrotik = (server, action, success, details = {}) => {
    logger.info('Mikrotik Operation', {
        server,
        action,
        success,
        details,
        timestamp: new Date().toISOString()
    });
};

// Log startup information
logger.startup = () => {
    logger.info('========================================');
    logger.info('🚀 NuboLink API Starting Up');
    logger.info('========================================');
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`Node.js Version: ${process.version}`);
    logger.info(`Process ID: ${process.pid}`);
    logger.info(`Log Level: ${logger.level}`);
    logger.info(`Memory Usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
    logger.info('========================================');
};

// Log shutdown information
logger.shutdown = () => {
    logger.info('========================================');
    logger.info('🛑 NuboLink API Shutting Down');
    logger.info('========================================');
    logger.info(`Uptime: ${Math.floor(process.uptime())} seconds`);
    logger.info(`Final Memory Usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
    logger.info('========================================');
};

// Error logging helper
logger.logError = (error, context = {}) => {
    logger.error('Application Error', {
        message: error.message,
        stack: error.stack,
        code: error.code,
        context,
        timestamp: new Date().toISOString()
    });
};

// Request logging middleware helper
logger.requestMiddleware = () => {
    return (req, res, next) => {
        const start = Date.now();
        
        res.on('finish', () => {
            const duration = Date.now() - start;
            logger.api(
                req.method,
                req.originalUrl,
                res.statusCode,
                duration,
                req.get('User-Agent')
            );
        });
        
        next();
    };
};

// Debug helper for development
if (process.env.NODE_ENV === 'development') {
    logger.debug('Logger initialized in development mode');
    logger.debug(`Log directory: ${path.resolve(logsDir)}`);
}

module.exports = logger;
