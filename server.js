#!/usr/bin/env node

/**
 * NuboLink API Server
 * VPN + DNS API with WireGuard & Mikrotik Integration
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Internal modules
const logger = require('./utils/logger');
const database = require('./config/database');

// Routes
const authRoutes = require('./routes/auth');
const vpnRoutes = require('./routes/vpn');
const dnsRoutes = require('./routes/dns');
const userRoutes = require('./routes/users');
const statsRoutes = require('./routes/stats');

// Middleware
const authMiddleware = require('./middleware/auth');
const errorHandler = require('./middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 3001;
const NODE_ENV = process.env.NODE_ENV || 'development';

// ========================================
// Security & Performance Middleware
// ========================================

// Security headers
app.use(helmet({
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// CORS configuration
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = process.env.CORS_ORIGIN 
            ? process.env.CORS_ORIGIN.split(',')
            : ['http://localhost:3000', 'https://nubolink.com'];
        
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: process.env.CORS_CREDENTIALS === 'true',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

app.use(cors(corsOptions));

// Request compression
app.use(compression());

// Request parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// HTTP request logger
if (NODE_ENV === 'development') {
    app.use(morgan('dev'));
} else {
    app.use(morgan('combined', {
        stream: { write: (message) => logger.info(message.trim()) }
    }));
}

// ========================================
// Rate Limiting
// ========================================

// General rate limiting
const generalLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000) / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false
});

// Auth rate limiting (more restrictive)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_AUTH_MAX) || 5,
    message: {
        error: 'Too many authentication attempts from this IP, please try again later.',
        retryAfter: 900
    },
    standardHeaders: true,
    legacyHeaders: false
});

app.use('/api/', generalLimiter);
app.use('/api/auth/', authLimiter);

// ========================================
// Health Check & Status
// ========================================

app.get('/health', async (req, res) => {
    try {
        // Check database connection
        const dbStatus = await database.checkConnection();
        
        const healthCheck = {
            status: 'OK',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            environment: NODE_ENV,
            version: process.env.npm_package_version || '1.0.0',
            database: dbStatus ? 'connected' : 'disconnected',
            memory: process.memoryUsage(),
            pid: process.pid
        };

        res.status(200).json(healthCheck);
        
    } catch (error) {
        logger.error('Health check failed:', error);
        res.status(503).json({
            status: 'ERROR',
            timestamp: new Date().toISOString(),
            error: 'Service unavailable'
        });
    }
});

// API Info endpoint
app.get('/api', (req, res) => {
    res.json({
        name: 'NuboLink API',
        version: '1.0.0',
        description: 'VPN + DNS API with WireGuard & Mikrotik Integration',
        endpoints: {
            auth: '/api/auth',
            vpn: '/api/vpn',
            dns: '/api/dns',
            users: '/api/users',
            stats: '/api/stats'
        },
        documentation: 'https://github.com/yourusername/nubolink-api/blob/main/docs/API.md',
        status: 'active',
        timestamp: new Date().toISOString()
    });
});

// ========================================
// API Routes
// ========================================

// Public routes (no auth required)
app.use('/api/auth', authRoutes);

// Protected routes (require authentication)
app.use('/api/vpn', authMiddleware, vpnRoutes);
app.use('/api/dns', authMiddleware, dnsRoutes);
app.use('/api/users', authMiddleware, userRoutes);
app.use('/api/stats', authMiddleware, statsRoutes);

// ========================================
// Error Handling
// ========================================

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        message: `${req.method} ${req.originalUrl} is not a valid API endpoint`,
        availableEndpoints: [
            'GET /health',
            'GET /api',
            'POST /api/auth/login',
            'POST /api/auth/register',
            'GET /api/vpn/countries',
            'GET /api/dns/servers'
        ]
    });
});

// Global error handler
app.use(errorHandler);

// ========================================
// Database Initialization
// ========================================

async function initializeDatabase() {
    try {
        await database.initialize();
        logger.info('Database initialized successfully');
    } catch (error) {
        logger.error('Failed to initialize database:', error);
        process.exit(1);
    }
}

// ========================================
// Graceful Shutdown
// ========================================

function gracefulShutdown(signal) {
    logger.info(`Received ${signal}. Starting graceful shutdown...`);
    
    server.close(async (err) => {
        if (err) {
            logger.error('Error during server shutdown:', err);
            process.exit(1);
        }
        
        try {
            // Close database connections
            await database.close();
            logger.info('Database connections closed');
            
            logger.info('Graceful shutdown completed');
            process.exit(0);
        } catch (error) {
            logger.error('Error during shutdown cleanup:', error);
            process.exit(1);
        }
    });
}

// ========================================
// Server Startup
// ========================================

let server;

async function startServer() {
    try {
        // Initialize database
        await initializeDatabase();
        
        // Start HTTP server
        server = app.listen(PORT, process.env.HOST || '0.0.0.0', () => {
            logger.info('========================================');
            logger.info('🚀 NuboLink API Server Started');
            logger.info('========================================');
            logger.info(`Environment: ${NODE_ENV}`);
            logger.info(`Port: ${PORT}`);
            logger.info(`PID: ${process.pid}`);
            logger.info(`Node.js: ${process.version}`);
            logger.info(`Memory: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
            logger.info('========================================');
            
            if (NODE_ENV === 'development') {
                logger.info(`🌐 Server running at: http://localhost:${PORT}`);
                logger.info(`📚 API Documentation: http://localhost:${PORT}/api`);
                logger.info(`🔍 Health Check: http://localhost:${PORT}/health`);
                logger.info('========================================');
            }
        });

        // Handle server errors
        server.on('error', (error) => {
            if (error.code === 'EADDRINUSE') {
                logger.error(`Port ${PORT} is already in use`);
            } else {
                logger.error('Server error:', error);
            }
            process.exit(1);
        });

        // Setup graceful shutdown handlers
        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));
        
        // Handle uncaught exceptions
        process.on('uncaughtException', (error) => {
            logger.error('Uncaught Exception:', error);
            gracefulShutdown('UNCAUGHT_EXCEPTION');
        });
        
        // Handle unhandled promise rejections
        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
            gracefulShutdown('UNHANDLED_REJECTION');
        });

    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Start the server
if (require.main === module) {
    startServer();
}

module.exports = app;
