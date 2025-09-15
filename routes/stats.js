const express = require('express');
const Joi = require('joi');

const database = require('../config/database');
const logger = require('../utils/logger');
const { authMiddleware, requireSubscription } = require('../middleware/auth');
const { asyncErrorHandler, validationError } = require('../middleware/errorHandler');

const router = express.Router();

// Validation schemas
const statsQuerySchema = Joi.object({
    timeframe: Joi.string()
        .valid('hour', 'day', 'week', 'month', 'year')
        .default('week'),
    
    startDate: Joi.date()
        .iso()
        .optional(),
    
    endDate: Joi.date()
        .iso()
        .optional(),
    
    country: Joi.string()
        .length(2)
        .uppercase()
        .optional(),
    
    detailed: Joi.boolean()
        .default(false)
});

const comparisonSchema = Joi.object({
    metric: Joi.string()
        .valid('bandwidth', 'connections', 'dns_queries', 'blocked_queries')
        .required(),
    
    period1: Joi.object({
        start: Joi.date().iso().required(),
        end: Joi.date().iso().required()
    }).required(),
    
    period2: Joi.object({
        start: Joi.date().iso().required(),
        end: Joi.date().iso().required()
    }).required()
});

// Helper function to format bytes
const formatBytes = (bytes) => {
    if (bytes === 0) return { value: 0, unit: 'B', formatted: '0 B' };
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const value = parseFloat((bytes / Math.pow(k, i)).toFixed(2));
    
    return {
        value,
        unit: sizes[i],
        formatted: `${value} ${sizes[i]}`
    };
};

// Helper function to format duration
const formatDuration = (seconds) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
        return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
};

// Helper function to get date range
const getDateRange = (timeframe, startDate, endDate) => {
    const now = new Date();
    
    if (startDate && endDate) {
        return {
            start: new Date(startDate),
            end: new Date(endDate)
        };
    }
    
    let start;
    switch (timeframe) {
        case 'hour':
            start = new Date(now.getTime() - 24 * 60 * 60 * 1000); // Last 24 hours
            break;
        case 'day':
            start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000); // Last 7 days
            break;
        case 'week':
            start = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000); // Last 30 days
            break;
        case 'month':
            start = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000); // Last 90 days
            break;
        case 'year':
            start = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000); // Last year
            break;
        default:
            start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000); // Default to week
    }
    
    return { start, end: now };
};

/**
 * GET /api/stats/overview
 * Get user's overall statistics overview
 */
router.get('/overview', authMiddleware, asyncErrorHandler(async (req, res) => {
    const userId = req.user.id;
    
    // Get VPN overview stats
    const vpnStats = await database.get(`
        SELECT 
            COUNT(*) as total_connections,
            COUNT(CASE WHEN status = 'connected' THEN 1 END) as active_connections,
            SUM(bytes_sent + bytes_received) as total_bytes,
            SUM(duration_seconds) as total_duration,
            AVG(duration_seconds) as avg_duration,
            MAX(connected_at) as last_connection,
            COUNT(DISTINCT country_code) as countries_used
        FROM vpn_connections 
        WHERE user_id = ?
    `, [userId]);
    
    // Get DNS overview stats
    const dnsStats = await database.get(`
        SELECT 
            SUM(queries_total) as total_queries,
            SUM(queries_blocked) as blocked_queries,
            SUM(queries_allowed) as allowed_queries
        FROM dns_stats 
        WHERE user_id = ?
    `, [userId]);
    
    // Get current month stats
    const currentMonth = new Date().toISOString().substring(0, 7); // YYYY-MM
    const monthlyStats = await database.get(`
        SELECT 
            SUM(CASE WHEN DATE(connected_at) LIKE ? THEN bytes_sent + bytes_received ELSE 0 END) as monthly_bytes,
            COUNT(CASE WHEN DATE(connected_at) LIKE ? THEN 1 END) as monthly_connections,
            SUM(CASE WHEN DATE(connected_at) LIKE ? THEN duration_seconds ELSE 0 END) as monthly_duration
        FROM vpn_connections 
        WHERE user_id = ?
    `, [currentMonth + '%', currentMonth + '%', currentMonth + '%', userId]);
    
    // Get most used country
    const topCountry = await database.get(`
        SELECT 
            country_code, 
            country_name,
            COUNT(*) as connection_count,
            SUM(bytes_sent + bytes_received) as total_bytes
        FROM vpn_connections 
        WHERE user_id = ? AND country_code IS NOT NULL
        GROUP BY country_code, country_name
        ORDER BY connection_count DESC
        LIMIT 1
    `, [userId]);
    
    // Calculate block rate
    const blockRate = dnsStats?.total_queries > 0 
        ? Math.round((dnsStats.blocked_queries / dnsStats.total_queries) * 100)
        : 0;
    
    // Get user subscription info
    const user = await database.get(
        'SELECT subscription_type, bytes_used, bytes_limit FROM users WHERE id = ?',
        [userId]
    );
    
    res.json({
        overview: {
            vpn: {
                totalConnections: vpnStats?.total_connections || 0,
                activeConnections: vpnStats?.active_connections || 0,
                totalBytes: formatBytes(vpnStats?.total_bytes || 0),
                totalDuration: {
                    seconds: vpnStats?.total_duration || 0,
                    formatted: formatDuration(vpnStats?.total_duration || 0)
                },
                avgSessionDuration: {
                    seconds: Math.round(vpnStats?.avg_duration || 0),
                    formatted: formatDuration(Math.round(vpnStats?.avg_duration || 0))
                },
                lastConnection: vpnStats?.last_connection,
                countriesUsed: vpnStats?.countries_used || 0,
                favoriteCountry: topCountry ? {
                    code: topCountry.country_code,
                    name: topCountry.country_name,
                    connections: topCountry.connection_count,
                    bytes: formatBytes(topCountry.total_bytes)
                } : null
            },
            dns: {
                totalQueries: dnsStats?.total_queries || 0,
                blockedQueries: dnsStats?.blocked_queries || 0,
                allowedQueries: dnsStats?.allowed_queries || 0,
                blockRate,
                queriesSaved: dnsStats?.blocked_queries || 0
            },
            thisMonth: {
                bytes: formatBytes(monthlyStats?.monthly_bytes || 0),
                connections: monthlyStats?.monthly_connections || 0,
                duration: {
                    seconds: monthlyStats?.monthly_duration || 0,
                    formatted: formatDuration(monthlyStats?.monthly_duration || 0)
                }
            },
            subscription: {
                type: user.subscription_type,
                usage: {
                    bytes: formatBytes(user.bytes_used),
                    limit: formatBytes(user.bytes_limit),
                    percentage: Math.round((user.bytes_used / user.bytes_limit) * 100)
                }
            }
        }
    });
}));

/**
 * GET /api/stats/bandwidth
 * Get detailed bandwidth usage statistics
 */
router.get('/bandwidth', authMiddleware, asyncErrorHandler(async (req, res) => {
    const { error, value } = statsQuerySchema.validate(req.query);
    if (error) {
        throw validationError('bandwidth', error.details[0].message);
    }
    
    const { timeframe, country, detailed } = value;
    const { start, end } = getDateRange(timeframe, value.startDate, value.endDate);
    
    // Base query with date filtering
    let whereClause = 'WHERE user_id = ? AND connected_at >= ? AND connected_at <= ?';
    let params = [req.user.id, start.toISOString(), end.toISOString()];
    
    if (country) {
        whereClause += ' AND country_code = ?';
        params.push(country);
    }
    
    // Get bandwidth data grouped by time period
    const groupBy = timeframe === 'hour' ? "strftime('%Y-%m-%d %H:00:00', connected_at)" :
                   timeframe === 'day' ? "DATE(connected_at)" :
                   timeframe === 'week' ? "strftime('%Y-W%W', connected_at)" :
                   timeframe === 'month' ? "strftime('%Y-%m', connected_at)" :
                   "strftime('%Y', connected_at)";
    
    const bandwidthData = await database.all(`
        SELECT 
            ${groupBy} as period,
            SUM(bytes_sent) as bytes_sent,
            SUM(bytes_received) as bytes_received,
            SUM(bytes_sent + bytes_received) as total_bytes,
            COUNT(*) as connections,
            SUM(duration_seconds) as total_duration
        FROM vpn_connections 
        ${whereClause}
        GROUP BY ${groupBy}
        ORDER BY period DESC
        LIMIT 100
    `, params);
    
    // Get bandwidth by country if not filtered
    let byCountry = [];
    if (!country) {
        byCountry = await database.all(`
            SELECT 
                country_code,
                country_name,
                SUM(bytes_sent) as bytes_sent,
                SUM(bytes_received) as bytes_received,
                SUM(bytes_sent + bytes_received) as total_bytes,
                COUNT(*) as connections
            FROM vpn_connections 
            ${whereClause}
            GROUP BY country_code, country_name
            ORDER BY total_bytes DESC
        `, params);
    }
    
    // Calculate totals
    const totals = bandwidthData.reduce((acc, record) => ({
        sent: acc.sent + (record.bytes_sent || 0),
        received: acc.received + (record.bytes_received || 0),
        total: acc.total + (record.total_bytes || 0),
        connections: acc.connections + (record.connections || 0),
        duration: acc.duration + (record.total_duration || 0)
    }), { sent: 0, received: 0, total: 0, connections: 0, duration: 0 });
    
    res.json({
        timeframe,
        period: {
            start: start.toISOString(),
            end: end.toISOString()
        },
        country: country || null,
        totals: {
            sent: formatBytes(totals.sent),
            received: formatBytes(totals.received),
            total: formatBytes(totals.total),
            connections: totals.connections,
            duration: {
                seconds: totals.duration,
                formatted: formatDuration(totals.duration)
            }
        },
        timeline: bandwidthData.map(record => ({
            period: record.period,
            sent: formatBytes(record.bytes_sent || 0),
            received: formatBytes(record.bytes_received || 0),
            total: formatBytes(record.total_bytes || 0),
            connections: record.connections,
            duration: {
                seconds: record.total_duration || 0,
                formatted: formatDuration(record.total_duration || 0)
            }
        })),
        byCountry: byCountry.map(record => ({
            code: record.country_code,
            name: record.country_name,
            sent: formatBytes(record.bytes_sent || 0),
            received: formatBytes(record.bytes_received || 0),
            total: formatBytes(record.total_bytes || 0),
            connections: record.connections,
            percentage: totals.total > 0 ? Math.round((record.total_bytes / totals.total) * 100) : 0
        }))
    });
}));

/**
 * GET /api/stats/connections
 * Get connection patterns and statistics
 */
router.get('/connections', authMiddleware, asyncErrorHandler(async (req, res) => {
    const { error, value } = statsQuerySchema.validate(req.query);
    if (error) {
        throw validationError('connections', error.details[0].message);
    }
    
    const { timeframe } = value;
    const { start, end } = getDateRange(timeframe, value.startDate, value.endDate);
    
    // Get connections by hour of day
    const hourlyPattern = await database.all(`
        SELECT 
            CAST(strftime('%H', connected_at) AS INTEGER) as hour,
            COUNT(*) as connection_count,
            AVG(duration_seconds) as avg_duration
        FROM vpn_connections 
        WHERE user_id = ? AND connected_at >= ? AND connected_at <= ?
        GROUP BY CAST(strftime('%H', connected_at) AS INTEGER)
        ORDER BY hour
    `, [req.user.id, start.toISOString(), end.toISOString()]);
    
    // Get connections by day of week
    const weeklyPattern = await database.all(`
        SELECT 
            CASE CAST(strftime('%w', connected_at) AS INTEGER)
                WHEN 0 THEN 'Sunday'
                WHEN 1 THEN 'Monday'
                WHEN 2 THEN 'Tuesday'
                WHEN 3 THEN 'Wednesday'
                WHEN 4 THEN 'Thursday'
                WHEN 5 THEN 'Friday'
                WHEN 6 THEN 'Saturday'
            END as day_name,
            CAST(strftime('%w', connected_at) AS INTEGER) as day_number,
            COUNT(*) as connection_count,
            AVG(duration_seconds) as avg_duration
        FROM vpn_connections 
        WHERE user_id = ? AND connected_at >= ? AND connected_at <= ?
        GROUP BY CAST(strftime('%w', connected_at) AS INTEGER)
        ORDER BY day_number
    `, [req.user.id, start.toISOString(), end.toISOString()]);
    
    // Get session duration distribution
    const durationDistribution = await database.all(`
        SELECT 
            CASE 
                WHEN duration_seconds < 300 THEN 'Under 5 minutes'
                WHEN duration_seconds < 1800 THEN '5-30 minutes'
                WHEN duration_seconds < 3600 THEN '30 minutes - 1 hour'
                WHEN duration_seconds < 7200 THEN '1-2 hours'
                WHEN duration_seconds < 14400 THEN '2-4 hours'
                ELSE 'Over 4 hours'
            END as duration_range,
            COUNT(*) as count,
            AVG(duration_seconds) as avg_duration
        FROM vpn_connections 
        WHERE user_id = ? AND connected_at >= ? AND connected_at <= ? AND duration_seconds > 0
        GROUP BY duration_range
        ORDER BY MIN(duration_seconds)
    `, [req.user.id, start.toISOString(), end.toISOString()]);
    
    // Get top countries by connection count
    const topCountries = await database.all(`
        SELECT 
            country_code,
            country_name,
            COUNT(*) as connection_count,
            SUM(duration_seconds) as total_duration,
            AVG(duration_seconds) as avg_duration
        FROM vpn_connections 
        WHERE user_id = ? AND connected_at >= ? AND connected_at <= ? AND country_code IS NOT NULL
        GROUP BY country_code, country_name
        ORDER BY connection_count DESC
        LIMIT 10
    `, [req.user.id, start.toISOString(), end.toISOString()]);
    
    // Calculate total connections for percentages
    const totalConnections = hourlyPattern.reduce((sum, h) => sum + h.connection_count, 0);
    
    res.json({
        timeframe,
        period: {
            start: start.toISOString(),
            end: end.toISOString()
        },
        totalConnections,
        patterns: {
            hourly: Array.from({ length: 24 }, (_, hour) => {
                const data = hourlyPattern.find(h => h.hour === hour);
                return {
                    hour,
                    connections: data?.connection_count || 0,
                    avgDuration: {
                        seconds: Math.round(data?.avg_duration || 0),
                        formatted: formatDuration(Math.round(data?.avg_duration || 0))
                    },
                    percentage: totalConnections > 0 && data ? Math.round((data.connection_count / totalConnections) * 100) : 0
                };
            }),
            weekly: weeklyPattern.map(day => ({
                day: day.day_name,
                dayNumber: day.day_number,
                connections: day.connection_count,
                avgDuration: {
                    seconds: Math.round(day.avg_duration || 0),
                    formatted: formatDuration(Math.round(day.avg_duration || 0))
                },
                percentage: totalConnections > 0 ? Math.round((day.connection_count / totalConnections) * 100) : 0
            })),
            sessionDuration: durationDistribution.map(range => ({
                range: range.duration_range,
                count: range.count,
                avgDuration: {
                    seconds: Math.round(range.avg_duration || 0),
                    formatted: formatDuration(Math.round(range.avg_duration || 0))
                },
                percentage: totalConnections > 0 ? Math.round((range.count / totalConnections) * 100) : 0
            }))
        },
        topCountries: topCountries.map(country => ({
            code: country.country_code,
            name: country.country_name,
            connections: country.connection_count,
            totalDuration: {
                seconds: country.total_duration,
                formatted: formatDuration(country.total_duration)
            },
            avgDuration: {
                seconds: Math.round(country.avg_duration || 0),
                formatted: formatDuration(Math.round(country.avg_duration || 0))
            },
            percentage: totalConnections > 0 ? Math.round((country.connection_count / totalConnections) * 100) : 0
        }))
    });
}));

/**
 * GET /api/stats/dns-detailed
 * Get detailed DNS statistics with advanced metrics
 */
router.get('/dns-detailed', authMiddleware, requireSubscription('premium'), asyncErrorHandler(async (req, res) => {
    const { error, value } = statsQuerySchema.validate(req.query);
    if (error) {
        throw validationError('dnsDetailed', error.details[0].message);
    }
    
    const { timeframe } = value;
    const { start, end } = getDateRange(timeframe, value.startDate, value.endDate);
    
    const startDateStr = start.toISOString().split('T')[0];
    const endDateStr = end.toISOString().split('T')[0];
    
    // Get DNS stats timeline
    const timeline = await database.all(`
        SELECT 
            date,
            hour,
            SUM(queries_total) as total_queries,
            SUM(queries_blocked) as blocked_queries,
            SUM(queries_allowed) as allowed_queries
        FROM dns_stats 
        WHERE user_id = ? AND date >= ? AND date <= ?
        GROUP BY date, ${timeframe === 'hour' ? 'hour' : '1'}
        ORDER BY date DESC, hour DESC
        LIMIT 200
    `, [req.user.id, startDateStr, endDateStr]);
    
    // Get blocked domains statistics
    const topBlockedDomains = await database.all(`
        SELECT 
            domain,
            category,
            block_count,
            last_blocked
        FROM blocked_domains 
        WHERE is_active = 1 
        ORDER BY block_count DESC 
        LIMIT 20
    `);
    
    // Get blocking efficiency by category
    const blockingByCategory = await database.all(`
        SELECT 
            category,
            COUNT(*) as domain_count,
            SUM(block_count) as total_blocks
        FROM blocked_domains 
        WHERE is_active = 1 
        GROUP BY category
        ORDER BY total_blocks DESC
    `);
    
    // Calculate totals and averages
    const totals = timeline.reduce((acc, record) => ({
        queries: acc.queries + record.total_queries,
        blocked: acc.blocked + record.blocked_queries,
        allowed: acc.allowed + record.allowed_queries
    }), { queries: 0, blocked: 0, allowed: 0 });
    
    const avgPerDay = timeline.length > 0 ? {
        queries: Math.round(totals.queries / timeline.length),
        blocked: Math.round(totals.blocked / timeline.length),
        allowed: Math.round(totals.allowed / timeline.length)
    } : { queries: 0, blocked: 0, allowed: 0 };
    
    res.json({
        timeframe,
        period: {
            start: start.toISOString(),
            end: end.toISOString()
        },
        summary: {
            total: totals,
            averagePerDay: avgPerDay,
            blockRate: totals.queries > 0 ? Math.round((totals.blocked / totals.queries) * 100) : 0,
            malwareBlocked: blockingByCategory.find(cat => cat.category === 'malware')?.total_blocks || 0,
            adsBlocked: blockingByCategory.find(cat => cat.category === 'ads')?.total_blocks || 0,
            trackersBlocked: blockingByCategory.find(cat => cat.category === 'tracking')?.total_blocks || 0
        },
        timeline: timeline.map(record => ({
            date: record.date,
            hour: timeframe === 'hour' ? record.hour : null,
            queries: {
                total: record.total_queries,
                blocked: record.blocked_queries,
                allowed: record.allowed_queries,
                blockRate: record.total_queries > 0 ? Math.round((record.blocked_queries / record.total_queries) * 100) : 0
            }
        })),
        topBlockedDomains: topBlockedDomains.map(domain => ({
            domain: domain.domain,
            category: domain.category,
            blockCount: domain.block_count,
            lastBlocked: domain.last_blocked
        })),
        blockingByCategory: blockingByCategory.map(category => ({
            category: category.category,
            domainCount: category.domain_count,
            totalBlocks: category.total_blocks,
            percentage: totals.blocked > 0 ? Math.round((category.total_blocks / totals.blocked) * 100) : 0
        }))
    });
}));

/**
 * GET /api/stats/comparison
 * Compare metrics between two time periods
 */
router.get('/comparison', authMiddleware, requireSubscription('premium'), asyncErrorHandler(async (req, res) => {
    const { error, value } = comparisonSchema.validate(req.query);
    if (error) {
        throw validationError('comparison', error.details[0].message);
    }
    
    const { metric, period1, period2 } = value;
    
    const getMetricData = async (startDate, endDate) => {
        switch (metric) {
            case 'bandwidth':
                return await database.get(`
                    SELECT 
                        SUM(bytes_sent + bytes_received) as total_bytes,
                        COUNT(*) as connections
                    FROM vpn_connections 
                    WHERE user_id = ? AND connected_at >= ? AND connected_at <= ?
                `, [req.user.id, startDate, endDate]);
                
            case 'connections':
                return await database.get(`
                    SELECT 
                        COUNT(*) as total_connections,
                        AVG(duration_seconds) as avg_duration
                    FROM vpn_connections 
                    WHERE user_id = ? AND connected_at >= ? AND connected_at <= ?
                `, [req.user.id, startDate, endDate]);
                
            case 'dns_queries':
                const startDateStr = new Date(startDate).toISOString().split('T')[0];
                const endDateStr = new Date(endDate).toISOString().split('T')[0];
                return await database.get(`
                    SELECT 
                        SUM(queries_total) as total_queries,
                        SUM(queries_allowed) as allowed_queries
                    FROM dns_stats 
                    WHERE user_id = ? AND date >= ? AND date <= ?
                `, [req.user.id, startDateStr, endDateStr]);
                
            case 'blocked_queries':
                const startDateStr2 = new Date(startDate).toISOString().split('T')[0];
                const endDateStr2 = new Date(endDate).toISOString().split('T')[0];
                return await database.get(`
                    SELECT 
                        SUM(queries_blocked) as blocked_queries,
                        SUM(queries_total) as total_queries
                    FROM dns_stats 
                    WHERE user_id = ? AND date >= ? AND date <= ?
                `, [req.user.id, startDateStr2, endDateStr2]);
                
            default:
                throw validationError('metric', 'Invalid metric type');
        }
    };
    
    const data1 = await getMetricData(period1.start, period1.end);
    const data2 = await getMetricData(period2.start, period2.end);
    
    // Calculate comparison based on metric type
    let comparison = {};
    
    switch (metric) {
        case 'bandwidth':
            const bytes1 = data1?.total_bytes || 0;
            const bytes2 = data2?.total_bytes || 0;
            const change = bytes1 > 0 ? ((bytes2 - bytes1) / bytes1) * 100 : 0;
            
            comparison = {
                period1: { value: formatBytes(bytes1), connections: data1?.connections || 0 },
                period2: { value: formatBytes(bytes2), connections: data2?.connections || 0 },
                change: {
                    percentage: Math.round(change),
                    direction: change > 0 ? 'increase' : change < 0 ? 'decrease' : 'no_change',
                    absolute: formatBytes(Math.abs(bytes2 - bytes1))
                }
            };
            break;
            
        case 'connections':
            const conn1 = data1?.total_connections || 0;
            const conn2 = data2?.total_connections || 0;
            const connChange = conn1 > 0 ? ((conn2 - conn1) / conn1) * 100 : 0;
            
            comparison = {
                period1: { 
                    connections: conn1, 
                    avgDuration: formatDuration(Math.round(data1?.avg_duration || 0))
                },
                period2: { 
                    connections: conn2, 
                    avgDuration: formatDuration(Math.round(data2?.avg_duration || 0))
                },
                change: {
                    percentage: Math.round(connChange),
                    direction: connChange > 0 ? 'increase' : connChange < 0 ? 'decrease' : 'no_change',
                    absolute: Math.abs(conn2 - conn1)
                }
            };
            break;
            
        case 'dns_queries':
            const queries1 = data1?.total_queries || 0;
            const queries2 = data2?.total_queries || 0;
            const queriesChange = queries1 > 0 ? ((queries2 - queries1) / queries1) * 100 : 0;
            
            comparison = {
                period1: { queries: queries1, allowed: data1?.allowed_queries || 0 },
                period2: { queries: queries2, allowed: data2?.allowed_queries || 0 },
                change: {
                    percentage: Math.round(queriesChange),
                    direction: queriesChange > 0 ? 'increase' : queriesChange < 0 ? 'decrease' : 'no_change',
                    absolute: Math.abs(queries2 - queries1)
                }
            };
            break;
            
        case 'blocked_queries':
            const blocked1 = data1?.blocked_queries || 0;
            const blocked2 = data2?.blocked_queries || 0;
            const blockedChange = blocked1 > 0 ? ((blocked2 - blocked1) / blocked1) * 100 : 0;
            
            comparison = {
                period1: { 
                    blocked: blocked1, 
                    blockRate: data1?.total_queries > 0 ? Math.round((blocked1 / data1.total_queries) * 100) : 0
                },
                period2: { 
                    blocked: blocked2, 
                    blockRate: data2?.total_queries > 0 ? Math.round((blocked2 / data2.total_queries) * 100) : 0
                },
                change: {
                    percentage: Math.round(blockedChange),
                    direction: blockedChange > 0 ? 'increase' : blockedChange < 0 ? 'decrease' : 'no_change',
                    absolute: Math.abs(blocked2 - blocked1)
                }
            };
            break;
    }
    
    res.json({
        metric,
        periods: {
            period1: {
                start: period1.start,
                end: period1.end,
                duration: Math.ceil((new Date(period1.end) - new Date(period1.start)) / (1000 * 60 * 60 * 24))
            },
            period2: {
                start: period2.start,
                end: period2.end,
                duration: Math.ceil((new Date(period2.end) - new Date(period2.start)) / (1000 * 60 * 60 * 24))
            }
        },
        comparison
    });
}));

/**
 * GET /api/stats/export
 * Export user statistics (premium feature)
 */
router.get('/export', authMiddleware, requireSubscription('premium'), asyncErrorHandler(async (req, res) => {
    const format = req.query.format || 'json'; // json, csv
    const { start, end } = getDateRange('month'); // Default to last month
    
    // Get comprehensive data
    const vpnData = await database.all(`
        SELECT 
            connected_at, disconnected_at, duration_seconds,
            country_code, country_name, server_name,
            bytes_sent, bytes_received, status
        FROM vpn_connections 
        WHERE user_id = ? AND connected_at >= ? AND connected_at <= ?
        ORDER BY connected_at DESC
    `, [req.user.id, start.toISOString(), end.toISOString()]);
    
    const dnsData = await database.all(`
        SELECT 
            date, hour, queries_total, queries_blocked, queries_allowed
        FROM dns_stats 
        WHERE user_id = ? AND date >= ? AND date <= ?
        ORDER BY date DESC, hour DESC
    `, [req.user.id, start.toISOString().split('T')[0], end.toISOString().split('T')[0]]);
    
    if (format === 'csv') {
        // Generate CSV format
        let csv = 'Type,Date,Country,Duration,Bytes Sent,Bytes Received,Queries Total,Queries Blocked\n';
        
        vpnData.forEach(row => {
            csv += `VPN,${row.connected_at},${row.country_code},${row.duration_seconds},${row.bytes_sent},${row.bytes_received},,\n`;
        });
        
        dnsData.forEach(row => {
            csv += `DNS,${row.date} ${row.hour}:00,,,,,${row.queries_total},${row.queries_blocked}\n`;
        });
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="nubolink-stats.csv"');
        res.send(csv);
    } else {
        // JSON format
        res.json({
            exportedAt: new Date().toISOString(),
            period: {
                start: start.toISOString(),
                end: end.toISOString()
            },
            data: {
                vpn: vpnData,
                dns: dnsData
            },
            summary: {
                vpnConnections: vpnData.length,
                dnsRecords: dnsData.length,
                totalBytes: vpnData.reduce((sum, row) => sum + (row.bytes_sent || 0) + (row.bytes_received || 0), 0),
                totalQueries: dnsData.reduce((sum, row) => sum + (row.queries_total || 0), 0)
            }
        });
    }
}));

module.exports = router;
