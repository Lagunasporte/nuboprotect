const express = require('express');
const Joi = require('joi');
const crypto = require('crypto');
const { Client } = require('ssh2');

const database = require('../config/database');
const logger = require('../utils/logger');
const { authMiddleware, requireSubscription, auditLog } = require('../middleware/auth');
const { asyncErrorHandler, validationError, createError, notFoundError } = require('../middleware/errorHandler');

const router = express.Router();

// Validation schemas
const connectSchema = Joi.object({
    countryCode: Joi.string()
        .length(2)
        .uppercase()
        .required()
        .messages({
            'string.length': 'Country code must be exactly 2 characters',
            'string.uppercase': 'Country code must be uppercase',
            'any.required': 'Country code is required'
        }),
    
    serverPreference: Joi.string()
        .valid('auto', 'fastest', 'specific')
        .default('auto'),
    
    serverId: Joi.number()
        .integer()
        .positive()
        .when('serverPreference', {
            is: 'specific',
            then: Joi.required(),
            otherwise: Joi.optional()
        })
});

const disconnectSchema = Joi.object({
    connectionId: Joi.number()
        .integer()
        .positive()
        .optional()
});

// Helper function to generate WireGuard key pair
const generateWireGuardKeys = () => {
    // Generate private key (32 random bytes, base64 encoded)
    const privateKey = crypto.randomBytes(32).toString('base64');
    
    // In a real implementation, you would derive the public key from the private key
    // For this example, we'll generate a mock public key
    const publicKey = crypto.randomBytes(32).toString('base64');
    
    return { privateKey, publicKey };
};

// Helper function to get next available IP in subnet
const getNextAvailableIP = async (serverPool, userId) => {
    // Parse pool (e.g., "10.0.0.0/24")
    const [baseIP, prefix] = serverPool.split('/');
    const [a, b, c, d] = baseIP.split('.').map(Number);
    
    // Get used IPs from database
    const usedIPs = await database.all(`
        SELECT client_ip FROM vpn_connections 
        WHERE status = 'connected' AND client_ip LIKE ?
    `, [`${a}.${b}.${c}.%`]);
    
    const usedIPSet = new Set(usedIPs.map(row => row.client_ip));
    
    // Find first available IP (starting from .10 to leave room for gateway, etc.)
    for (let i = 10; i < 254; i++) {
        const candidateIP = `${a}.${b}.${c}.${i}`;
        if (!usedIPSet.has(candidateIP)) {
            return candidateIP;
        }
    }
    
    throw createError('No available IP addresses in subnet', 'IP_POOL_EXHAUSTED', 503);
};

// SSH connection helper
const createSSHConnection = (serverConfig) => {
    return new Promise((resolve, reject) => {
        const conn = new Client();
        
        const timeout = setTimeout(() => {
            conn.end();
            reject(new Error('SSH connection timeout'));
        }, parseInt(process.env.SSH_TIMEOUT_MS) || 30000);
        
        conn.on('ready', () => {
            clearTimeout(timeout);
            resolve(conn);
        });
        
        conn.on('error', (err) => {
            clearTimeout(timeout);
            reject(err);
        });
        
        conn.connect({
            host: serverConfig.host,
            port: serverConfig.port || 22,
            username: serverConfig.username,
            password: serverConfig.password,
            readyTimeout: 30000,
            algorithms: {
                kex: ['diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1'],
                cipher: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr']
            }
        });
    });
};

// Execute Mikrotik command via SSH
const executeMikrotikCommand = async (serverConfig, command) => {
    let conn;
    
    try {
        conn = await createSSHConnection(serverConfig);
        
        return new Promise((resolve, reject) => {
            conn.exec(command, (err, stream) => {
                if (err) {
                    reject(err);
                    return;
                }
                
                let output = '';
                let errorOutput = '';
                
                stream.on('close', (code, signal) => {
                    if (code === 0) {
                        resolve(output.trim());
                    } else {
                        reject(new Error(`Command failed with code ${code}: ${errorOutput || output}`));
                    }
                });
                
                stream.on('data', (data) => {
                    output += data.toString();
                });
                
                stream.stderr.on('data', (data) => {
                    errorOutput += data.toString();
                });
            });
        });
    } finally {
        if (conn) {
            conn.end();
        }
    }
};

// Configure WireGuard peer on Mikrotik
const configureMikrotikPeer = async (server, peerConfig) => {
    const serverConfig = {
        host: server.server_ip,
        port: parseInt(process.env[`MIKROTIK_${server.country_code}_PORT`]) || 22,
        username: process.env[`MIKROTIK_${server.country_code}_USER`],
        password: process.env[`MIKROTIK_${server.country_code}_PASS`]
    };
    
    try {
        // Add WireGuard peer
        const addPeerCommand = `/interface/wireguard/peers/add ` +
            `interface=${server.wg_interface} ` +
            `public-key="${peerConfig.publicKey}" ` +
            `allowed-address=${peerConfig.clientIP}/32 ` +
            `comment="NuboLink-User-${peerConfig.userId}"`;
        
        await executeMikrotikCommand(serverConfig, addPeerCommand);
        
        // Add IP pool entry if needed
        const poolCommand = `/ip/pool/add ` +
            `name=wg-pool-${server.country_code} ` +
            `ranges=${peerConfig.clientIP}`;
        
        // This might fail if pool already exists, which is fine
        try {
            await executeMikrotikCommand(serverConfig, poolCommand);
        } catch (poolError) {
            // Ignore pool creation errors
            logger.debug('Pool creation ignored:', poolError.message);
        }
        
        logger.mikrotik(server.server_ip, 'ADD_PEER', true, {
            userId: peerConfig.userId,
            clientIP: peerConfig.clientIP,
            publicKey: peerConfig.publicKey.substring(0, 20) + '...'
        });
        
        return true;
        
    } catch (error) {
        logger.mikrotik(server.server_ip, 'ADD_PEER', false, {
            error: error.message,
            userId: peerConfig.userId
        });
        
        throw createError('Failed to configure VPN on router', 'MIKROTIK_CONFIG_ERROR', 503);
    }
};

// Remove WireGuard peer from Mikrotik
const removeMikrotikPeer = async (server, publicKey, userId) => {
    const serverConfig = {
        host: server.server_ip,
        port: parseInt(process.env[`MIKROTIK_${server.country_code}_PORT`]) || 22,
        username: process.env[`MIKROTIK_${server.country_code}_USER`],
        password: process.env[`MIKROTIK_${server.country_code}_PASS`]
    };
    
    try {
        // Find and remove peer
        const findCommand = `/interface/wireguard/peers/print where public-key="${publicKey}"`;
        const peerInfo = await executeMikrotikCommand(serverConfig, findCommand);
        
        if (peerInfo.includes('public-key=' + publicKey)) {
            const removeCommand = `/interface/wireguard/peers/remove [find public-key="${publicKey}"]`;
            await executeMikrotikCommand(serverConfig, removeCommand);
        }
        
        logger.mikrotik(server.server_ip, 'REMOVE_PEER', true, {
            userId,
            publicKey: publicKey.substring(0, 20) + '...'
        });
        
    } catch (error) {
        logger.mikrotik(server.server_ip, 'REMOVE_PEER', false, {
            error: error.message,
            userId
        });
        
        // Don't throw error for cleanup operations
        logger.warn('Failed to remove peer from Mikrotik:', error);
    }
};

/**
 * GET /api/vpn/countries
 * Get list of available VPN countries/servers
 */
router.get('/countries', authMiddleware, asyncErrorHandler(async (req, res) => {
    const servers = await database.all(`
        SELECT 
            id, country_code, country_name, server_ip, server_name,
            server_location, status, latency_ms, current_clients,
            max_clients
        FROM servers 
        WHERE status = 'active'
        ORDER BY latency_ms ASC
    `);
    
    const countries = servers.map(server => ({
        id: server.id,
        code: server.country_code,
        name: server.country_name,
        flag: getCountryFlag(server.country_code),
        server: {
            name: server.server_name,
            location: server.server_location,
            ip: server.server_ip
        },
        performance: {
            latency: server.latency_ms,
            load: Math.round((server.current_clients / server.max_clients) * 100)
        },
        status: server.status,
        available: server.current_clients < server.max_clients
    }));
    
    // Group by country and mark recommended
    const groupedCountries = countries.reduce((acc, country) => {
        if (!acc[country.code]) {
            acc[country.code] = {
                code: country.code,
                name: country.name,
                flag: country.flag,
                servers: [],
                recommended: country.performance.latency < 50 && country.performance.load < 80
            };
        }
        acc[country.code].servers.push(country);
        return acc;
    }, {});
    
    logger.vpn('GET_COUNTRIES', req.user.id, null, {
        countriesCount: Object.keys(groupedCountries).length,
        serversCount: servers.length
    });
    
    res.json({
        countries: Object.values(groupedCountries),
        total: Object.keys(groupedCountries).length,
        totalServers: servers.length
    });
}));

// Helper function to get country flag emoji
const getCountryFlag = (countryCode) => {
    const flags = {
        'ES': '🇪🇸', 'US': '🇺🇸', 'GB': '🇬🇧', 'FR': '🇫🇷', 
        'DE': '🇩🇪', 'NL': '🇳🇱', 'CH': '🇨🇭', 'CA': '🇨🇦',
        'JP': '🇯🇵', 'AU': '🇦🇺', 'SG': '🇸🇬', 'BR': '🇧🇷',
        'IN': '🇮🇳', 'SE': '🇸🇪', 'NO': '🇳🇴'
    };
    return flags[countryCode] || '🏳️';
};

/**
 * POST /api/vpn/connect
 * Connect to VPN server
 */
router.post('/connect', authMiddleware, auditLog('VPN_CONNECT', 'vpn'), asyncErrorHandler(async (req, res) => {
    // Validate request
    const { error, value } = connectSchema.validate(req.body);
    if (error) {
        throw validationError('connect', error.details[0].message);
    }
    
    const { countryCode, serverPreference, serverId } = value;
    
    // Check if user already has an active connection
    const existingConnection = await database.get(`
        SELECT id, country_code, server_name FROM vpn_connections 
        WHERE user_id = ? AND status = 'connected'
    `, [req.user.id]);
    
    if (existingConnection) {
        logger.vpn('CONNECT_ALREADY_CONNECTED', req.user.id, countryCode, {
            existingConnection: existingConnection.country_code,
            requestedCountry: countryCode
        });
        
        return res.status(409).json({
            error: {
                message: 'Already connected to VPN',
                code: 'ALREADY_CONNECTED',
                currentConnection: {
                    id: existingConnection.id,
                    countryCode: existingConnection.country_code,
                    serverName: existingConnection.server_name
                }
            }
        });
    }
    
    // Check subscription limits
    const connectionCount = await database.get(`
        SELECT COUNT(*) as count FROM vpn_connections 
        WHERE user_id = ? AND status = 'connected'
    `, [req.user.id]);
    
    const user = await database.get('SELECT max_connections FROM users WHERE id = ?', [req.user.id]);
    
    if (connectionCount.count >= user.max_connections) {
        throw createError(
            `Maximum connections limit reached (${user.max_connections})`,
            'CONNECTION_LIMIT_EXCEEDED',
            429
        );
    }
    
    // Find appropriate server
    let server;
    if (serverPreference === 'specific' && serverId) {
        server = await database.get(`
            SELECT * FROM servers 
            WHERE id = ? AND status = 'active' AND current_clients < max_clients
        `, [serverId]);
        
        if (!server) {
            throw notFoundError('Specified server not available');
        }
    } else {
        // Find best server for country
        const orderBy = serverPreference === 'fastest' ? 'latency_ms ASC' : 'current_clients ASC';
        
        server = await database.get(`
            SELECT * FROM servers 
            WHERE country_code = ? AND status = 'active' AND current_clients < max_clients
            ORDER BY ${orderBy}
            LIMIT 1
        `, [countryCode]);
        
        if (!server) {
            throw notFoundError(`No available servers in ${countryCode}`);
        }
    }
    
    try {
        // Generate WireGuard configuration
        const { privateKey, publicKey } = generateWireGuardKeys();
        const clientIP = await getNextAvailableIP(server.client_pool, req.user.id);
        
        // Create connection record
        const connectionResult = await database.run(`
            INSERT INTO vpn_connections (
                user_id, country_code, country_name, server_ip, server_name,
                client_ip, public_key, private_key, endpoint, status,
                connected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'connecting', CURRENT_TIMESTAMP)
        `, [
            req.user.id, server.country_code, server.country_name,
            server.server_ip, server.server_name, clientIP,
            publicKey, privateKey, `${server.server_ip}:${server.wg_port || 51820}`,
        ]);
        
        const connectionId = connectionResult.id;
        
        // Configure peer on Mikrotik
        await configureMikrotikPeer(server, {
            userId: req.user.id,
            publicKey,
            clientIP
        });
        
        // Update connection status to connected
        await database.run(`
            UPDATE vpn_connections 
            SET status = 'connected'
            WHERE id = ?
        `, [connectionId]);
        
        // Update server client count
        await database.run(`
            UPDATE servers 
            SET current_clients = current_clients + 1
            WHERE id = ?
        `, [server.id]);
        
        // Generate WireGuard configuration file
        const wgConfig = {
            interface: {
                privateKey,
                address: `${clientIP}/32`,
                dns: [
                    process.env.DNS_PRIMARY || '1.1.1.1',
                    process.env.DNS_SECONDARY || '1.0.0.1'
                ],
                mtu: parseInt(process.env.WG_MTU) || 1420
            },
            peer: {
                publicKey: server.wg_public_key || 'SERVER_PUBLIC_KEY_PLACEHOLDER',
                endpoint: `${server.server_ip}:${server.wg_port || 51820}`,
                allowedIPs: '0.0.0.0/0,::/0',
                keepAlive: parseInt(process.env.WG_KEEP_ALIVE) || 25
            }
        };
        
        const wgConfigText = `
[Interface]
PrivateKey = ${wgConfig.interface.privateKey}
Address = ${wgConfig.interface.address}
DNS = ${wgConfig.interface.dns.join(', ')}
MTU = ${wgConfig.interface.mtu}

[Peer]
PublicKey = ${wgConfig.peer.publicKey}
Endpoint = ${wgConfig.peer.endpoint}
AllowedIPs = ${wgConfig.peer.allowedIPs}
PersistentKeepalive = ${wgConfig.peer.keepAlive}
        `.trim();
        
        logger.vpn('VPN_CONNECTED', req.user.id, countryCode, {
            serverId: server.id,
            serverName: server.server_name,
            clientIP,
            connectionId
        });
        
        res.json({
            message: 'VPN connection established',
            connection: {
                id: connectionId,
                country: {
                    code: server.country_code,
                    name: server.country_name,
                    flag: getCountryFlag(server.country_code)
                },
                server: {
                    id: server.id,
                    name: server.server_name,
                    location: server.server_location,
                    latency: server.latency_ms
                },
                client: {
                    ip: clientIP,
                    assignedAt: new Date().toISOString()
                },
                status: 'connected'
            },
            wireguard: {
                config: wgConfigText,
                qrCode: `data:text/plain;base64,${Buffer.from(wgConfigText).toString('base64')}`
            }
        });
        
    } catch (error) {
        // Cleanup on error
        if (connectionResult?.id) {
            await database.run('DELETE FROM vpn_connections WHERE id = ?', [connectionResult.id]);
        }
        
        logger.vpn('VPN_CONNECT_FAILED', req.user.id, countryCode, {
            error: error.message,
            serverId: server.id
        });
        
        throw error;
    }
}));

/**
 * DELETE /api/vpn/disconnect
 * Disconnect from VPN
 */
router.delete('/disconnect', authMiddleware, auditLog('VPN_DISCONNECT', 'vpn'), asyncErrorHandler(async (req, res) => {
    const { error, value } = disconnectSchema.validate(req.body);
    if (error) {
        throw validationError('disconnect', error.details[0].message);
    }
    
    const { connectionId } = value;
    
    // Find active connection
    let connection;
    if (connectionId) {
        connection = await database.get(`
            SELECT * FROM vpn_connections 
            WHERE id = ? AND user_id = ? AND status = 'connected'
        `, [connectionId, req.user.id]);
    } else {
        connection = await database.get(`
            SELECT * FROM vpn_connections 
            WHERE user_id = ? AND status = 'connected'
            ORDER BY connected_at DESC
            LIMIT 1
        `, [req.user.id]);
    }
    
    if (!connection) {
        return res.status(404).json({
            error: {
                message: 'No active VPN connection found',
                code: 'NO_ACTIVE_CONNECTION'
            }
        });
    }
    
    try {
        // Get server info
        const server = await database.get(`
            SELECT * FROM servers WHERE country_code = ?
        `, [connection.country_code]);
        
        // Remove peer from Mikrotik
        if (server && connection.public_key) {
            await removeMikrotikPeer(server, connection.public_key, req.user.id);
        }
        
        // Calculate connection duration
        const connectedAt = new Date(connection.connected_at);
        const disconnectedAt = new Date();
        const durationSeconds = Math.floor((disconnectedAt - connectedAt) / 1000);
        
        // Update connection record
        await database.run(`
            UPDATE vpn_connections 
            SET status = 'disconnected', 
                disconnected_at = CURRENT_TIMESTAMP,
                duration_seconds = ?
            WHERE id = ?
        `, [durationSeconds, connection.id]);
        
        // Update server client count
        if (server) {
            await database.run(`
                UPDATE servers 
                SET current_clients = CASE 
                    WHEN current_clients > 0 THEN current_clients - 1 
                    ELSE 0 
                END
                WHERE id = ?
            `, [server.id]);
        }
        
        logger.vpn('VPN_DISCONNECTED', req.user.id, connection.country_code, {
            connectionId: connection.id,
            durationSeconds,
            serverName: connection.server_name
        });
        
        res.json({
            message: 'VPN disconnected successfully',
            connection: {
                id: connection.id,
                duration: {
                    seconds: durationSeconds,
                    human: formatDuration(durationSeconds)
                },
                bytesTransferred: {
                    sent: connection.bytes_sent || 0,
                    received: connection.bytes_received || 0,
                    total: (connection.bytes_sent || 0) + (connection.bytes_received || 0)
                },
                disconnectedAt: disconnectedAt.toISOString()
            }
        });
        
    } catch (error) {
        logger.vpn('VPN_DISCONNECT_FAILED', req.user.id, connection.country_code, {
            error: error.message,
            connectionId: connection.id
        });
        
        // Still mark as disconnected even if Mikrotik cleanup failed
        await database.run(`
            UPDATE vpn_connections 
            SET status = 'disconnected', 
                disconnected_at = CURRENT_TIMESTAMP,
                disconnect_reason = ?
            WHERE id = ?
        `, [error.message, connection.id]);
        
        throw error;
    }
}));

/**
 * GET /api/vpn/status
 * Get current VPN connection status
 */
router.get('/status', authMiddleware, asyncErrorHandler(async (req, res) => {
    const connection = await database.get(`
        SELECT 
            id, country_code, country_name, server_ip, server_name,
            server_location, client_ip, status, connected_at,
            bytes_sent, bytes_received, last_handshake
        FROM vpn_connections 
        WHERE user_id = ? AND status = 'connected'
        ORDER BY connected_at DESC
        LIMIT 1
    `, [req.user.id]);
    
    if (!connection) {
        return res.json({
            connected: false,
            status: 'disconnected',
            message: 'No active VPN connection'
        });
    }
    
    // Calculate connection duration
    const connectedAt = new Date(connection.connected_at);
    const now = new Date();
    const durationSeconds = Math.floor((now - connectedAt) / 1000);
    
    res.json({
        connected: true,
        status: connection.status,
        connection: {
            id: connection.id,
            country: {
                code: connection.country_code,
                name: connection.country_name,
                flag: getCountryFlag(connection.country_code)
            },
            server: {
                name: connection.server_name,
                location: connection.server_location,
                ip: connection.server_ip
            },
            client: {
                ip: connection.client_ip
            },
            duration: {
                seconds: durationSeconds,
                human: formatDuration(durationSeconds)
            },
            traffic: {
                sent: connection.bytes_sent || 0,
                received: connection.bytes_received || 0,
                total: (connection.bytes_sent || 0) + (connection.bytes_received || 0)
            },
            connectedAt: connection.connected_at,
            lastHandshake: connection.last_handshake
        }
    });
}));

/**
 * GET /api/vpn/config/:connectionId
 * Get WireGuard configuration for specific connection
 */
router.get('/config/:connectionId', authMiddleware, asyncErrorHandler(async (req, res) => {
    const connectionId = parseInt(req.params.connectionId);
    
    const connection = await database.get(`
        SELECT 
            id, country_code, server_ip, client_ip, private_key,
            status, server_name
        FROM vpn_connections 
        WHERE id = ? AND user_id = ?
    `, [connectionId, req.user.id]);
    
    if (!connection) {
        throw notFoundError('VPN connection');
    }
    
    const server = await database.get(`
        SELECT wg_public_key, wg_port FROM servers 
        WHERE country_code = ?
    `, [connection.country_code]);
    
    const wgConfig = `
[Interface]
PrivateKey = ${connection.private_key}
Address = ${connection.client_ip}/32
DNS = ${process.env.DNS_PRIMARY || '1.1.1.1'}, ${process.env.DNS_SECONDARY || '1.0.0.1'}
MTU = ${process.env.WG_MTU || 1420}

[Peer]
PublicKey = ${server?.wg_public_key || 'SERVER_PUBLIC_KEY_PLACEHOLDER'}
Endpoint = ${connection.server_ip}:${server?.wg_port || 51820}
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = ${process.env.WG_KEEP_ALIVE || 25}
    `.trim();
    
    res.json({
        connection: {
            id: connection.id,
            status: connection.status,
            serverName: connection.server_name
        },
        wireguard: {
            config: wgConfig,
            qrCode: `data:text/plain;base64,${Buffer.from(wgConfig).toString('base64')}`
        }
    });
}));

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

module.exports = router;
