// node-safe/server.js - Node.js Safe Endpoints (Express + mysql2/pg)

const express = require('express');
const mysql = require('mysql2/promise');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

// MySQL Connection Pool (SAFE - always uses prepared statements)
const mysqlPool = mysql.createPool({
    host: process.env.MYSQL_HOST || 'mysql-safe',
    user: process.env.MYSQL_USER || 'testuser',
    password: process.env.MYSQL_PASS || 'testpass',
    database: process.env.MYSQL_DB || 'testdb',
    waitForConnections: true,
    connectionLimit: 10
});

// PostgreSQL Connection Pool (SAFE)
const pgPool = new Pool({
    host: process.env.POSTGRES_HOST || 'postgres-safe',
    user: process.env.POSTGRES_USER || 'testuser',
    password: process.env.POSTGRES_PASSWORD || 'rootpass',
    database: process.env.POSTGRES_DB || 'testdb',
    port: 5432
});

app.get('/', (req, res) => {
    res.json({
        service: 'Node.js False Positive Test Suite',
        endpoints: [
            '/mysql2-prepared - mysql2 prepared (safe)',
            '/mysql2-in-clause - mysql2 IN clause prepared (safe)',
            '/pg-prepared - PostgreSQL prepared (safe)',
            '/pg-like - PostgreSQL LIKE parameterized (safe)',
            '/redis-cache - Redis cache lookup (no SQL)'
        ]
    });
});

// TEST 16: MySQL2 Prepared Statement (TRUE SAFE)
app.get('/mysql2-prepared', async (req, res) => {
    const id = req.query.id || '1';
    try {
        // SAFE - mysql2 prepared statement with ?
        const [rows] = await mysqlPool.execute(
            'SELECT * FROM users WHERE id = ?',
            [id] // Bound as parameter
        );
        res.json({ safe: true, method: 'mysql2 execute()', results: rows.length });
    } catch (e) {
        res.json({ safe: true, error: e.message });
    }
});

// TEST 17: MySQL2 with IN clause (ARRAY - SAFE)
app.get('/mysql2-in-clause', async (req, res) => {
    const ids = (req.query.ids || '1,2,3').split(',').map(Number);
    try {
        // SAFE - Dynamic ? placeholders but parameterized execution
        const placeholders = ids.map(() => '?').join(',');
        const [rows] = await mysqlPool.execute(
            `SELECT * FROM users WHERE id IN (${placeholders})`,
            ids // All values bound as parameters
        );
        res.json({ safe: true, method: 'mysql2 IN clause prepared', results: rows.length });
    } catch (e) {
        res.json({ safe: true, error: e.message });
    }
});

// TEST 18: PostgreSQL Prepared (SAFE)
app.get('/pg-prepared', async (req, res) => {
    const id = req.query.id || '1';
    try {
        // SAFE - PostgreSQL $1, $2 parameterization
        const result = await pgPool.query(
            'SELECT * FROM users WHERE id = $1',
            [id] // Bound parameter
        );
        res.json({ safe: true, method: 'pg parameterized', results: result.rows.length });
    } catch (e) {
        res.json({ safe: true, error: e.message });
    }
});

// TEST 19: PostgreSQL with LIKE (SAFE)
app.get('/pg-like', async (req, res) => {
    const search = req.query.search || 'test';
    try {
        // SAFE - LIKE with parameter (wildcards included in bound value)
        const pattern = `%${search}%`;
        const result = await pgPool.query(
            'SELECT * FROM users WHERE name LIKE $1',
            [pattern]
        );
        res.json({ safe: true, method: 'pg LIKE parameterized', results: result.rows.length });
    } catch (e) {
        res.json({ safe: true, error: e.message });
    }
});

// TEST 20: Non-SQL Redis Cache (Simulated with Map)
const mockRedis = new Map();
app.get('/redis-cache', (req, res) => {
    const key = req.query.key || 'user:1';
    // NOT SQL - Redis cache lookup
    const value = mockRedis.get(key);
    if (!value) {
        mockRedis.set(key, { data: 'cached_data', timestamp: Date.now() });
    }
    res.json({ 
        safe: true, 
        method: 'Redis cache (no SQL)', 
        hit: value !== undefined,
        key: key
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Node.js False Positive Suite running on port ${PORT}`);
});
