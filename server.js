require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_ad_network_key_2026';
const MINIMUM_WITHDRAWAL = 500.00; // R500 threshold

// TiDB Database Connection Pool Configuration
const db = mysql.createPool({
    host: process.env.TIDB_HOST || '127.0.0.1',
    port: process.env.TIDB_PORT || 4000,
    user: process.env.TIDB_USER || 'root',
    password: process.env.TIDB_PASSWORD || '',
    database: process.env.TIDB_DATABASE || 'ad_network',
    ssl: process.env.TIDB_SSL === 'true' ? { rejectUnauthorized: true } : false,
    waitForConnections: true,
    connectionLimit: 10
});

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied. Token missing.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
};

// ==========================================
// 1. AUTHENTICATION & USER MANAGEMENT
// ==========================================

// Register Account (Advertiser or Publisher)
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role, bank_name, account_number, branch_code } = req.body;
    
    if (!['advertiser', 'publisher'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role selection.' });
    }
    if (!bank_name || !account_number || !branch_code) {
        return res.status(400).json({ error: 'Banking details are mandatory for payment processing.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.execute(
            `INSERT INTO users (name, email, password_hash, role, bank_name, account_number, branch_code) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [name, email, hashedPassword, role, bank_name, account_number, branch_code]
        );
        res.status(201).json({ message: 'Account registered successfully', userId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: 'User registration failed. Email may already be in use.', details: err.message });
    }
});

// Login Route
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(404).json({ error: 'User not found.' });

        const user = rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials.' });

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                balance: user.balance
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error during login.' });
    }
});

// ==========================================
// 2. ADVERTISER MODULE & CAMPAIGNS
// ==========================================

// Create Campaign (Advertisers only)
app.post('/api/advertiser/campaigns', authenticateToken, async (req, res) => {
    if (req.user.role !== 'advertiser') return res.status(403).json({ error: 'Advertiser access only.' });

    const { title, target_url, image_url, budget, cpm, cpc } = req.body;
    try {
        const [result] = await db.execute(
            `INSERT INTO campaigns (advertiser_id, title, target_url, image_url, budget, cpm, cpc) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [req.user.id, title, target_url, image_url, budget, cpm || 10.00, cpc || 2.00]
        );
        res.status(201).json({ message: 'Campaign created', campaignId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create campaign.' });
    }
});

// Comprehensive Stats (Analytics match Google Ads performance indicators)
app.get('/api/advertiser/analytics', authenticateToken, async (req, res) => {
    if (req.user.role !== 'advertiser') return res.status(403).json({ error: 'Advertiser access only.' });

    try {
        const [stats] = await db.execute(
            `SELECT 
                c.id AS campaign_id,
                c.title,
                c.budget,
                c.spent AS total_spent,
                COUNT(CASE WHEN e.event_type = 'impression' THEN 1 END) AS impressions,
                COUNT(CASE WHEN e.event_type = 'click' THEN 1 END) AS clicks,
                ROUND((COUNT(CASE WHEN e.event_type = 'click' THEN 1 END) / NULLIF(COUNT(CASE WHEN e.event_type = 'impression' THEN 1 END), 0)) * 100, 2) AS ctr,
                ROUND(AVG(CASE WHEN e.event_type = 'click' THEN e.gross_cost END), 2) AS avg_cpc
             FROM campaigns c
             LEFT JOIN ad_events e ON c.id = e.campaign_id
             WHERE c.advertiser_id = ?
             GROUP BY c.id`,
            [req.user.id]
        );
        res.json({ analytics: stats });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch analytics.' });
    }
});

// ==========================================
// 3. PUBLISHER MODULE & DOMAINS
// ==========================================

// Register Publisher Domain
app.post('/api/publisher/domains', authenticateToken, async (req, res) => {
    if (req.user.role !== 'publisher') return res.status(403).json({ error: 'Publisher access only.' });

    const { domain_name } = req.body;
    try {
        const [result] = await db.execute(
            `INSERT INTO publisher_domains (publisher_id, domain_name) VALUES (?, ?)`,
            [req.user.id, domain_name]
        );
        
        // Generate Embed Code for Publisher's Website
        const embedCode = `<!-- Ad Network Code -->
<div id="ad-unit-slot" data-publisher-id="${req.user.id}" data-domain="${domain_name}"></div>
<script src="http://localhost:5000/ad-tag.js" async></script>`;

        res.status(201).json({ 
            message: 'Domain registered successfully', 
            domainId: result.insertId,
            embedCode 
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to register domain.' });
    }
});

// Publisher Earnings & Performance Stats
app.get('/api/publisher/analytics', authenticateToken, async (req, res) => {
    if (req.user.role !== 'publisher') return res.status(403).json({ error: 'Publisher access only.' });

    try {
        const [userRows] = await db.execute('SELECT balance FROM users WHERE id = ?', [req.user.id]);
        const [eventStats] = await db.execute(
            `SELECT 
                COUNT(CASE WHEN event_type = 'impression' THEN 1 END) AS impressions,
                COUNT(CASE WHEN event_type = 'click' THEN 1 END) AS clicks,
                SUM(publisher_payout) AS total_earned
             FROM ad_events 
             WHERE publisher_id = ?`,
            [req.user.id]
        );

        res.json({
            current_balance: userRows[0].balance,
            minimum_withdrawal_threshold: MINIMUM_WITHDRAWAL,
            can_withdraw: userRows[0].balance >= MINIMUM_WITHDRAWAL,
            impressions: eventStats[0].impressions || 0,
            clicks: eventStats[0].clicks || 0,
            total_earned: eventStats[0].total_earned || 0.00
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch publisher performance.' });
    }
});

// Request Payout (Enforces minimum R500 threshold)
app.post('/api/publisher/withdraw', authenticateToken, async (req, res) => {
    if (req.user.role !== 'publisher') return res.status(403).json({ error: 'Publisher access only.' });

    try {
        const [userRows] = await db.execute('SELECT balance FROM users WHERE id = ?', [req.user.id]);
        const currentBalance = parseFloat(userRows[0].balance);

        if (currentBalance < MINIMUM_WITHDRAWAL) {
            return res.status(400).json({ 
                error: `Payout threshold not reached. Current balance: R${currentBalance.toFixed(2)}. Minimum required: R${MINIMUM_WITHDRAWAL.toFixed(2)}.` 
            });
        }

        // Process Withdrawal Transaction
        await db.execute('UPDATE users SET balance = 0.00 WHERE id = ?', [req.user.id]);
        await db.execute('INSERT INTO withdrawals (user_id, amount, status) VALUES (?, ?, ?)', [req.user.id, currentBalance, 'pending']);

        res.json({ message: `Payout of R${currentBalance.toFixed(2)} requested successfully. Status: Pending.` });
    } catch (err) {
        res.status(500).json({ error: 'Withdrawal processing failed.' });
    }
});

// ==========================================
// 4. AD SERVING ENGINE & 50/50 SPLIT EXECUTION
// ==========================================

// Authenticated Web Domain Ad Serving Route
app.get('/api/ads/serve', async (req, res) => {
    const { publisher_id, domain } = req.query;

    if (!publisher_id || !domain) {
        return res.status(400).json({ error: 'Unregistered publisher or missing domain authentication parameters.' });
    }

    try {
        // Authenticate domain registration against database records
        const [domains] = await db.execute(
            'SELECT * FROM publisher_domains WHERE publisher_id = ? AND domain_name = ?',
            [publisher_id, domain]
        );

        if (domains.length === 0) {
            return res.status(403).json({ error: 'Unauthorized domain. Domain is not registered under this publisher account.' });
        }

        // Fetch an active campaign with remaining budget
        const [campaigns] = await db.execute(
            'SELECT * FROM campaigns WHERE status = "active" AND (budget - spent) > 0 ORDER BY RAND() LIMIT 1'
        );

        if (campaigns.length === 0) {
            return res.status(404).json({ error: 'No active ad inventory available.' });
        }

        const ad = campaigns[0];
        
        // Calculate 50/50 Financial Split (CPM based)
        const grossCost = parseFloat(ad.cpm) / 1000;
        const publisherShare = grossCost * 0.50; // 50% split to publisher
        const agencyShare = grossCost * 0.50;    // 50% split to your network agency

        // Log impression ledger transaction
        await db.execute(
            `INSERT INTO ad_events (campaign_id, publisher_id, event_type, gross_cost, publisher_payout, agency_revenue, ip_address)
             VALUES (?, ?, 'impression', ?, ?, ?, ?)`,
            [ad.id, publisher_id, grossCost, publisherShare, agencyShare, req.ip]
        );

        // Update campaign expenditure and publisher balance
        await db.execute('UPDATE campaigns SET spent = spent + ? WHERE id = ?', [grossCost, ad.id]);
        await db.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [publisherShare, publisher_id]);

        // Output rendered HTML banner element
        res.json({
            ad_id: ad.id,
            html: `<div style="border: 1px solid #ccc; padding: 10px; max-width: 300px; text-align: center; font-family: sans-serif;">
                    <a href="http://localhost:5000/api/ads/click?campaign_id=${ad.id}&publisher_id=${publisher_id}" target="_blank">
                        <img src="${ad.image_url}" alt="${ad.title}" style="max-width: 100%; height: auto;" />
                        <h4 style="margin: 5px 0;">${ad.title}</h4>
                    </a>
                   </div>`
        });
    } catch (err) {
        res.status(500).json({ error: 'Ad serve error.' });
    }
});

// Authenticated Domain Click Tracking Route
app.get('/api/ads/click', async (req, res) => {
    const { campaign_id, publisher_id } = req.query;

    try {
        const [campaigns] = await db.execute('SELECT * FROM campaigns WHERE id = ?', [campaign_id]);
        if (campaigns.length === 0) return res.status(404).send('Campaign not found.');

        const ad = campaigns[0];
        const grossCost = parseFloat(ad.cpc);
        const publisherShare = grossCost * 0.50;
        const agencyShare = grossCost * 0.50;

        // Log click ledger record
        await db.execute(
            `INSERT INTO ad_events (campaign_id, publisher_id, event_type, gross_cost, publisher_payout, agency_revenue, ip_address)
             VALUES (?, ?, 'click', ?, ?, ?, ?)`,
            [campaign_id, publisher_id || null, grossCost, publisherShare, agencyShare, req.ip]
        );

        // Update spent balances
        await db.execute('UPDATE campaigns SET spent = spent + ? WHERE id = ?', [grossCost, campaign_id]);
        if (publisher_id) {
            await db.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [publisher_id, publisherShare]);
        }

        res.redirect(ad.target_url);
    } catch (err) {
        res.status(500).send('Error redirecting.');
    }
});

// ==========================================
// 5. UNAUTHENTICATED DIRECT MARKETING LINK ROUTE
// ==========================================
// Does NOT require domain or publisher account verification
app.get('/api/ads/direct-link/:campaign_id', async (req, res) => {
    const { campaign_id } = req.params;

    try {
        const [campaigns] = await db.execute('SELECT * FROM campaigns WHERE id = ? AND status = "active"', [campaign_id]);
        if (campaigns.length === 0) return res.status(404).send('Direct link campaign expired or invalid.');

        const ad = campaigns[0];
        const grossCost = parseFloat(ad.cpc);
        const publisherShare = 0.00; // No domain publisher assigned
        const agencyShare = grossCost; // Agency keeps total proceeds for direct traffic links

        // Record tracking event
        await db.execute(
            `INSERT INTO ad_events (campaign_id, publisher_id, event_type, gross_cost, publisher_payout, agency_revenue, ip_address)
             VALUES (?, NULL, 'click', ?, ?, ?, ?)`,
            [campaign_id, grossCost, publisherShare, agencyShare, req.ip]
        );

        await db.execute('UPDATE campaigns SET spent = spent + ? WHERE id = ?', [grossCost, campaign_id]);

        // Redirect directly to destination
        res.redirect(ad.target_url);
    } catch (err) {
        res.status(500).send('Direct link error.');
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Ad Network Engine active on port ${PORT}`));