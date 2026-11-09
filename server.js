require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Ensure uploads directory exists for raw image/video files
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}
app.use('/uploads', express.static(uploadDir));

// Configure Multer for raw multi-format media uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|mp4|webm|ogg|mov/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (mimetype && extname) return cb(null, true);
        cb(new Error('Only raw image and video files are permitted!'));
    }
});

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_ad_network_key_2026';
const MINIMUM_WITHDRAWAL = 500.00;
const MINIMUM_ADVERTISER_DEPOSIT = 2000.00;
const HOST_URL = process.env.HOST_URL || 'https://ads-platform-vjsg.onrender.com';

const PAYFAST_MERCHANT_ID = process.env.PAYFAST_MERCHANT_ID || '32880521';
const PAYFAST_MERCHANT_KEY = process.env.PAYFAST_MERCHANT_KEY || 'wfx9nr9j9cvlm';

const db = mysql.createPool({
    host: process.env.TIDB_HOST || 'gateway01.eu-central-1.prod.aws.tidbcloud.com',
    port: parseInt(process.env.TIDB_PORT || '4000'),
    user: process.env.TIDB_USER || 'KLQaiBoivGWMnF9.root',
    password: process.env.TIDB_PASSWORD || 'QgYk345DiiCIdhM1',
    database: process.env.TIDB_DATABASE || 'policy_admin',
    ssl: { rejectUnauthorized: true },
    waitForConnections: true,
    connectionLimit: 10
});

async function seedDatabase() {
    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', ['admin']);
        if (rows.length === 0) {
            const hashedAdminPassword = await bcrypt.hash('admin', 10);
            await db.execute(
                `INSERT INTO users (name, email, password_hash, role, bank_name, account_number, branch_code, balance) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                ['L3 System Owner', 'admin', hashedAdminPassword, 'admin', 'System Bank', '000000000', '000', 0.00]
            );
        }
    } catch (err) {
        console.error('Seeding error:', err.message);
    }
}

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
// 1. AUTHENTICATION & BALANCE
// ==========================================

app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role, bank_name, account_number, branch_code } = req.body;
    if (!['advertiser', 'publisher'].includes(role)) return res.status(400).json({ error: 'Invalid role.' });
    if (!bank_name || !account_number || !branch_code) return res.status(400).json({ error: 'Banking details required.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.execute(
            `INSERT INTO users (name, email, password_hash, role, bank_name, account_number, branch_code, balance) 
             VALUES (?, ?, ?, ?, ?, ?, ?, 0.00)`,
            [name, email, hashedPassword, role, bank_name, account_number, branch_code]
        );
        res.status(201).json({ message: 'Registered successfully', userId: result.insertId });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Email already registered.' });
        res.status(500).json({ error: 'Registration failed.', details: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(404).json({ error: 'User not found.' });

        const user = rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials.' });

        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        res.json({
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role, balance: parseFloat(user.balance || 0) }
        });
    } catch (err) {
        res.status(500).json({ error: 'Login error.', details: err.message });
    }
});

app.get('/api/user/balance', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute('SELECT balance FROM users WHERE id = ?', [req.user.id]);
        if (rows.length === 0) return res.status(404).json({ error: 'User not found.' });

        let netRemainingFunds = 0;
        if (req.user.role === 'advertiser') {
            const [depRows] = await db.execute(
                'SELECT SUM(amount) AS total_deposited FROM advertiser_deposits WHERE user_id = ? AND status = "completed"',
                [req.user.id]
            );
            const totalDeposited = parseFloat(depRows[0].total_deposited || 0);

            const [spentRows] = await db.execute(
                'SELECT SUM(spent) AS total_spent FROM campaigns WHERE advertiser_id = ?',
                [req.user.id]
            );
            const totalSpent = parseFloat(spentRows[0].total_spent || 0);
            netRemainingFunds = totalDeposited - totalSpent;
        }

        res.json({
            balance: parseFloat(rows[0].balance || 0),
            net_remaining_funds: netRemainingFunds,
            required_deposit: MINIMUM_ADVERTISER_DEPOSIT,
            can_publish_ads: req.user.role === 'admin' || netRemainingFunds >= MINIMUM_ADVERTISER_DEPOSIT
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch balance.' });
    }
});

// ==========================================
// 2. PAYFAST DEPOSITS
// ==========================================

app.post('/api/advertiser/deposit-checkout', authenticateToken, async (req, res) => {
    if (req.user.role !== 'advertiser') return res.status(403).json({ error: 'Advertiser access only.' });

    const payfastData = {
        merchant_id: PAYFAST_MERCHANT_ID,
        merchant_key: PAYFAST_MERCHANT_KEY,
        return_url: `${HOST_URL}`,
        cancel_url: `${HOST_URL}`,
        notify_url: `${HOST_URL}/api/advertiser/deposit-notify`,
        m_payment_id: `DEP-${req.user.id}-${Date.now()}`,
        amount: MINIMUM_ADVERTISER_DEPOSIT.toFixed(2),
        item_name: `Ad Creator Deposit - User #${req.user.id}`,
        email_address: req.user.email
    };

    res.json({ gateway: 'https://www.payfast.co.za/eng/process', payload: payfastData });
});

app.post('/api/advertiser/deposit-notify', async (req, res) => {
    const paymentData = req.body;
    if (paymentData && paymentData.payment_status === 'COMPLETE') {
        const parts = paymentData.m_payment_id.split('-');
        if (parts.length >= 2) {
            const userId = parseInt(parts[1]);
            const amount = parseFloat(paymentData.amount_gross || MINIMUM_ADVERTISER_DEPOSIT);
            try {
                await db.execute(
                    `INSERT INTO advertiser_deposits (user_id, amount, payfast_payment_id, status) VALUES (?, ?, ?, 'completed')`,
                    [userId, amount, paymentData.pf_payment_id || 'PF-LIVE']
                );
                await db.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, userId]);
            } catch (err) {
                console.error('Deposit log error:', err.message);
            }
        }
    }
    res.status(200).send('OK');
});

// ==========================================
// 3. CAMPAIGNS & DEPLETION LOCK CHECK
// ==========================================

app.post('/api/advertiser/campaigns', authenticateToken, upload.single('media_file'), async (req, res) => {
    if (req.user.role !== 'advertiser' && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Advertiser access only.' });
    }

    if (req.user.role !== 'admin') {
        // Calculate net remaining funds (Deposits minus Spent)
        const [depRows] = await db.execute(
            'SELECT SUM(amount) AS total_deposited FROM advertiser_deposits WHERE user_id = ? AND status = "completed"',
            [req.user.id]
        );
        const totalDeposited = parseFloat(depRows[0].total_deposited || 0);

        const [spentRows] = await db.execute(
            'SELECT SUM(spent) AS total_spent FROM campaigns WHERE advertiser_id = ?',
            [req.user.id]
        );
        const totalSpent = parseFloat(spentRows[0].total_spent || 0);
        const netRemainingFunds = totalDeposited - totalSpent;

        if (netRemainingFunds < MINIMUM_ADVERTISER_DEPOSIT) {
            return res.status(403).json({ 
                error: `Publication denied. Your funds are depleted. Remaining funds (R${netRemainingFunds.toFixed(2)}) are below the minimum R${MINIMUM_ADVERTISER_DEPOSIT.toFixed(2)} threshold. Please deposit additional funds to continue.` 
            });
        }
    }

    const { title, target_url, budget, ad_type, text_content, html_content } = req.body;
    let mediaUrl = '';
    if (req.file) {
        mediaUrl = `${HOST_URL}/uploads/${req.file.filename}`;
    }

    const resolvedAdType = ad_type || 'image';

    try {
        const [result] = await db.execute(
            `INSERT INTO campaigns (advertiser_id, title, target_url, image_url, budget, ad_type, text_content, html_content, status, cpm, cpc) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 10.00, 2.00)`,
            [req.user.id, title, target_url || '', mediaUrl, budget, resolvedAdType, text_content || '', html_content || '']
        );
        res.status(201).json({ message: 'Campaign published successfully', campaignId: result.insertId, status: 'active' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to publish campaign.', details: err.message });
    }
});

// External Tool API Integration with Depletion Lock Check
app.post('/api/external/campaigns', authenticateToken, async (req, res) => {
    if (req.user.role !== 'advertiser' && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Advertiser authorization required.' });
    }

    if (req.user.role !== 'admin') {
        const [depRows] = await db.execute(
            'SELECT SUM(amount) AS total_deposited FROM advertiser_deposits WHERE user_id = ? AND status = "completed"',
            [req.user.id]
        );
        const totalDeposited = parseFloat(depRows[0].total_deposited || 0);

        const [spentRows] = await db.execute(
            'SELECT SUM(spent) AS total_spent FROM campaigns WHERE advertiser_id = ?',
            [req.user.id]
        );
        const totalSpent = parseFloat(spentRows[0].total_spent || 0);
        const netRemainingFunds = totalDeposited - totalSpent;

        if (netRemainingFunds < MINIMUM_ADVERTISER_DEPOSIT) {
            return res.status(403).json({ 
                error: `External publication denied. Funds depleted. Remaining funds: R${netRemainingFunds.toFixed(2)}.` 
            });
        }
    }

    const { title, target_url, media_url, budget, ad_type, text_content, html_content } = req.body;
    const resolvedAdType = ad_type || 'image';

    try {
        const [result] = await db.execute(
            `INSERT INTO campaigns (advertiser_id, title, target_url, image_url, budget, ad_type, text_content, html_content, status, cpm, cpc) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 10.00, 2.00)`,
            [req.user.id, title, target_url || '', media_url || '', budget || 2000.00, resolvedAdType, text_content || '', html_content || '']
        );
        res.status(201).json({ success: true, message: 'Campaign published via external tool API', campaignId: result.insertId, status: 'active' });
    } catch (err) {
        res.status(500).json({ error: 'External campaign publishing failed.', details: err.message });
    }
});

app.put('/api/advertiser/campaigns/:id/status', authenticateToken, async (req, res) => {
    const { status } = req.body;
    if (!['active', 'paused'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status value.' });
    }

    try {
        const [result] = await db.execute(
            'UPDATE campaigns SET status = ? WHERE id = ? AND advertiser_id = ?',
            [status, req.params.id, req.user.id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Campaign not found or unauthorized.' });
        res.json({ message: `Campaign successfully ${status}.`, status });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update campaign status.' });
    }
});

app.get('/api/advertiser/analytics', authenticateToken, async (req, res) => {
    if (req.user.role !== 'advertiser' && req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied.' });
    try {
        const [stats] = await db.execute(
            `SELECT c.*, 
                COUNT(CASE WHEN e.event_type = 'impression' THEN 1 END) AS impressions,
                COUNT(CASE WHEN e.event_type = 'click' THEN 1 END) AS clicks
             FROM campaigns c LEFT JOIN ad_events e ON c.id = e.campaign_id
             WHERE c.advertiser_id = ? GROUP BY c.id`,
            [req.user.id]
        );
        res.json({ analytics: stats });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch analytics.' });
    }
});

// ==========================================
// 4. PUBLISHER DOMAINS & EMBED CODE PERSISTENCE
// ==========================================

app.post('/api/publisher/domains', authenticateToken, async (req, res) => {
    if (req.user.role !== 'publisher' && req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied.' });
    const { domain_name } = req.body;
    try {
        await db.execute('INSERT INTO publisher_domains (publisher_id, domain_name, status) VALUES (?, ?, "active")', [req.user.id, domain_name]);
        const embedCode = `<!-- L3 Ad Network Widget -->\n<div id="ad-unit-slot" data-publisher-id="${req.user.id}" data-domain="${domain_name}"></div>\n<script src="${HOST_URL}/ad-tag.js" async></script>`;
        res.status(201).json({ message: 'Domain registered', embedCode });
    } catch (err) {
        res.status(500).json({ error: 'Domain registration failed.' });
    }
});

app.put('/api/publisher/domains/:id/status', authenticateToken, async (req, res) => {
    const { status } = req.body;
    if (!['active', 'paused'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status.' });
    }

    try {
        const [result] = await db.execute(
            'UPDATE publisher_domains SET status = ? WHERE id = ? AND publisher_id = ?',
            [status, req.params.id, req.user.id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Domain not found or unauthorized.' });
        res.json({ message: `Publisher domain widget successfully ${status}.`, status });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update domain status.' });
    }
});

app.get('/api/publisher/analytics', authenticateToken, async (req, res) => {
    if (req.user.role !== 'publisher' && req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied.' });
    try {
        const [userRows] = await db.execute('SELECT balance FROM users WHERE id = ?', [req.user.id]);
        const [eventStats] = await db.execute(
            `SELECT COUNT(CASE WHEN event_type = 'impression' THEN 1 END) AS impressions,
                    COUNT(CASE WHEN event_type = 'click' THEN 1 END) AS clicks,
                    SUM(publisher_payout) AS total_earned FROM ad_events WHERE publisher_id = ?`,
            [req.user.id]
        );
        const [domains] = await db.execute(
            `SELECT d.id, d.domain_name, d.status, 
                    COUNT(CASE WHEN e.event_type = 'impression' THEN 1 END) AS impressions,
                    COUNT(CASE WHEN e.event_type = 'click' THEN 1 END) AS clicks,
                    COALESCE(SUM(e.publisher_payout), 0) AS total_earned
             FROM publisher_domains d LEFT JOIN ad_events e ON d.publisher_id = e.publisher_id
             WHERE d.publisher_id = ? GROUP BY d.id`,
            [req.user.id]
        );

        const domainsWithEmbed = domains.map(dom => ({
            ...dom,
            embed_code: `<!-- L3 Ad Network Widget -->\n<div id="ad-unit-slot" data-publisher-id="${req.user.id}" data-domain="${dom.domain_name}"></div>\n<script src="${HOST_URL}/ad-tag.js" async></script>`
        }));

        res.json({
            current_balance: parseFloat(userRows[0].balance || 0),
            minimum_withdrawal_threshold: MINIMUM_WITHDRAWAL,
            can_withdraw: parseFloat(userRows[0].balance || 0) >= MINIMUM_WITHDRAWAL,
            impressions: eventStats[0].impressions || 0,
            clicks: eventStats[0].clicks || 0,
            total_earned: eventStats[0].total_earned || 0,
            domains: domainsWithEmbed
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to load stats.' });
    }
});

app.post('/api/publisher/withdraw', authenticateToken, async (req, res) => {
    if (req.user.role !== 'publisher' && req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied.' });
    try {
        const [userRows] = await db.execute('SELECT balance FROM users WHERE id = ?', [req.user.id]);
        const balance = parseFloat(userRows[0].balance || 0);
        if (balance < MINIMUM_WITHDRAWAL) {
            return res.status(400).json({ error: `Threshold not reached. Balance: R${balance.toFixed(2)}.` });
        }
        await db.execute('UPDATE users SET balance = 0.00 WHERE id = ?', [req.user.id]);
        await db.execute('INSERT INTO withdrawals (user_id, amount, status) VALUES (?, ?, "pending")', [req.user.id, balance]);
        res.json({ message: `Payout request of R${balance.toFixed(2)} submitted successfully.` });
    } catch (err) {
        res.status(500).json({ error: 'Withdrawal failed.' });
    }
});

// ==========================================
// 5. AD-TAG.JS SCRIPT ENDPOINT
// ==========================================

app.get('/ad-tag.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.send(`
        (function() {
            const slot = document.getElementById('ad-unit-slot');
            if (!slot) return;
            const pubId = slot.getAttribute('data-publisher-id');
            const domain = slot.getAttribute('data-domain');
            if (!pubId || !domain) return;

            fetch('${HOST_URL}/api/ads/serve?publisher_id=' + pubId + '&domain=' + encodeURIComponent(domain))
                .then(response => response.json())
                .then(data => {
                    if (data && data.html) {
                        slot.innerHTML = data.html;
                    }
                })
                .catch(err => console.error('L3 Ad Load Error:', err));
        })();
    `);
});

// ==========================================
// 6. AD SERVING ENGINE
// ==========================================

app.get('/api/ads/serve', async (req, res) => {
    const { publisher_id, domain } = req.query;
    if (!publisher_id || !domain) return res.status(400).json({ error: 'Missing parameters.' });

    try {
        const [domains] = await db.execute(
            'SELECT * FROM publisher_domains WHERE publisher_id = ? AND domain_name = ? AND status = "active"',
            [publisher_id, domain]
        );
        if (domains.length === 0) return res.status(403).json({ error: 'Domain is paused or unregistered.' });

        const [campaigns] = await db.execute(
            'SELECT * FROM campaigns WHERE status = "active" AND (budget - spent) > 0 ORDER BY RAND() LIMIT 1'
        );
        if (campaigns.length === 0) return res.status(404).json({ error: 'No active inventory.' });

        const ad = campaigns[0];
        const grossCost = parseFloat(ad.cpm) / 1000;
        const publisherShare = grossCost * 0.50;
        const agencyShare = grossCost * 0.50;

        await db.execute('INSERT INTO ad_events (campaign_id, publisher_id, event_type, gross_cost, publisher_payout, agency_revenue, ip_address) VALUES (?, ?, "impression", ?, ?, ?, ?)', [ad.id, publisher_id, grossCost, publisherShare, agencyShare, req.ip]);
        await db.execute('UPDATE campaigns SET spent = spent + ? WHERE id = ?', [grossCost, ad.id]);
        await db.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [publisherShare, publisher_id]);

        let mediaHtml = '';
        if (ad.ad_type === 'video') {
            mediaHtml = `<video src="${ad.image_url}" autoplay muted loop style="max-width:100%;height:auto;"></video>`;
        } else if (ad.ad_type === 'text') {
            mediaHtml = `<div style="padding:15px;background:#f9f9f9;font-weight:bold;color:#333;">${ad.text_content || ad.title}</div>`;
        } else if (ad.ad_type === 'html_rich') {
            mediaHtml = `<div>${ad.html_content || ''}</div>`;
        } else {
            mediaHtml = `<img src="${ad.image_url}" style="max-width:100%;height:auto;" />`;
        }

        res.json({
            ad_id: ad.id,
            ad_type: ad.ad_type,
            html: `<div style="border:1px solid #ccc;padding:10px;text-align:center;"><a href="${HOST_URL}/api/ads/click?campaign_id=${ad.id}&publisher_id=${publisher_id}" target="_blank">${mediaHtml}<h4 style="margin-top:8px;">${ad.title}</h4></a></div>`
        });
    } catch (err) {
        res.status(500).json({ error: 'Ad serve error.' });
    }
});

app.get('/api/ads/click', async (req, res) => {
    const { campaign_id, publisher_id } = req.query;
    try {
        const [campaigns] = await db.execute('SELECT * FROM campaigns WHERE id = ?', [campaign_id]);
        if (campaigns.length === 0) return res.status(404).send('Campaign not found.');
        const ad = campaigns[0];
        const grossCost = parseFloat(ad.cpc);
        const publisherShare = publisher_id ? grossCost * 0.50 : 0.00;
        const agencyShare = publisher_id ? grossCost * 0.50 : grossCost;

        await db.execute('INSERT INTO ad_events (campaign_id, publisher_id, event_type, gross_cost, publisher_payout, agency_revenue, ip_address) VALUES (?, ?, "click", ?, ?, ?, ?)', [campaign_id, publisher_id || null, grossCost, publisherShare, agencyShare, req.ip]);
        await db.execute('UPDATE campaigns SET spent = spent + ? WHERE id = ?', [grossCost, campaign_id]);
        if (publisher_id) await db.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [publisherShare, publisher_id]);

        res.redirect(ad.target_url);
    } catch (err) {
        res.status(500).send('Redirect error.');
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
    console.log(`L3 Ad Network Server active on port ${PORT}`);
    await seedDatabase();
});