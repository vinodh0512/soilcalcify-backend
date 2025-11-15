// SoilCalcify backend server (Express + MySQL)
// Reads credentials from environment variables; see .env.example

const express = require('express')
const cors = require('cors')
const mysql = require('mysql2/promise')
const dotenv = require('dotenv')
const cookieParser = require('cookie-parser')
const crypto = require('crypto')
const bcrypt = require('bcrypt')
const path = require('path')
const jwt = require('jsonwebtoken')

// Load env from backend/.env explicitly to avoid cwd issues
dotenv.config({ path: path.join(__dirname, '.env') })

const PORT = process.env.PORT || 5000
const DB_HOST = process.env.DB_HOST || 'localhost'
const DB_PORT = Number(process.env.DB_PORT || 3306)
const DB_USER = process.env.DB_USER || 'root'
const DB_PASSWORD = process.env.DB_PASSWORD || process.env.DB_PASS || ''
const DB_NAME = process.env.DB_NAME || ''
const DB_SSL = String(process.env.DB_SSL || '').toLowerCase() === 'true'
const USE_S3 = String(process.env.USE_S3 || '').toLowerCase() === 'true'
const S3_BUCKET = process.env.S3_BUCKET || ''
const S3_REGION = process.env.S3_REGION || ''
const S3_ACCESS_KEY_ID = process.env.S3_ACCESS_KEY_ID || ''
const S3_SECRET_ACCESS_KEY = process.env.S3_SECRET_ACCESS_KEY || ''
const S3_BASE_URL = process.env.S3_BASE_URL || ''
const DB_SSL_REJECT_UNAUTHORIZED = String(process.env.DB_SSL_REJECT_UNAUTHORIZED || '').toLowerCase() === 'true'
const PROFILE_ENC_KEY = process.env.PROFILE_ENC_KEY || ''
const JWT_SECRET = process.env.JWT_SECRET || process.env.JWT_KEY || 'change-me-in-env'
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d'

// Log sanitized configuration to confirm env is connected (no password logged)
console.log('Backend configuration loaded:', {
  PORT,
  DB_HOST,
  DB_PORT,
  DB_USER,
  DB_NAME,
  DB_SSL,
  DB_SSL_REJECT_UNAUTHORIZED,
  USE_S3,
  S3_BUCKET,
  S3_REGION,
  PROFILE_ENC_KEY_SET: PROFILE_ENC_KEY ? true : false,
})

const app = express()
app.disable('x-powered-by')

// Behind proxies (Railway/Render), trust proxy so secure cookies and protocol are handled correctly
app.set('trust proxy', 1)

// Strict CORS: allow configured origins and common localhost dev origins
function expandOrigins(list) {
  const out = new Set()
  for (const item of list) {
    const origin = String(item || '').trim().replace(/\/$/, '')
    if (!origin) continue
    out.add(origin)
    try {
      const u = new URL(origin)
      const host = u.host || ''
      if (host.startsWith('www.')) {
        const bare = `${u.protocol}//${host.replace(/^www\./, '')}`
        out.add(bare)
      } else {
        const www = `${u.protocol}//www.${host}`
        out.add(www)
      }
    } catch {}
  }
  return Array.from(out)
}

const ALLOWED_ORIGINS_INPUT = (process.env.ALLOWED_ORIGINS || process.env.ALLOWED_ORIGIN || 'https://soilcalcify.com,https://www.soilcalcify.com')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
const DEV_ORIGINS = ['http://localhost:5173','http://127.0.0.1:5173','http://localhost:3000','http://127.0.0.1:3000']
const STATIC_ALLOWED_ORIGINS = Array.from(new Set([...expandOrigins(ALLOWED_ORIGINS_INPUT), ...DEV_ORIGINS]))
const ALLOWED_ORIGIN_REGEX = process.env.ALLOWED_ORIGIN_REGEX ? new RegExp(process.env.ALLOWED_ORIGIN_REGEX) : null
const FRONTEND_URL = process.env.FRONTEND_URL || STATIC_ALLOWED_ORIGINS[0] || 'https://soilcalcify.com'
const SECURE_COOKIES = String(process.env.SECURE_COOKIES || 'true').toLowerCase() === 'true'
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true)
      if (STATIC_ALLOWED_ORIGINS.includes(origin)) return cb(null, true)
      if (ALLOWED_ORIGIN_REGEX && ALLOWED_ORIGIN_REGEX.test(origin)) return cb(null, true)
      console.warn('Blocked CORS origin:', origin)
      return cb(new Error('Not allowed by CORS'))
    },
    credentials: true,
    methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Accept', 'Authorization', 'X-CSRF-Token'],
  })
)
// Preflight support
app.options('*', cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true)
    if (STATIC_ALLOWED_ORIGINS.includes(origin)) return cb(null, true)
    if (ALLOWED_ORIGIN_REGEX && ALLOWED_ORIGIN_REGEX.test(origin)) return cb(null, true)
    return cb(new Error('Not allowed by CORS'))
  },
  credentials: true,
  methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'Authorization', 'X-CSRF-Token'],
}))

app.use(cookieParser())
// Serve uploaded files (read-only)
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable')
  }
}))
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff')
  res.set('X-Frame-Options', 'SAMEORIGIN')
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  next()
})

// Create a reusable MySQL connection pool
const pool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 15000,
  ssl: { rejectUnauthorized: false },
});

pool.query("SELECT 1")
  .then(() => console.log("Database: Connected"))
  .catch(err => console.error("Database Error:", err.message))

app.use((req, res, next) => {
  const start = Date.now()
  const rid = crypto.randomBytes(16).toString('hex')
  res.set('X-Request-Id', rid)
  res.on('finish', () => {
    const ms = Date.now() - start
    console.log(`[${new Date().toISOString()}] ${rid} ${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms}ms)`)
  })
  next()
})

// Basic health routes for frontend connectivity tests
function buildBanner({ port, mode, dbConnected }) {
  const lines = [
    '====================================================',
    '         🚀 SoilCalcify Backend is Running!',
    '====================================================',
    '📡 Server Status: ACTIVE',
    `🌐 Listening on Port: ${port}`,
    `🧠 Mode: ${mode}`,
    `🗄️ Database: ${dbConnected ? 'Connected & Decoding Queries...' : 'Disconnected'}`,
    '🔐 Auth System: JWT Enabled',
    '🛰️ CORS: Configured Successfully',
    '📁 Routes: Loaded & Ready',
    '====================================================',
  ]
  return lines.join('\n')
}

async function testDbConnection() {
  try {
    const conn = await pool.getConnection()
    try {
      await conn.query('SELECT 1')
      return { ok: true }
    } finally {
      try { conn.release() } catch {}
    }
  } catch (err) {
    const msg = err?.message || String(err)
    const code = err?.code || null
    console.error(`Database Error: ${msg}${code ? ` (code: ${code})` : ''}`)
    return { ok: false, error: msg, code }
  }
}

app.get('/', async (req, res) => {
  const check = await testDbConnection()
  const port = req.socket?.localPort || PORT
  const mode = process.env.NODE_ENV || 'production'
  res.type('text/plain').send(buildBanner({ port, mode, dbConnected: !!check.ok }))
})

app.get('/api/test', (req, res) => {
  res.json({ status: 'success', message: 'Frontend connected to Backend successfully!' })
})

// Allow larger JSON payloads for base64 images
app.use(express.json({ limit: '10mb' }))

function getClientIp(req) {
  const xff = (req.headers['x-forwarded-for'] || '').toString()
  if (xff) {
    const parts = xff.split(',').map(s => s.trim()).filter(Boolean)
    if (parts.length) return parts[0]
  }
  const ip = req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || ''
  return String(ip).replace(/^::ffff:/, '')
}

function extractBearer(req) {
  const h = String(req.headers['authorization'] || '').trim()
  const m = /^Bearer\s+(.+)$/i.exec(h)
  return m ? m[1] : null
}

function requireAuth(req, res, next) {
  try {
    const token = extractBearer(req)
    if (!token) return res.status(401).json({ error: 'Authentication required' })
    const payload = jwt.verify(token, JWT_SECRET)
    req.auth = { userId: Number(payload.sub) || Number(payload.userId) || 0, isAdmin: !!payload.isAdmin }
    if (!req.auth.userId) return res.status(401).json({ error: 'Authentication required' })
    next()
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

function requireAdmin(req, res, next) {
  try {
    const token = extractBearer(req)
    if (!token) return res.status(401).json({ error: 'Authentication required' })
    const payload = jwt.verify(token, JWT_SECRET)
    const isAdmin = !!payload.isAdmin
    const userId = Number(payload.sub) || Number(payload.userId) || 0
    if (!isAdmin) return res.status(403).json({ error: 'Admin privileges required' })
    req.auth = { userId, isAdmin }
    next()
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

// Rate limiter (in-memory) per IP for signup attempts
const signupRateLimitWindowMs = 15 * 60 * 1000 // 15 minutes
const signupRateMax = 10 // attempts per window
const rateStore = new Map()
function signupRateLimiter(req, res, next) {
  const key = req.ip || req.headers['x-forwarded-for'] || 'unknown'
  const now = Date.now()
  const entry = rateStore.get(key) || { count: 0, windowStart: now }
  if (now - entry.windowStart > signupRateLimitWindowMs) {
    entry.count = 0
    entry.windowStart = now
  }
  entry.count += 1
  rateStore.set(key, entry)
  if (entry.count > signupRateMax) {
    return res.status(429).json({ error: 'Too many signup attempts. Please try again later.' })
  }
  next()
}

function makeRateLimiter({ windowMs, max }) {
  const store = new Map()
  return function (req, res, next) {
    const key = req.ip || req.headers['x-forwarded-for'] || 'unknown'
    const now = Date.now()
    const entry = store.get(key) || { count: 0, windowStart: now }
    if (now - entry.windowStart > windowMs) {
      entry.count = 0
      entry.windowStart = now
    }
    entry.count += 1
    store.set(key, entry)
    if (entry.count > max) {
      return res.status(429).json({ error: 'Too many requests' })
    }
    next()
  }
}

const loginRateLimiter = makeRateLimiter({ windowMs: 15 * 60 * 1000, max: 20 })

// CSRF protection using double-submit cookie pattern
const CSRF_COOKIE_NAME = 'csrfToken'
function requireCsrf(req, res, next) {
  // Only enforce for state-changing requests
  const method = req.method.toUpperCase()
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return next()
  const cookieToken = req.cookies[CSRF_COOKIE_NAME]
  const headerToken = req.headers['x-csrf-token']
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    console.warn('CSRF validation failed', {
      hasCookie: !!cookieToken,
      hasHeader: !!headerToken,
      cookieLen: cookieToken ? cookieToken.length : 0,
      headerLen: headerToken ? headerToken.length : 0,
    })
    return res.status(403).json({ error: 'Invalid CSRF token' })
  }
  next()
}

app.get('/api/csrf-token', (req, res) => {
  const token = crypto.randomBytes(24).toString('hex')
  res.cookie(CSRF_COOKIE_NAME, token, {
    httpOnly: false,
    sameSite: 'none',
    secure: SECURE_COOKIES,
    domain: COOKIE_DOMAIN,
    maxAge: 60 * 60 * 1000,
  })
  res.json({ token })
})

// Validation helper
function validateSignupPayload(body) {
  const errors = []
  const name = (body.name || '').trim()
  const email = (body.email || '').trim().toLowerCase()
  const password = (body.password || '')
  if (!name || name.length < 2) errors.push('Name must be at least 2 characters')
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  if (!emailRegex.test(email)) errors.push('Invalid email address')
  if (!password || password.length < 8) errors.push('Password must be at least 8 characters')
  return { valid: errors.length === 0, errors, name, email, password }
}

// Basic input sanitization
function sanitizeText(str, { maxLen = 255, preserveCase = true } = {}) {
  if (typeof str !== 'string') return ''
  let s = str.trim()
  s = s.replace(/[\u0000-\u001F\u007F]/g, ' ') // strip control chars
  s = s.replace(/\s+/g, ' ')
  if (!preserveCase) s = s.toLowerCase()
  if (s.length > maxLen) s = s.slice(0, maxLen)
  return s
}

function sanitizeHtmlBasic(str, { maxLen = 4096 } = {}) {
  if (typeof str !== 'string') return ''
  let s = str.trim()
  // naive HTML tag removal; for production use DOMPurify or similar
  s = s.replace(/<[^>]*>/g, '')
  s = s.replace(/[\u0000-\u001F\u007F]/g, ' ')
  if (s.length > maxLen) s = s.slice(0, maxLen)
  return s
}

function validatePhoneE164(phone) {
  const p = String(phone || '').trim()
  return /^\+[1-9]\d{1,14}$/.test(p)
}

// AES-256-GCM helpers for encrypting avatar blobs
function getEncKey() {
  if (!PROFILE_ENC_KEY) return null
  let key = null
  try {
    if (/^[0-9a-fA-F]+$/.test(PROFILE_ENC_KEY) && PROFILE_ENC_KEY.length === 64) {
      key = Buffer.from(PROFILE_ENC_KEY, 'hex')
    } else {
      const b = Buffer.from(PROFILE_ENC_KEY, 'base64')
      if (b.length === 32) key = b
    }
  } catch {}
  return key && key.length === 32 ? key : null
}

function encryptBuffer(buf) {
  const key = getEncKey()
  if (!key) return { cipher: buf, iv: null, tag: null, encrypted: false }
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const enc = Buffer.concat([cipher.update(buf), cipher.final()])
  const tag = cipher.getAuthTag()
  return { cipher: enc, iv, tag, encrypted: true }
}

function decryptBuffer(enc, iv, tag) {
  const key = getEncKey()
  if (!key || !iv || !tag) return enc
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(tag)
  const dec = Buffer.concat([decipher.update(enc), decipher.final()])
  return dec
}

// Data access helpers (unit-testable)
async function userExists(pool, email) {
  const [rows] = await pool.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [email])
  return rows && rows.length > 0
}

async function createUser(pool, { name, email, passwordHash }) {
  const [result] = await pool.execute(
    'INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, NOW())',
    [name, email, passwordHash]
  )
  return result && result.insertId
}

// Signup endpoint
app.post('/api/signup', signupRateLimiter, async (req, res) => {
  try {
    const { valid, errors, name, email, password } = validateSignupPayload(req.body || {})
    if (!valid) {
      return res.status(400).json({ error: 'Validation failed', details: errors })
    }

    // Check existing user
    if (await userExists(pool, email)) {
      return res.status(409).json({ error: 'User already exists' })
    }

    // Hash password
    const saltRounds = 10
    const passwordHash = await bcrypt.hash(password, saltRounds)

    // Insert new user
    try {
      const userId = await createUser(pool, { name, email, passwordHash })
      return res.status(200).json({ message: 'Signup successful', userId })
    } catch (err) {
      // Gracefully handle duplicate key race conditions
      if (err && err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'User already exists' })
      }
      throw err
    }
  } catch (err) {
    console.error('Signup error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Login endpoint
app.post('/api/login', loginRateLimiter, async (req, res) => {
  try {
    const email = String((req.body?.email || '')).trim().toLowerCase()
    const password = String(req.body?.password || '')
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' })
    }

    const [rows] = await pool.execute('SELECT id, name, email, password_hash FROM users WHERE email = ? LIMIT 1', [email])
    if (!rows || rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    const user = rows[0]
    const ok = await bcrypt.compare(password, user.password_hash)
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const token = jwt.sign({ sub: user.id, email: user.email, name: user.name, isAdmin: false }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN })
    const base = FRONTEND_URL.replace(/\/$/, '')
    return res.status(200).json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email }, redirects: [`${base}/login`, `${base}/`] })
  } catch (err) {
    console.error('Login error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Logout endpoint (stateless JWT): instruct client to clear tokens
app.post('/api/logout', (req, res) => {
  try {
    res.set('Cache-Control', 'no-store')
    return res.status(200).json({ message: 'Logged out' })
  } catch {
    return res.status(200).json({ message: 'Logged out' })
  }
})

// Admin login (username/password) using env-configured credentials.
// Configure ADMIN_USERNAME and ADMIN_PASSWORD_HASH in backend/.env
app.post('/api/admin/login', loginRateLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {}
    if (!username || !password) {
      return res.status(400).json({ error: 'Missing credentials' })
    }
    const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin'
    const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || ''
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || ''
    const userOk = String(username) === ADMIN_USERNAME
    let passOk = false
    if (ADMIN_PASSWORD_HASH) {
      passOk = await bcrypt.compare(String(password), ADMIN_PASSWORD_HASH)
    } else if (ADMIN_PASSWORD) {
      passOk = String(password) === ADMIN_PASSWORD
    } else {
      passOk = String(password) === 'admin123'
    }
    if (!userOk || !passOk) {
      return res.status(401).json({ error: 'Invalid admin credentials' })
    }
    const token = jwt.sign({ sub: 0, username: ADMIN_USERNAME, isAdmin: true }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN })
    return res.status(200).json({ message: 'Admin login successful', token })
  } catch (err) {
    console.error('Admin login error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Session heartbeat to maintain active session state
// Session endpoints removed in JWT-based auth

// Redirect unauthorized direct /admin route hits to frontend dashboard
app.get(['/admin', '/admin/*'], (req, res) => {
  const token = extractBearer(req)
  try {
    const payload = token ? jwt.verify(token, JWT_SECRET) : null
    if (!payload || !payload.isAdmin) {
      return res.redirect(302, `${FRONTEND_URL.replace(/\/$/, '')}`)
    }
    return res.status(200).type('text/plain').send('OK')
  } catch {
    return res.redirect(302, `${FRONTEND_URL.replace(/\/$/, '')}`)
  }
})

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  })
})

app.get('/api/debug/whoami', (req, res) => {
  const token = extractBearer(req)
  if (!token) return res.json({ authenticated: false })
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    const userId = Number(payload.sub) || Number(payload.userId) || 0
    return res.json({ authenticated: true, userId, isAdmin: !!payload.isAdmin })
  } catch {
    return res.json({ authenticated: false })
  }
})

// Database connectivity check
app.get('/db/ping', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 AS ping')
    res.json({ connected: true, result: rows[0] })
  } catch (err) {
    console.error('DB ping error:', err.message)
    res.status(500).json({ connected: false, error: err.message })
  }
})

// DB diagnostics endpoint (current user and selected database)
app.get('/db/diagnostics', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT CURRENT_USER() AS user, DATABASE() AS db')
    res.json({ user: rows[0]?.user || null, database: rows[0]?.db || null })
  } catch (err) {
    res.status(500).json({ error: err.message, code: err.code || null })
  }
})

// MySQL version endpoint (useful for diagnostics)
app.get('/db/version', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT VERSION() AS version')
    res.json({ version: rows[0]?.version || null })
  } catch (err) {
    console.error('DB version error:', err.message)
    res.status(500).json({ error: err.message })
  }
})

// ---------- Analytics: Calculator usage (anonymous and authenticated) ----------
app.post('/api/analytics/track', async (req, res) => {
  try {
    const { tool, params, result } = req.body || {}
    const t = String(tool || '').trim().toLowerCase()
    if (!t) return res.status(400).json({ error: 'tool is required' })
    const ip = getClientIp(req)
    const ua = String(req.headers['user-agent'] || '')
    let userId = null
    try {
      const token = extractBearer(req)
      if (token) {
        const payload = jwt.verify(token, JWT_SECRET)
        userId = Number(payload.sub) || Number(payload.userId) || null
      }
    } catch {}
    const p = typeof params === 'object' ? JSON.stringify(params).slice(0, 65535) : (typeof params === 'string' ? params : null)
    const r = typeof result === 'object' ? JSON.stringify(result).slice(0, 65535) : (typeof result === 'string' ? result : null)
    const sql = `INSERT INTO \`${DB_NAME}\`.analytics_events (user_id, ip_address, user_agent, tool, params, result) VALUES (?, ?, ?, ?, ?, ?)`
    const [dbRes] = await pool.execute(sql, [userId, ip || null, ua || null, t, p, r])
    return res.status(201).json({ id: dbRes.insertId })
  } catch (err) {
    console.error('POST /api/analytics/track error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Recent analytics events: filter by ip (anonymous) or user
app.get('/api/analytics/recent', async (req, res) => {
  try {
    const ip = String(req.query.ip || '').trim()
    const limit = Math.min(50, Math.max(1, parseInt(String(req.query.limit || '20'), 10) || 20))
    const whereParts = []
    const params = []
    if (ip) { whereParts.push('ip_address = ?'); params.push(ip) }
    const whereSql = whereParts.length ? ('WHERE ' + whereParts.join(' AND ')) : ''
    const [rows] = await pool.query(`SELECT id, user_id, ip_address, user_agent, tool, params, result, created_at FROM \`${DB_NAME}\`.analytics_events ${whereSql} ORDER BY created_at DESC LIMIT ?`, [...params, limit])
    res.set('Cache-Control', 'no-store')
    return res.json({ items: rows })
  } catch (err) {
    console.error('GET /api/analytics/recent error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Contact form endpoint: saves to separate 'carstev' table
app.post('/api/contact', requireCsrf, async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      company,
      inquiryType,
      subject,
      message,
    } = req.body || {}

    // Basic validation
    const errors = []
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    const fn = sanitizeText(firstName, { maxLen: 100 })
    const ln = sanitizeText(lastName, { maxLen: 100 })
    const em = sanitizeText(email, { maxLen: 255, preserveCase: true })
    const co = sanitizeText(company, { maxLen: 255 })
    const iq = sanitizeText(inquiryType, { maxLen: 50, preserveCase: false })
    const sj = sanitizeText(subject, { maxLen: 255 })
    const ms = sanitizeHtmlBasic(message, { maxLen: 8192 })

    if (!fn) errors.push('firstName required')
    if (!ln) errors.push('lastName required')
    if (!em || !emailRegex.test(em)) errors.push('valid email required')
    if (!iq) errors.push('inquiryType required')
    if (!sj) errors.push('subject required')
    if (!ms) errors.push('message required')
    if (errors.length) return res.status(400).json({ error: 'Invalid payload', details: errors })

    const sql = `
      INSERT INTO \`${DB_NAME}\`.carstev
        (first_name, last_name, email, company, inquiry_type, subject, message)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `
    const params = [fn, ln, em, co || null, iq, sj, ms]
    const [result] = await pool.execute(sql, params)
    return res.status(201).json({ id: result.insertId, message: 'Contact message submitted' })
  } catch (err) {
    console.error('POST /api/contact error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Admin: fetch contact messages with pagination, sorting, search, and status filter
app.get('/api/admin/contact', requireAdmin, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1)
    const limit = Math.min(100, Math.max(1, parseInt(String(req.query.limit || '20'), 10) || 20))
    const q = String(req.query.q || '').trim()
    const status = String(req.query.status || '').trim().toLowerCase() // 'read'|'unread'|''
    const sort = String(req.query.sort || 'created_at').trim().toLowerCase()
    const dir = String(req.query.dir || 'desc').trim().toLowerCase() === 'asc' ? 'ASC' : 'DESC'

    const sortMap = {
      created_at: '`created_at`',
      name: "CONCAT(`first_name`, ' ', `last_name`)",
      email: '`email`',
      status: '`read_status`',
    }
    const orderBy = sortMap[sort] || sortMap.created_at

    const whereParts = []
    const params = []
    if (q) {
      whereParts.push("(CONCAT(`first_name`, ' ', `last_name`) LIKE ? OR `email` LIKE ? OR `subject` LIKE ? OR `message` LIKE ?)")
      const like = `%${q}%`
      params.push(like, like, like, like)
    }
    if (status === 'read') { whereParts.push('`read_status` = 1') }
    if (status === 'unread') { whereParts.push('`read_status` = 0') }
    const whereSql = whereParts.length ? ('WHERE ' + whereParts.join(' AND ')) : ''

    // Count total
    const [countRows] = await pool.query(`SELECT COUNT(*) AS cnt FROM \`${DB_NAME}\`.carstev ${whereSql}`, params)
    const total = Number(countRows?.[0]?.cnt || 0)

    // Data page
    const offset = (page - 1) * limit
    const [rows] = await pool.query(
      `SELECT id, CONCAT(first_name, ' ', last_name) AS name, email, phone, subject, message, created_at, read_status
       FROM \`${DB_NAME}\`.carstev
       ${whereSql}
       ORDER BY ${orderBy} ${dir}
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    )

    res.set('Cache-Control', 'no-store')
    return res.json({ items: rows, total })
  } catch (err) {
    console.error('GET /api/admin/contact error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Admin: mark contact message read/unread
app.patch('/api/admin/contact/:id', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id)
    if (!id) return res.status(400).json({ error: 'Invalid id' })
    const { read } = req.body || {}
    const val = read ? 1 : 0
    const [result] = await pool.execute(`UPDATE \`${DB_NAME}\`.carstev SET read_status = ? WHERE id = ?`, [val, id])
    return res.status(200).json({ updated: result?.affectedRows || 0 })
  } catch (err) {
    console.error('PATCH /api/admin/contact/:id error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Ensure schema exists (idempotent)
async function ensureSchema() {
  try {
    if (!DB_NAME) {
      console.warn('Schema skipped: DB_NAME is not set. Configure .env and restart to enable table creation.')
      return
    }
    // Create database if it does not exist (idempotent)
    const createDbSQL = `CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`
    await pool.execute(createDbSQL)

    // Create users table if it does not exist
    const createUsersSQL = `
      CREATE TABLE IF NOT EXISTS \`${DB_NAME}\`.users (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY users_email_unique (email)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `
    await pool.execute(createUsersSQL)
    console.log('Schema ensured: users table exists')
    // Profile fields and indexes (idempotent add; ignore duplicates)
    const alterStatements = [
      // Profile columns (no avatar fields)
      `ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN bio TEXT NULL`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN location VARCHAR(255) NULL`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN website_url VARCHAR(255) NULL`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN twitter_url VARCHAR(255) NULL`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN linkedin_url VARCHAR(255) NULL`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN github_url VARCHAR(255) NULL`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD INDEX idx_users_updated_at (updated_at)`,
      // Enhanced profile structure
      `ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN first_name VARCHAR(50) NOT NULL DEFAULT ''`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN last_name VARCHAR(50) NOT NULL DEFAULT ''`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN phone VARCHAR(20) NULL`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN company VARCHAR(100) NULL`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN title VARCHAR(100) NULL`,
      // Indexes and constraints
      `ALTER TABLE \`${DB_NAME}\`.users ADD INDEX idx_users_name (first_name, last_name)`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD UNIQUE KEY users_phone_unique (phone)`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD CONSTRAINT chk_phone_format CHECK (phone IS NULL OR phone REGEXP '^\\+[1-9][0-9]{1,14}$')`,
      `ALTER TABLE \`${DB_NAME}\`.users ADD CONSTRAINT chk_email_format CHECK (email REGEXP '^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$')`
    ]
    for (const sql of alterStatements) {
      try {
        await pool.execute(sql)
      } catch (err) {
        const code = err && err.code
        if (code !== 'ER_DUP_FIELDNAME' && code !== 'ER_DUP_KEYNAME' && code !== 'ER_CHECK_CONSTRAINT_VIOLATED') {
          console.warn('Schema alter failed (non-fatal):', code || err.message)
        }
      }
    }

    // Avatar URL column (idempotent)
    try {
      await pool.execute(`ALTER TABLE \`${DB_NAME}\`.users ADD COLUMN avatar_url VARCHAR(1024) NULL`)
    } catch (err) {
      const code = err && err.code
      if (code !== 'ER_DUP_FIELDNAME') {
        console.warn('Avatar column add non-fatal:', code || err.message)
      }
    }

    // Backfill first_name/last_name from existing name field (best-effort)
    try {
      await pool.execute(
        `UPDATE \`${DB_NAME}\`.users
         SET first_name = IF(INSTR(name, ' ') > 0, SUBSTRING_INDEX(name, ' ', 1), name),
             last_name = IF(INSTR(name, ' ') > 0, SUBSTRING_INDEX(name, ' ', -1), '')
         WHERE first_name = '' OR last_name = ''`
      )
    } catch (err) {
      console.warn('Backfill first/last name failed (non-fatal):', err.code || err.message)
    }

    // Calculation history table (idempotent)
    const createCalcSQL = `
      CREATE TABLE IF NOT EXISTS \`${DB_NAME}\`.calculation_history (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id INT UNSIGNED NOT NULL,
        params TEXT NOT NULL,
        result TEXT NOT NULL,
        performed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        INDEX idx_calc_user_performed (user_id, performed_at),
        INDEX idx_calc_performed (performed_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `
    await pool.execute(createCalcSQL)
    // Optional fulltext index for search across params/result
    try {
      await pool.execute(`ALTER TABLE \`${DB_NAME}\`.calculation_history ADD FULLTEXT INDEX ft_calc_params_result (params, result)`)
    } catch (err) {
      const code = err && err.code
      if (code !== 'ER_DUP_KEYNAME') {
        console.warn('Fulltext index not added (non-fatal):', code || err.message)
      }
    }
    // Add foreign key constraint to link calculation_history.user_id -> users.id
    try {
      await pool.execute(
        `ALTER TABLE \`${DB_NAME}\`.calculation_history
         ADD CONSTRAINT fk_calculation_user
         FOREIGN KEY (user_id) REFERENCES \`${DB_NAME}\`.users(id)
         ON DELETE CASCADE`
      )
    } catch (err) {
      const code = err && err.code
      if (code !== 'ER_DUP_KEYNAME' && code !== 'ER_CANNOT_ADD_FOREIGN') {
        console.warn('FK add failed (non-fatal):', code || err.message)
      }
    }
    console.log('Schema ensured: calculation_history table exists')

    const createAvatarsSQL = `
      CREATE TABLE IF NOT EXISTS \`${DB_NAME}\`.user_avatars (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id INT UNSIGNED NOT NULL,
        path VARCHAR(1024) NOT NULL,
        mime VARCHAR(64) NOT NULL,
        size BIGINT UNSIGNED NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        INDEX idx_user_avatars_user_created (user_id, created_at),
        CONSTRAINT fk_user_avatars_user FOREIGN KEY (user_id) REFERENCES \`${DB_NAME}\`.users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `
    await pool.execute(createAvatarsSQL)

    // Contact messages table (requested as separate 'carstev' table)
    const createContactSQL = `
      CREATE TABLE IF NOT EXISTS \`${DB_NAME}\`.carstev (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL,
        company VARCHAR(255) NULL,
        inquiry_type VARCHAR(50) NOT NULL,
        subject VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        INDEX idx_carstev_created (created_at),
        INDEX idx_carstev_inquiry (inquiry_type),
        INDEX idx_carstev_email (email)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `
    await pool.execute(createContactSQL)
    // Optional email format check (best-effort; ignore failure if unsupported)
    try {
      await pool.execute(`ALTER TABLE \`${DB_NAME}\`.carstev ADD CONSTRAINT chk_carstev_email CHECK (email REGEXP '^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$')`)
    } catch (err) {
      const code = err && err.code
      if (code !== 'ER_DUP_KEYNAME' && code !== 'ER_CHECK_CONSTRAINT_VIOLATED') {
        console.warn('Schema alter (carstev) non-fatal:', code || err.message)
      }
    }
    console.log('Schema ensured: carstev (contact messages) table exists')
    // Add optional columns and indexes for phone and read status
    const contactAlterStatements = [
      `ALTER TABLE \`${DB_NAME}\`.carstev ADD COLUMN phone VARCHAR(20) NULL`,
      `ALTER TABLE \`${DB_NAME}\`.carstev ADD COLUMN read_status TINYINT(1) NOT NULL DEFAULT 0`,
      `ALTER TABLE \`${DB_NAME}\`.carstev ADD INDEX idx_carstev_status (read_status)`,
    ]
    for (const sql of contactAlterStatements) {
      try {
        await pool.execute(sql)
      } catch (err) {
        const code = err && err.code
        if (code !== 'ER_DUP_FIELDNAME' && code !== 'ER_DUP_KEYNAME') {
          console.warn('Schema alter (carstev) non-fatal:', code || err.message)
        }
      }
    }

    // Analytics events table: tracks anonymous and authenticated calculator usage
    const createAnalyticsSQL = `
      CREATE TABLE IF NOT EXISTS \`${DB_NAME}\`.analytics_events (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id INT UNSIGNED NULL,
        ip_address VARCHAR(64) NULL,
        user_agent VARCHAR(255) NULL,
        tool VARCHAR(64) NOT NULL,
        params TEXT NULL,
        result TEXT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        INDEX idx_analytics_created (created_at),
        INDEX idx_analytics_tool_created (tool, created_at),
        INDEX idx_analytics_ip_created (ip_address, created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `
    await pool.execute(createAnalyticsSQL)
    try {
      await pool.execute(`ALTER TABLE \`${DB_NAME}\`.analytics_events ADD CONSTRAINT fk_analytics_user FOREIGN KEY (user_id) REFERENCES \`${DB_NAME}\`.users(id) ON DELETE SET NULL`)
    } catch (err) {
      const code = err && err.code
      if (code !== 'ER_DUP_KEYNAME' && code !== 'ER_CANNOT_ADD_FOREIGN') {
        console.warn('FK add (analytics) failed (non-fatal):', code || err.message)
      }
    }

    // Ensure user_images table exists for base64 avatars
    const createUserImagesSQL = `
      CREATE TABLE IF NOT EXISTS \`${DB_NAME}\`.user_images (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id INT UNSIGNED NOT NULL,
        image_data LONGTEXT NOT NULL,
        image_type VARCHAR(50) NOT NULL DEFAULT 'profile',
        mime_type VARCHAR(100) NOT NULL,
        file_size INT UNSIGNED NOT NULL,
        width INT UNSIGNED NULL,
        height INT UNSIGNED NULL,
        is_active TINYINT(1) NOT NULL DEFAULT 1,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_user_images_user_id (user_id),
        KEY idx_user_images_user_type (user_id, image_type)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `
    await pool.execute(createUserImagesSQL)
    try {
      await pool.execute(`ALTER TABLE \`${DB_NAME}\`.user_images ADD CONSTRAINT fk_user_images_user FOREIGN KEY (user_id) REFERENCES \`${DB_NAME}\`.users(id) ON DELETE CASCADE`)
    } catch (err) {
      const code = err && err.code
      if (code !== 'ER_DUP_KEYNAME' && code !== 'ER_CANNOT_ADD_FOREIGN') {
        console.warn('FK add (user_images) failed (non-fatal):', code || err.message)
      }
    }
  } catch (err) {
    console.error('Failed to ensure schema:', err.message)
    throw err
  }
}

// ---------- Profile APIs and Uploads ----------
// Simple cache for /api/me to reduce DB hits
const meCache = new Map() // userId -> { data, expires }

// Cache management functions
function clearUserCache(userId) {
  try {
    if (userId && typeof userId === 'number' && userId > 0) {
      meCache.delete(userId)
    }
  } catch (err) {
    console.error('Failed to clear user cache:', err)
  }
}

function clearAllCache() {
  try {
    meCache.clear()
  } catch (err) {
    console.error('Failed to clear all cache:', err)
  }
}

async function getUserById(userId) {
  try {
    // Validate userId
    if (!userId || typeof userId !== 'number' || userId <= 0) {
      console.error('Invalid userId provided to getUserById:', userId)
      return null
    }
    
    const cache = meCache.get(userId)
    if (cache && cache.expires > Date.now()) {
      return cache.data
    }
    
    const [rows] = await pool.execute(
      'SELECT id, name, email, first_name, last_name, phone, company, title, bio, location, website_url, twitter_url, linkedin_url, github_url, avatar_url, updated_at FROM users WHERE id = ? LIMIT 1',
      [userId]
    )
    
    const data = rows && rows[0] ? rows[0] : null
    
    // Only cache if we have valid data
    if (data) {
      meCache.set(userId, { data, expires: Date.now() + 60 * 1000 }) // cache 60s
    } else {
      // Cache null result for shorter time to prevent repeated queries for non-existent users
      meCache.set(userId, { data: null, expires: Date.now() + 10 * 1000 }) // cache 10s
    }
    
    return data
  } catch (err) {
    console.error('getUserById error:', err)
    return null
  }
}

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const user = await getUserById(req.auth.userId)
    if (!user) return res.status(404).json({ error: 'User not found' })
    res.set('Cache-Control', 'private, max-age=30')
    const etag = crypto.createHash('sha1').update(JSON.stringify(user)).digest('hex')
    res.set('ETag', etag)
    return res.json({ user })
  } catch (err) {
    console.error('GET /api/me error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

app.patch('/api/me', requireAuth, async (req, res) => {
  try {
    const { name, first_name, last_name, phone, company, title, bio, location, website_url, twitter_url, linkedin_url, github_url, avatar_url } = req.body || {}
    
    // Validate and sanitize each field individually
    const updates = {}
    
    if (typeof name === 'string') {
      updates.name = sanitizeText(name, { maxLen: 100 })
    }
    
    if (typeof first_name === 'string') {
      const v = sanitizeText(first_name, { maxLen: 50 })
      if (!v) return res.status(400).json({ error: 'First name is required' })
      updates.first_name = v
    }
    
    if (typeof last_name === 'string') {
      const v = sanitizeText(last_name, { maxLen: 50 })
      if (!v) return res.status(400).json({ error: 'Last name is required' })
      updates.last_name = v
    }
    
    if (typeof phone === 'string') {
      const p = phone.trim()
      if (p && !validatePhoneE164(p)) {
        return res.status(400).json({ error: 'Invalid phone format (E.164)' })
      }
      updates.phone = p || null
    }
    
    if (typeof company === 'string') {
      updates.company = sanitizeText(company, { maxLen: 100 })
    }
    
    if (typeof title === 'string') {
      updates.title = sanitizeText(title, { maxLen: 100 })
    }
    
    if (typeof bio === 'string') {
      updates.bio = sanitizeHtmlBasic(bio, { maxLen: 65535 })
    }
    
    if (typeof location === 'string') {
      updates.location = sanitizeText(location, { maxLen: 255 })
    }
    
    if (typeof website_url === 'string') {
      updates.website_url = sanitizeText(website_url, { maxLen: 255 })
    }
    
    if (typeof twitter_url === 'string') {
      updates.twitter_url = sanitizeText(twitter_url, { maxLen: 255 })
    }
    
    if (typeof linkedin_url === 'string') {
      updates.linkedin_url = sanitizeText(linkedin_url, { maxLen: 255 })
    }
    
    if (typeof github_url === 'string') {
      updates.github_url = sanitizeText(github_url, { maxLen: 255 })
    }
    
    if (typeof avatar_url === 'string') {
      updates.avatar_url = sanitizeText(avatar_url, { maxLen: 1024 })
    }
    
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields provided' })
    }
    
    // Build safe, parameterized query with explicit field names
    const allowedFields = ['name', 'first_name', 'last_name', 'phone', 'company', 'title', 'bio', 'location', 'website_url', 'twitter_url', 'linkedin_url', 'github_url', 'avatar_url']
    const validUpdates = {}
    
    for (const [key, value] of Object.entries(updates)) {
      if (allowedFields.includes(key)) {
        validUpdates[key] = value
      }
    }
    
    if (Object.keys(validUpdates).length === 0) {
      return res.status(400).json({ error: 'No valid fields provided' })
    }
    
    // Build safe query with explicit field mapping
    const setClause = Object.keys(validUpdates).map(field => `${field} = ?`).join(', ')
    const values = Object.values(validUpdates)
    values.push(req.auth.userId) // for WHERE clause
    
    await pool.execute(`UPDATE \`${DB_NAME}\`.users SET ${setClause} WHERE id = ?`, values)
    clearUserCache(req.auth.userId)
    return res.json({ message: 'Profile updated' })
    
  } catch (err) {
    console.error('PATCH /api/me error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Change password for current user
app.post('/api/me/password', requireAuth, async (req, res) => {
  try {
    const currentPassword = String(req.body?.current_password || '')
    const newPassword = String(req.body?.new_password || '')
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password are required' })
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' })
    }

    // Fetch existing password hash
    const [rows] = await pool.execute('SELECT password_hash FROM users WHERE id = ? LIMIT 1', [req.auth.userId])
    const row = rows && rows[0]
    if (!row) return res.status(404).json({ error: 'User not found' })

    const ok = await bcrypt.compare(currentPassword, row.password_hash)
    if (!ok) {
      return res.status(400).json({ error: 'Current password is incorrect' })
    }

    const saltRounds = 10
    const newHash = await bcrypt.hash(newPassword, saltRounds)
    await pool.execute('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, req.auth.userId])

    // Optional: invalidate cache for /api/me (profile fetch)
    meCache.delete(req.auth.userId)
    return res.json({ message: 'Password updated' })
  } catch (err) {
    console.error('POST /api/me/password error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// File upload setup
const fs = require('fs')
const { v4: uuidv4 } = require('uuid')
const multer = require('multer')
const { fileTypeFromFile } = require('file-type')
// Optional antivirus scanning with clamscan if available
let ClamFactory = null
try { ClamFactory = require('clamscan') } catch { ClamFactory = null }
// Optional S3 storage
let S3Client = null, UploadS3 = null
if (USE_S3) {
  try {
    const { S3Client: C, PutObjectCommand } = require('@aws-sdk/client-s3')
    const { Upload } = require('@aws-sdk/lib-storage')
    S3Client = new C({ region: S3_REGION, credentials: { accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY } })
    UploadS3 = Upload
    console.log('S3 storage enabled')
  } catch (err) {
    console.error('Failed to init S3 SDK:', err.message)
  }
}

const UPLOAD_ROOT = path.join(__dirname, 'uploads')
try { fs.mkdirSync(UPLOAD_ROOT, { recursive: true }) } catch {}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userId = req.auth?.userId || 'anonymous'
    const dir = path.join(UPLOAD_ROOT, 'profile', String(userId))
    try { fs.mkdirSync(dir, { recursive: true }) } catch {}
    cb(null, dir)
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase()
    cb(null, uuidv4() + ext)
  },
})

const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } })

async function verifyFileType(filePath) {
  try {
    const ft = await fileTypeFromFile(filePath)
    console.log(`File type detection result for ${filePath}:`, ft)
    return ft
  } catch (err) {
    console.error(`File type detection failed for ${filePath}:`, err)
    return null
  }
}

async function scanFileForVirus(filePath) {
  if (!ClamFactory) return { isInfected: false }
  try {
    const ClamScan = await new ClamFactory().init()
    const result = await ClamScan.scanFile(filePath)
    return { isInfected: !!result?.isInfected }
  } catch (err) {
    console.warn('Virus scan failed or not configured:', err?.message || err)
    return { isInfected: false }
  }
}

// Avatar upload: only JPG/PNG, max 5MB, CSRF + auth required

// Diagnostics: list columns present in users table (schema troubleshooting)
app.get('/db/users-columns', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT COLUMN_NAME, IS_NULLABLE, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = "users"',
      [DB_NAME]
    )
    return res.json({ columns: rows })
  } catch (err) {
    return res.status(500).json({ error: err.message, code: err.code || null })
  }
})

// ---------- Profile (by user id) ----------
// GET /api/users/:id/profile — allowed for self or admin
app.get('/api/users/:id/profile', requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id)
    if (!id) return res.status(400).json({ error: 'Invalid user id' })
    const isAdmin = !!req.auth?.isAdmin
    if (!isAdmin && req.auth.userId !== id) {
      return res.status(403).json({ error: 'Forbidden' })
    }
    const user = await getUserById(id)
    if (!user) return res.status(404).json({ error: 'User not found' })
    res.set('Cache-Control', 'private, max-age=30')
    return res.json({ user })
  } catch (err) {
    console.error('GET /api/users/:id/profile error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// PUT /api/users/:id/profile — allowed for self or admin
app.put('/api/users/:id/profile', requireCsrf, requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id)
    if (!id) return res.status(400).json({ error: 'Invalid user id' })
    const isAdmin = !!req.auth?.isAdmin
    if (!isAdmin && req.auth.userId !== id) {
      return res.status(403).json({ error: 'Forbidden' })
    }
    const { name, first_name, last_name, phone, company, title, bio, location, website_url, twitter_url, linkedin_url, github_url } = req.body || {}
    const fields = []
    const params = []
    function pushSanitized(field, value, opts) {
      if (typeof value === 'string') {
        fields.push(`${field} = ?`)
        params.push(sanitizeText(value, opts))
      }
    }
    if (typeof name === 'string') {
      fields.push('name = ?')
      params.push(sanitizeText(name, { maxLen: 100 }))
    }
    if (typeof first_name === 'string') {
      const v = sanitizeText(first_name, { maxLen: 50 })
      if (!v) return res.status(400).json({ error: 'First name is required' })
      fields.push('first_name = ?')
      params.push(v)
    }
    if (typeof last_name === 'string') {
      const v = sanitizeText(last_name, { maxLen: 50 })
      if (!v) return res.status(400).json({ error: 'Last name is required' })
      fields.push('last_name = ?')
      params.push(v)
    }
    if (typeof phone === 'string') {
      const p = phone.trim()
      if (p && !validatePhoneE164(p)) {
        return res.status(400).json({ error: 'Invalid phone format (E.164)' })
      }
      fields.push('phone = ?')
      params.push(p || null)
    }
    pushSanitized('company', company, { maxLen: 100 })
    pushSanitized('title', title, { maxLen: 100 })
    if (typeof bio === 'string') {
      fields.push('bio = ?')
      params.push(sanitizeHtmlBasic(bio, { maxLen: 65535 }))
    }
    pushSanitized('location', location, { maxLen: 255 })
    pushSanitized('website_url', website_url, { maxLen: 255 })
    pushSanitized('twitter_url', twitter_url, { maxLen: 255 })
    pushSanitized('linkedin_url', linkedin_url, { maxLen: 255 })
    pushSanitized('github_url', github_url, { maxLen: 255 })
    if (fields.length === 0) return res.status(400).json({ error: 'No valid fields provided' })
    params.push(id)
    await pool.execute(`UPDATE \`${DB_NAME}\`.users SET ${fields.join(', ')} WHERE id = ?`, params)
    meCache.delete(id)
    return res.json({ message: 'Profile updated' })
  } catch (err) {
    console.error('PUT /api/users/:id/profile error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Avatar upload feature removed: no memory upload route or handlers

// DEPRECATED: Old file upload system - redirects to new base64 system
app.post('/api/me/upload', requireAuth, upload.single('file'), async (req, res) => {
  return res.status(410).json({ 
    error: 'This endpoint is deprecated. Please use POST /api/me/image with base64 data instead.',
    migration_guide: 'Convert your image to base64 and send it to /api/me/image endpoint'
  })
})

// DEPRECATED: Old avatar upload system - redirects to new base64 system
app.post('/api/me/avatar', requireAuth, upload.single('file'), async (req, res) => {
  return res.status(410).json({ 
    error: 'This endpoint is deprecated. Please use POST /api/me/image with base64 data instead.',
    migration_guide: 'Convert your avatar image to base64 and send it to /api/me/image endpoint'
  })
})

// ---------- Base64 Image Storage (New System) ----------
// Store user image as base64
app.post('/api/me/image', requireAuth, async (req, res) => {
  try {
    console.log('Received image upload request from user:', req.auth.userId)
    const { image_data, mime_type, image_type = 'profile', width, height } = req.body || {}
    
    // Input validation
    if (!image_data || !mime_type) {
      console.log('Missing image_data or mime_type')
      return res.status(400).json({ error: 'Image data and MIME type are required' })
    }
    
    if (typeof image_data !== 'string' || image_data.length === 0) {
      console.log('Invalid image_data type or empty')
      return res.status(400).json({ error: 'Image data must be a non-empty string' })
    }
    
    if (typeof mime_type !== 'string' || mime_type.length === 0) {
      console.log('Invalid mime_type type or empty')
      return res.status(400).json({ error: 'MIME type must be a non-empty string' })
    }
    
    // Validate image_type if provided
    if (image_type && typeof image_type !== 'string') {
      console.log('Invalid image_type type')
      return res.status(400).json({ error: 'Image type must be a string' })
    }
    
    // Validate dimensions if provided
    if (width !== undefined && (typeof width !== 'number' || width < 0)) {
      console.log('Invalid width:', width)
      return res.status(400).json({ error: 'Width must be a positive number' })
    }
    if (height !== undefined && (typeof height !== 'number' || height < 0)) {
      return res.status(400).json({ error: 'Height must be a positive number' })
    }

    // Validate MIME type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp']
    if (!allowedTypes.includes(mime_type)) {
      console.log('Invalid mime_type:', mime_type)
      return res.status(400).json({ error: 'Invalid image type. Allowed: JPG, PNG, WebP' })
    }

    // Validate base64 data (basic check)
    if (!/^data:image\/[a-zA-Z+]+;base64,/.test(image_data)) {
      console.log('Invalid base64 format')
      return res.status(400).json({ error: 'Invalid image data format. Must start with data:image/...;base64,' })
    }

    // Calculate file size (approximate)
    const base64Data = image_data.split(',')[1]
    if (!base64Data || base64Data.length === 0) {
      console.log('Empty base64 content')
      return res.status(400).json({ error: 'Invalid base64 data' })
    }
    const fileSize = Math.ceil(base64Data.length * 0.75)

    // Check file size (5MB limit)
    if (fileSize > 5 * 1024 * 1024) {
      console.log('File too large:', fileSize, 'bytes')
      return res.status(400).json({ error: `Image size must be less than 5MB. Current size: ${(fileSize / 1024 / 1024).toFixed(2)}MB` })
    }

    // Deactivate any existing profile images for this user
    try {
      await pool.execute(
        `UPDATE \`${DB_NAME}\`.user_images SET is_active = 0 WHERE user_id = ? AND image_type = ?`,
        [req.auth.userId, image_type]
      )
    } catch (err) {
      console.error('Failed to deactivate existing images:', err)
      // Continue with upload even if deactivation fails
    }

    // Insert new image
    let result
    try {
      const [insertResult] = await pool.execute(
        `INSERT INTO \`${DB_NAME}\`.user_images (user_id, image_data, mime_type, image_type, file_size, width, height) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [req.auth.userId, image_data, mime_type, image_type, fileSize, width || null, height || null]
      )
      result = insertResult
    } catch (err) {
      console.error('Failed to insert image into database:', err)
      return res.status(500).json({ error: 'Failed to save image to database' })
    }

    // Update user's avatar_url field for backward compatibility
    const imageUrl = `/api/me/image/${result.insertId}`
    try {
      await pool.execute(
        `UPDATE \`${DB_NAME}\`.users SET avatar_url = ? WHERE id = ?`,
        [imageUrl, req.auth.userId]
      )
    } catch (err) {
      console.error('Failed to update user avatar_url:', err)
      // Continue even if avatar_url update fails - the image is still saved
    }

    // Clear cache
    clearUserCache(req.auth.userId)

    console.log('Image saved successfully, returning URL:', imageUrl)
    return res.json({ 
      id: result.insertId, 
      url: imageUrl,
      message: 'Image saved successfully'
    })
  } catch (err) {
    console.error('POST /api/me/image error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Get user image by ID
app.get('/api/me/image/:id', requireAuth, async (req, res) => {
  try {
    const imageId = Number(req.params.id)
    console.log(`Serving image ID: ${imageId} for user: ${req.auth.userId}`)
    
    if (!imageId) return res.status(400).json({ error: 'Invalid image ID' })

    const [rows] = await pool.execute(
      `SELECT image_data, mime_type FROM \`${DB_NAME}\`.user_images WHERE id = ? AND user_id = ? LIMIT 1`,
      [imageId, req.auth.userId]
    )

    console.log(`Image query result:`, rows)
    
    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Image not found' })
    }

    const image = rows[0]
    console.log(`Found image with mime_type: ${image.mime_type}`)
    
    // Set appropriate headers and send image data
    res.setHeader('Content-Type', image.mime_type)
    res.setHeader('Cache-Control', 'public, max-age=31536000') // Cache for 1 year
    
    // Extract base64 data and convert to buffer
    const base64Data = image.image_data.split(',')[1]
    const imageBuffer = Buffer.from(base64Data, 'base64')
    
    console.log(`Sending image buffer of size: ${imageBuffer.length} bytes`)
    return res.send(imageBuffer)
  } catch (err) {
    console.error('GET /api/me/image/:id error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Get user's active profile image
app.get('/api/me/image', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, image_data, mime_type, created_at FROM \`${DB_NAME}\`.user_images 
       WHERE user_id = ? AND image_type = 'profile' AND is_active = 1 
       ORDER BY created_at DESC 
       LIMIT 1`,
      [req.auth.userId]
    )

    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'No profile image found' })
    }

    const image = rows[0]
    // Return full URL for the image
    const baseUrl = `${req.protocol}://${req.get('host')}`
    return res.json({
      id: image.id,
      url: `${baseUrl}/api/me/image/${image.id}`,
      mime_type: image.mime_type,
      created_at: image.created_at
    })
  } catch (err) {
    console.error('GET /api/me/image error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Delete user image
app.delete('/api/me/image/:id', requireAuth, async (req, res) => {
  try {
    const imageId = Number(req.params.id)
    if (!imageId || imageId <= 0) {
      return res.status(400).json({ error: 'Invalid image ID' })
    }

    // Check if image belongs to user
    let rows
    try {
      const [result] = await pool.execute(
        `SELECT id FROM \`${DB_NAME}\`.user_images WHERE id = ? AND user_id = ? LIMIT 1`,
        [imageId, req.auth.userId]
      )
      rows = result
    } catch (err) {
      console.error('Database query failed:', err)
      return res.status(500).json({ error: 'Database query failed' })
    }

    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Image not found or does not belong to you' })
    }

    // Delete the image
    try {
      await pool.execute(
        `DELETE FROM \`${DB_NAME}\`.user_images WHERE id = ?`,
        [imageId]
      )
    } catch (err) {
      console.error('Failed to delete image:', err)
      return res.status(500).json({ error: 'Failed to delete image' })
    }

    // If this was the active profile image, clear avatar_url
    try {
      await pool.execute(
        `UPDATE \`${DB_NAME}\`.users SET avatar_url = NULL WHERE id = ? AND avatar_url = ?`,
        [req.auth.userId, `/api/me/image/${imageId}`]
      )
    } catch (err) {
      console.error('Failed to clear avatar_url:', err)
      // Continue even if this fails
    }

    // Clear cache
    clearUserCache(req.auth.userId)

    return res.json({ message: 'Image deleted successfully' })
  } catch (err) {
    console.error('DELETE /api/me/image/:id error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ---------- Calculation History ----------
// Save calculation (transactional)
async function saveCalculationHistory(poolRef, { userId, params, result }) {
  const conn = await poolRef.getConnection()
  try {
    await conn.beginTransaction()
    const p = typeof params === 'string' ? params : JSON.stringify(params || {})
    const r = typeof result === 'string' ? result : JSON.stringify(result || {})
    const [res] = await conn.execute(`INSERT INTO \`${DB_NAME}\`.calculation_history (user_id, params, result) VALUES (?, ?, ?)`, [userId, p, r])
    await conn.commit()
    return res && res.insertId ? Number(res.insertId) : null
  } catch (err) {
    try { await conn.rollback() } catch {}
    throw err
  } finally {
    try { conn.release() } catch {}
  }
}

// Fetch calculation history with pagination and optional search
async function getCalculationHistory(poolRef, { userId, limit = 20, page = 1, q = '', from = '', to = '' }) {
  const lim = Math.min(Math.max(parseInt(String(limit || ''), 10) || 20, 1), 100)
  const pg = Math.max(parseInt(String(page || ''), 10) || 1, 1)
  const offset = (pg - 1) * lim
  const where = ['user_id = ?']
  const params = [userId]
  if (q && String(q).trim()) {
    where.push('(params LIKE ? OR result LIKE ? )')
    const like = `%${String(q).trim()}%`
    params.push(like, like)
  }
  if (from && String(from).trim()) {
    where.push('performed_at >= ?')
    params.push(new Date(from))
  }
  if (to && String(to).trim()) {
    where.push('performed_at <= ?')
    params.push(new Date(to))
  }
  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : ''
  const [rows] = await poolRef.execute(
    `SELECT id, user_id, params, result, performed_at FROM \`${DB_NAME}\`.calculation_history ${whereClause} ORDER BY performed_at DESC LIMIT ? OFFSET ?`,
    [...params, lim, offset]
  )
  const [countRows] = await poolRef.execute(
    `SELECT COUNT(*) AS total FROM \`${DB_NAME}\`.calculation_history ${whereClause}`,
    params
  )
  return { items: rows || [], page: pg, limit: lim, total: countRows?.[0]?.total || 0 }
}

// API: Save new calculation
app.post('/api/me/calculations', requireAuth, async (req, res) => {
  try {
    const { params, result } = req.body || {}
    if (typeof params !== 'object' || typeof result !== 'object') {
      return res.status(400).json({ error: 'params and result must be objects' })
    }
    const insertId = await saveCalculationHistory(pool, { userId: req.auth.userId, params, result })
    return res.json({ id: insertId })
  } catch (err) {
    console.error('POST /api/me/calculations error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// API: Retrieve calculation history for current user
app.get('/api/me/calculations', requireAuth, async (req, res) => {
  try {
    const { limit, page, q, from, to } = req.query || {}
    const data = await getCalculationHistory(pool, { userId: req.auth.userId, limit, page, q, from, to })
    res.set('Cache-Control', 'private, max-age=10')
    return res.json(data)
  } catch (err) {
    console.error('GET /api/me/calculations error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ---------- Admin: Users ----------
// Total user count
app.get('/api/admin/users/count', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT COUNT(*) AS count FROM \`${DB_NAME}\`.users`)
    return res.json({ count: rows[0]?.count || 0 })
  } catch (err) {
    console.error('GET /api/admin/users/count error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Paginated user list
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(String(req.query.limit || ''), 10) || 20, 1), 100)
    const page = Math.max(parseInt(String(req.query.page || ''), 10) || 1, 1)
    const offset = (page - 1) * limit
    const [users] = await pool.query(
      `SELECT id, name, email, created_at FROM \`${DB_NAME}\`.users ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [limit, offset]
    )
    const [countRows] = await pool.query(`SELECT COUNT(*) AS count FROM \`${DB_NAME}\`.users`)
    return res.json({ users, total: countRows[0]?.count || 0, page, limit })
  } catch (err) {
    console.error('GET /api/admin/users error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ---------- Admin: Calculations ----------
// Recent calculations across all users, with user details
app.get('/api/admin/calculations/recent', requireAdmin, async (req, res) => {
  try {
    const { limit, page, q, from, to } = req.query || {}
    const lim = Math.min(Math.max(parseInt(String(limit || ''), 10) || 10, 1), 100)
    const pg = Math.max(parseInt(String(page || ''), 10) || 1, 1)
    const offset = (pg - 1) * lim
    const where = []
    const params = []
    if (q && String(q).trim()) {
      where.push('(ch.params LIKE ? OR ch.result LIKE ? OR u.name LIKE ? OR u.email LIKE ?)')
      const like = `%${String(q).trim()}%`
      params.push(like, like, like, like)
    }
    if (from && String(from).trim()) {
      where.push('ch.performed_at >= ?')
      params.push(new Date(from))
    }
    if (to && String(to).trim()) {
      where.push('ch.performed_at <= ?')
      params.push(new Date(to))
    }
    const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : ''
    const [rows] = await pool.execute(
      `SELECT ch.id, ch.user_id, ch.params, ch.result, ch.performed_at, u.name AS user_name, u.email AS user_email
       FROM \`${DB_NAME}\`.calculation_history ch
       JOIN \`${DB_NAME}\`.users u ON u.id = ch.user_id
       ${whereClause}
       ORDER BY ch.performed_at DESC
       LIMIT ? OFFSET ?`,
      [...params, lim, offset]
    )
    const [countRows] = await pool.execute(
      `SELECT COUNT(*) AS total
       FROM \`${DB_NAME}\`.calculation_history ch
       JOIN \`${DB_NAME}\`.users u ON u.id = ch.user_id
       ${whereClause}`,
      params
    )
    res.set('Cache-Control', 'private, max-age=10')
    return res.json({ items: rows || [], page: pg, limit: lim, total: countRows?.[0]?.total || 0 })
  } catch (err) {
    console.error('GET /api/admin/calculations/recent error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Calculation types breakdown (counts by tool) over a time range
app.get('/api/admin/analytics/calculation-types', requireAdmin, async (req, res) => {
  try {
    const { days, from, to, q } = req.query || {}
    const where = []
    const params = []
    if (days && String(days).trim()) {
      const d = Math.max(parseInt(String(days), 10) || 0, 0)
      const startDate = new Date(Date.now() - d * 24 * 60 * 60 * 1000)
      where.push('ch.performed_at >= ?')
      params.push(startDate)
    }
    if (from && String(from).trim()) {
      where.push('ch.performed_at >= ?')
      params.push(new Date(from))
    }
    if (to && String(to).trim()) {
      where.push('ch.performed_at <= ?')
      params.push(new Date(to))
    }
    if (q && String(q).trim()) {
      where.push('(ch.params LIKE ? OR ch.result LIKE ? )')
      const like = `%${String(q).trim()}%`
      params.push(like, like)
    }
    const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : ''
    const [rows] = await pool.execute(
      `SELECT COALESCE(NULLIF(JSON_UNQUOTE(JSON_EXTRACT(ch.params, '$.tool')), ''), 'other') AS tool, COUNT(*) AS count
       FROM \`${DB_NAME}\`.calculation_history ch
       ${whereClause}
       GROUP BY tool
       ORDER BY count DESC`
      , params
    )
    const series = Array.isArray(rows) ? rows.map(r => ({ tool: r.tool || 'other', count: Number(r.count) || 0 })) : []
    res.set('Cache-Control', 'private, max-age=10')
    return res.json({ series })
  } catch (err) {
    console.error('GET /api/admin/analytics/calculation-types error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Admin analytics: user growth over a time window
app.get('/api/admin/analytics/user-growth', requireAdmin, async (req, res) => {
  try {
    const daysParam = parseInt(String(req.query.days || ''), 10)
    const days = Math.min(Math.max(daysParam || 30, 1), 365)
    const [rows] = await pool.query(
      `SELECT DATE(created_at) AS d, COUNT(*) AS count
       FROM \`${DB_NAME}\`.users
       WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
       GROUP BY DATE(created_at)
       ORDER BY d ASC`,
      [days]
    )
    // Fill missing dates with zeros
    const today = new Date()
    const start = new Date()
    start.setDate(today.getDate() - (days - 1))
    function toISODate(dt) {
      const y = dt.getFullYear()
      const m = String(dt.getMonth() + 1).padStart(2, '0')
      const d = String(dt.getDate()).padStart(2, '0')
      return `${y}-${m}-${d}`
    }
    const map = new Map()
    for (const r of rows) {
      const key = typeof r.d === 'string' ? r.d : toISODate(new Date(r.d))
      map.set(key, Number(r.count) || 0)
    }
    const series = []
    const cursor = new Date(start)
    while (cursor <= today) {
      const key = toISODate(cursor)
      series.push({ date: key, count: map.get(key) || 0 })
      cursor.setDate(cursor.getDate() + 1)
    }
    return res.json({ rangeDays: days, series })
  } catch (err) {
    console.error('GET /api/admin/analytics/user-growth error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Admin analytics: calculations performed today (UTC-agnostic via MySQL CURDATE())
app.get('/api/admin/analytics/calculations-today', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT COUNT(*) AS count
       FROM \`${DB_NAME}\`.calculation_history
       WHERE performed_at >= CURDATE() AND performed_at < DATE_ADD(CURDATE(), INTERVAL 1 DAY)`
    )
    return res.json({ count: rows[0]?.count || 0 })
  } catch (err) {
    console.error('GET /api/admin/analytics/calculations-today error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Admin analytics: calculation volume per day over a time window
app.get('/api/admin/analytics/calculation-volume', requireAdmin, async (req, res) => {
  try {
    const daysParam = parseInt(String(req.query.days || ''), 10)
    const days = Math.min(Math.max(daysParam || 30, 1), 365)
    const [rows] = await pool.query(
      `SELECT DATE(performed_at) AS d, COUNT(*) AS count
       FROM \`${DB_NAME}\`.calculation_history
       WHERE performed_at >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
       GROUP BY DATE(performed_at)
       ORDER BY d ASC`,
      [days]
    )
    const today = new Date()
    const start = new Date()
    start.setDate(today.getDate() - (days - 1))
    function toISODate(dt) {
      const y = dt.getFullYear()
      const m = String(dt.getMonth() + 1).padStart(2, '0')
      const d = String(dt.getDate()).padStart(2, '0')
      return `${y}-${m}-${d}`
    }
    const map = new Map()
    for (const r of rows) {
      const key = typeof r.d === 'string' ? r.d : toISODate(new Date(r.d))
      map.set(key, Number(r.count) || 0)
    }
    const series = []
    const cursor = new Date(start)
    while (cursor <= today) {
      const key = toISODate(cursor)
      series.push({ date: key, count: map.get(key) || 0 })
      cursor.setDate(cursor.getDate() + 1)
    }
    res.set('Cache-Control', 'private, max-age=10')
    return res.json({ rangeDays: days, series })
  } catch (err) {
    console.error('GET /api/admin/analytics/calculation-volume error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Admin analytics: calculation types per day (multi-series line data)
app.get('/api/admin/analytics/calculation-types-series', requireAdmin, async (req, res) => {
  try {
    const daysParam = parseInt(String(req.query.days || ''), 10)
    const days = Math.min(Math.max(daysParam || 30, 1), 365)
    // Query per-day counts grouped by tool type
    const [rows] = await pool.query(
      `SELECT DATE(performed_at) AS d,
              COALESCE(NULLIF(JSON_UNQUOTE(JSON_EXTRACT(params, '$.tool')), ''), 'other') AS tool,
              COUNT(*) AS count
       FROM \`${DB_NAME}\`.calculation_history
       WHERE performed_at >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
       GROUP BY DATE(performed_at), tool
       ORDER BY d ASC`,
      [days]
    )
    const today = new Date()
    const start = new Date()
    start.setDate(today.getDate() - (days - 1))
    function toISODate(dt) {
      const y = dt.getFullYear()
      const m = String(dt.getMonth() + 1).padStart(2, '0')
      const d = String(dt.getDate()).padStart(2, '0')
      return `${y}-${m}-${d}`
    }
    // Build tool list and per-tool date maps
    const tools = new Set()
    const mapByTool = new Map() // tool -> Map(date -> count)
    for (const r of rows || []) {
      const key = typeof r.d === 'string' ? r.d : toISODate(new Date(r.d))
      const tool = r.tool || 'other'
      tools.add(tool)
      if (!mapByTool.has(tool)) mapByTool.set(tool, new Map())
      mapByTool.get(tool).set(key, Number(r.count) || 0)
    }
    // Ensure every tool has a full date series (fill missing dates with zero)
    const series = []
    const cursorBase = new Date(start)
    const allDates = []
    const cursor = new Date(cursorBase)
    while (cursor <= today) {
      allDates.push(toISODate(cursor))
      cursor.setDate(cursor.getDate() + 1)
    }
    for (const tool of tools) {
      const dateMap = mapByTool.get(tool) || new Map()
      const points = []
      for (const d of allDates) {
        points.push({ date: d, count: dateMap.get(d) || 0 })
      }
      series.push({ tool, points })
    }
    res.set('Cache-Control', 'private, max-age=10')
    return res.json({ rangeDays: days, series })
  } catch (err) {
    console.error('GET /api/admin/analytics/calculation-types-series error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON' })
  }
  console.error('Unhandled error:', err)
  return res.status(500).json({ error: 'Internal server error' })
})

app.use((req, res) => {
  return res.status(404).json({ error: 'Not found' })
})

// Start server only when executed directly
if (require.main === module) {
  function listenWithRetry(startPort, maxAttempts) {
    return new Promise((resolve, reject) => {
      let current = startPort
      let remaining = Math.max(Number(maxAttempts) || 1, 1)
      function attempt() {
        const server = app.listen(current, '0.0.0.0', async () => {
          resolve({ server, port: current })
        })
        server.on('error', (err) => {
          if (err && err.code === 'EADDRINUSE' && remaining > 0) {
            remaining -= 1
            current += 1
            attempt()
          } else {
            reject(err)
          }
        })
      }
      attempt()
    })
  }

  listenWithRetry(Number(PORT), 10)
    .then(async ({ port }) => {
      console.log(`SoilCalcify backend listening on http://localhost:${port}`)
      const check = await testDbConnection()
      if (check.ok) {
        console.log('Database: Connected')
      } else {
        console.error(`Database Error: ${check.error || 'unknown'}`)
      }
      try {
        await ensureSchema()
      } catch (schemaErr) {
        console.error('Schema ensure failed:', schemaErr.message)
      }
      const mode = process.env.NODE_ENV || 'production'
      console.log(buildBanner({ port, mode, dbConnected: !!check.ok }))
    })
    .catch((err) => {
      console.error('Server start failed:', err?.message || String(err))
      process.exit(1)
    })
}

// Graceful shutdown
process.on('SIGINT', async () => {
  try {
    await pool.end()
    console.log('DB pool closed')
  } catch (err) {
    console.error('Error closing DB pool:', err.message)
  }
  process.exit(0)
})

// Export for testing
module.exports = { app, pool, userExists, createUser, ensureSchema, saveCalculationHistory, getCalculationHistory }
