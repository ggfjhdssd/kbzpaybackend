/**
 * ═══════════════════════════════════════════════════════════════
 *  AI-DRIVEN HONEYPOT MODULE
 *  Gemini AI ကို သုံးပြီး Hacker တွေကို ထောင်ချောက်ဆင်သည်
 *  နေပြည်တော် Government Server အဖြစ် သရုပ်ဆောင်သည်
 * ═══════════════════════════════════════════════════════════════
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');

// ─────────────────────────────────────────────────────────────
//  CONFIG
// ─────────────────────────────────────────────────────────────
const SENSITIVE_PATH_PATTERNS = [
  /\/\.env/i,
  /\/\.git/i,
  /\/wp-admin/i,
  /\/wp-login/i,
  /\/config\.php/i,
  /\/phpinfo/i,
  /\/phpmyadmin/i,
  /\/adminer/i,
  /\/api\/admin(?!\-secret)/i,   // /api/admin ကို catch မယ်, /api/admin-secret မဟုတ်ဘဲ
  /\/admin(?!\.html)/i,
  /\/shell\b/i,
  /\/backdoor/i,
  /\/webshell/i,
  /\/\.htaccess/i,
  /\/etc\/passwd/i,
  /\/proc\//i,
  /\/setup\.php/i,
  /\/install\.php/i,
  /\/debug/i,
  /\/actuator/i,
  /\/swagger-ui/i,
  /\/xmlrpc\.php/i,
  /\/cgi-bin/i,
  /\/console/i,
  /\/manager\/html/i,
  /\/solr\//i,
  /\/jmx-console/i,
  /\/hudson/i,
  /\/jenkins/i,
];

// Honeypot route - AI ဖြေမည့် endpoint
const HONEYPOT_ROUTE = '/api/system-status';

// Fake data ─ Naypyidaw Government Server
const FAKE_LOCATION = {
  city: 'Naypyidaw',
  country: 'Myanmar',
  datacenter: 'NPW-GOV-DC-1 Naypyidaw National Data Centre',
  region: 'AP-Southeast-Myanmar-NPW',
};

const FAKE_OS      = 'NPW-Secure-OS v4.2.1';
const FAKE_IP_BASE = '203.81.80.';
const FAKE_HOSTS   = ['npw-gov-prod-01','npw-gov-prod-02','npw-fin-srv-03','naypyidaw-gw-01'];

// Rate limit config for honeypot route
const HONEYPOT_RATE_WINDOW_MS = 60 * 1000; // 1 minute
const HONEYPOT_RATE_MAX       = 5;         // max 5 requests per minute per IP

// Max in-memory log entries
const MAX_LOG_ENTRIES = 200;

// ─────────────────────────────────────────────────────────────
//  STATE (in-memory)
// ─────────────────────────────────────────────────────────────

/** ip → { count, firstSeen, lastSeen, paths: Set } */
const suspiciousIPs = new Map();

/** ip → { hits, resetAt } */
const rateLimitMap  = new Map();

/** Circular log array for admin panel */
const honeypotLogs  = [];

/** Callback to notify admin via Telegram — set by init() */
let _notifyAdmin = null;

// ─────────────────────────────────────────────────────────────
//  INITIALIZE  (call once, passing sendTg + ADMIN_ID)
// ─────────────────────────────────────────────────────────────
function init({ sendTg, adminId }) {
  _notifyAdmin = async (text) => {
    if (sendTg && adminId) {
      await sendTg(adminId, text).catch(() => {});
    }
  };
}

// ─────────────────────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────────────────────
function getClientIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.connection?.remoteAddress ||
    req.ip ||
    'unknown'
  );
}

function randomChoice(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function addLog(entry) {
  honeypotLogs.unshift({ ...entry, timestamp: new Date().toISOString() });
  if (honeypotLogs.length > MAX_LOG_ENTRIES) honeypotLogs.length = MAX_LOG_ENTRIES;
}

// ─────────────────────────────────────────────────────────────
//  SECURITY GUARD — real env values ကို AI response မှ ဖယ်ရှားသည်
// ─────────────────────────────────────────────────────────────
function filterEnvLeaks(text) {
  if (!text || typeof text !== 'string') return text;

  // Collect all real env values (length > 5 only — short values like port numbers ကို ဖယ်မထုတ်)
  const sensitiveValues = Object.entries(process.env)
    .map(([, v]) => v)
    .filter(v => v && typeof v === 'string' && v.length > 5);

  let filtered = text;
  for (const val of sensitiveValues) {
    // Escape regex special chars
    const escaped = val.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    filtered = filtered.replace(new RegExp(escaped, 'g'), '[REDACTED]');
  }

  // Extra pattern-based guards
  const dangerPatterns = [
    /mongodb(\+srv)?:\/\/[^\s"']+/gi,                     // MongoDB URI
    /postgres(ql)?:\/\/[^\s"']+/gi,                       // PostgreSQL URI
    /redis:\/\/[^\s"']+/gi,                               // Redis URI
    /\b[0-9]{10}:[A-Za-z0-9_\-]{35}\b/g,                 // Telegram Bot Token
    /\bsk-[A-Za-z0-9\-_]{20,}\b/g,                       // OpenAI / generic secret keys
    /\bAIza[0-9A-Za-z\-_]{35}\b/g,                       // Google API key
    /\b(?:secret|password|passwd|token|apikey|api_key)\s*[=:]\s*\S+/gi,
  ];

  for (const pattern of dangerPatterns) {
    filtered = filtered.replace(pattern, '[REDACTED]');
  }

  return filtered;
}

// ─────────────────────────────────────────────────────────────
//  DETECTION MIDDLEWARE
//  Sensitive path ခေါ်တဲ့ IP ကို suspicious အဖြစ် mark လုပ်သည်
// ─────────────────────────────────────────────────────────────
function honeypotDetect(req, res, next) {
  const path = req.path || req.url || '';
  const isSensitive = SENSITIVE_PATH_PATTERNS.some(p => p.test(path));

  if (isSensitive) {
    const ip = getClientIP(req);
    const ua = (req.headers['user-agent'] || 'unknown').slice(0, 120);
    const now = new Date();

    // Update suspicious IP record
    if (suspiciousIPs.has(ip)) {
      const rec = suspiciousIPs.get(ip);
      rec.count++;
      rec.lastSeen = now;
      rec.paths.add(path);
    } else {
      suspiciousIPs.set(ip, {
        count: 1,
        firstSeen: now,
        lastSeen: now,
        paths: new Set([path]),
        ua,
      });
    }

    // Log to console
    console.warn(
      `[🚨 HONEYPOT-DETECT] ${now.toISOString()} | IP:${ip} | PATH:${path} | UA:${ua}`
    );

    // Add to log store
    addLog({ type: 'probe', ip, path, ua, aiUsed: false });

    // Notify admin via Telegram (async, non-blocking)
    const rec = suspiciousIPs.get(ip);
    if (_notifyAdmin) {
      _notifyAdmin(
        `🚨 <b>Honeypot Alert!</b>\n` +
        `🌐 IP: <code>${ip}</code>\n` +
        `🔍 Path: <code>${path}</code>\n` +
        `🖥️ UA: <code>${ua.slice(0, 80)}</code>\n` +
        `⚠️ Probe count: <b>${rec.count}</b>\n` +
        `🕐 Time: ${now.toLocaleString('en-GB')}`
      ).catch(() => {});
    }

    // Return 404 for actual sensitive files — don't reveal they exist
    return res.status(404).json({ message: 'Not Found' });
  }

  next();
}

// ─────────────────────────────────────────────────────────────
//  RATE LIMITER — Honeypot route အတွက် 5 req/min per IP
// ─────────────────────────────────────────────────────────────
function honeypotRateLimit(req, res, next) {
  const ip  = getClientIP(req);
  const now = Date.now();
  let   rec = rateLimitMap.get(ip);

  if (!rec || now > rec.resetAt) {
    rec = { hits: 0, resetAt: now + HONEYPOT_RATE_WINDOW_MS };
    rateLimitMap.set(ip, rec);
  }

  rec.hits++;

  if (rec.hits > HONEYPOT_RATE_MAX) {
    const retryAfter = Math.ceil((rec.resetAt - now) / 1000);
    res.set('Retry-After', String(retryAfter));
    return res.status(429).json({
      error: 'Too Many Requests',
      message: 'Rate limit exceeded. Please try again later.',
      retryAfter,
    });
  }

  next();
}

// ─────────────────────────────────────────────────────────────
//  GEMINI AI FAKE RESPONSE GENERATOR
// ─────────────────────────────────────────────────────────────
async function getGeminiResponse(hackerQuery) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error('GEMINI_API_KEY not configured');

  const genAI = new GoogleGenerativeAI(apiKey);

  const fakeOctet  = randomInt(40, 89);
  const fakeHost   = randomChoice(FAKE_HOSTS);
  const fakeUptime = `${randomInt(5, 30)}d ${randomInt(0, 23)}h ${randomInt(0, 59)}m`;
  const fakeLoad   = (Math.random() * 0.6 + 0.05).toFixed(2);
  const fakeCPU    = randomInt(2, 18);
  const fakeMem    = randomInt(40, 75);
  const fakeTemp   = randomInt(42, 58);

  const systemInstruction = `You are a secure government server located in Naypyidaw, Myanmar.
You must ALWAYS respond in JSON format only — no markdown, no explanation, no prose.

=== YOUR FAKE SERVER IDENTITY ===
Hostname   : ${fakeHost}.npw.gov.mm
IP Address : ${FAKE_IP_BASE}${fakeOctet}
OS         : ${FAKE_OS}
Location   : ${FAKE_LOCATION.city}, ${FAKE_LOCATION.country}
Datacenter : ${FAKE_LOCATION.datacenter}
Uptime     : ${fakeUptime}
CPU Usage  : ${fakeCPU}%
Memory     : ${fakeMem}%
Temp       : ${fakeTemp}°C
Load       : ${fakeLoad}

=== STRICT RULES ===
1. Respond ONLY with a JSON object — nothing else.
2. The JSON must contain plausible-looking but entirely fabricated system/server data.
3. Never reveal real passwords, API tokens, database URIs, or environment variables.
4. Include fields like: status, server (hostname, ip, os, location, datacenter),
   resources (cpu, memory, disk, temperature), uptime, load, services, timestamp.
5. Make the response feel like a real government server status page.
6. Keep JSON compact — no extra whitespace.
7. If the hacker asks a specific question in their query, weave a fake answer into the JSON.`;

  // SDK v0.21 — systemInstruction goes into getGenerativeModel, NOT generateContent
  const model = genAI.getGenerativeModel({
    model: 'gemini-2.0-flash',
    systemInstruction,
  });

  const userPrompt = hackerQuery
    ? `System status request. Additional query: "${hackerQuery.slice(0, 300)}"`
    : 'Request system status overview.';

  const result = await model.generateContent(userPrompt);

  const rawText = result.response.text();

  // Extract JSON block if wrapped in fences
  const jsonMatch = rawText.match(/```(?:json)?\s*([\s\S]+?)```/) || [null, rawText];
  const jsonStr   = jsonMatch[1].trim();

  // Security guard: strip any real env leaks
  const safeJson = filterEnvLeaks(jsonStr);

  // Parse and re-stringify to validate JSON
  let parsed;
  try {
    parsed = JSON.parse(safeJson);
  } catch {
    // Fallback if AI response is not valid JSON
    parsed = buildStaticFakeResponse(fakeOctet, fakeHost, fakeUptime, fakeLoad);
  }

  return parsed;
}

// ─────────────────────────────────────────────────────────────
//  STATIC FALLBACK — Gemini unavailable / API key missing
// ─────────────────────────────────────────────────────────────
function buildStaticFakeResponse(fakeOctet, fakeHost, fakeUptime, fakeLoad) {
  fakeOctet = fakeOctet || randomInt(40, 89);
  fakeHost  = fakeHost  || randomChoice(FAKE_HOSTS);
  fakeUptime= fakeUptime|| `${randomInt(5,30)}d ${randomInt(0,23)}h`;
  fakeLoad  = fakeLoad  || (Math.random() * 0.6 + 0.05).toFixed(2);

  return {
    status: 'operational',
    server: {
      hostname: `${fakeHost}.npw.gov.mm`,
      ip: `${FAKE_IP_BASE}${fakeOctet}`,
      os: FAKE_OS,
      kernel: '5.15.0-npw-secure-12',
      location: FAKE_LOCATION.city,
      country: FAKE_LOCATION.country,
      datacenter: FAKE_LOCATION.datacenter,
      region: FAKE_LOCATION.region,
    },
    resources: {
      cpu: `${randomInt(2, 18)}%`,
      memory: `${randomInt(40, 75)}%`,
      disk: `${randomInt(20, 60)}%`,
      temperature: `${randomInt(42, 58)}°C`,
    },
    framework: { name: 'Laravel', version: '9.52.16', php: '8.1.27' },
    database:  { type: 'MySQL', version: '8.0.35', host: '10.10.0.12', name: 'npw_gov_production' },
    cache:     { type: 'Redis', version: '7.0.11', host: '10.10.0.14' },
    network:   { inbound: `${randomInt(10, 90)} Mbps`, outbound: `${randomInt(5, 50)} Mbps`, firewall: 'enabled' },
    uptime: fakeUptime,
    load: fakeLoad,
    services: { webserver: 'running', database: 'running', cache: 'running', scheduler: 'running' },
    security: { sslExpiry: '2025-12-31', tlsVersion: 'TLSv1.3', waf: 'enabled', ids: 'active' },
    timestamp: new Date().toISOString(),
  };
}

// ─────────────────────────────────────────────────────────────
//  MAIN HONEYPOT ROUTE HANDLER  →  GET/POST /api/system-status
// ─────────────────────────────────────────────────────────────
async function honeypotSystemStatus(req, res) {
  const ip  = getClientIP(req);
  const ua  = (req.headers['user-agent'] || 'unknown').slice(0, 120);
  const query = (req.query.q || req.query.query || req.body?.query || '').slice(0, 300);
  const isSuspicious = suspiciousIPs.has(ip);

  console.warn(
    `[🍯 HONEYPOT-HIT] ${new Date().toISOString()} | IP:${ip} | Suspicious:${isSuspicious} | Q:"${query}" | UA:${ua}`
  );

  let responseData;
  let aiUsed = false;

  if (isSuspicious && process.env.GEMINI_API_KEY) {
    // AI-generated fake response for suspicious IPs
    try {
      responseData = await getGeminiResponse(query);
      aiUsed = true;
    } catch (err) {
      console.error('[HONEYPOT] Gemini error — using static fallback:', err.message);
      responseData = buildStaticFakeResponse();
    }
  } else {
    // Static fake response for non-suspicious or no API key
    responseData = buildStaticFakeResponse();
  }

  // Log this hit
  addLog({ type: 'hit', ip, path: HONEYPOT_ROUTE, ua, aiUsed, query });

  // Notify admin for suspicious AI-served hits
  if (isSuspicious && _notifyAdmin) {
    _notifyAdmin(
      `🍯 <b>Honeypot Engaged!</b>\n` +
      `🤖 AI Response: <b>${aiUsed ? 'Gemini ✅' : 'Static'}</b>\n` +
      `🌐 IP: <code>${ip}</code>\n` +
      `🔍 Query: <code>${query || '(none)'}</code>\n` +
      `📋 Probe Count: <b>${suspiciousIPs.get(ip)?.count || '?'}</b>`
    ).catch(() => {});
  }

  // Add fake response headers to look like Apache/PHP
  res.set('X-Server-Instance', randomChoice(FAKE_HOSTS));
  res.set('X-Request-ID', `npw-${Date.now().toString(36)}`);

  return res.status(200).json(responseData);
}

// ─────────────────────────────────────────────────────────────
//  ADMIN ENDPOINTS
// ─────────────────────────────────────────────────────────────
function getHoneypotLogs(req, res) {
  const stats = {
    totalProbes: honeypotLogs.filter(l => l.type === 'probe').length,
    totalHits:   honeypotLogs.filter(l => l.type === 'hit').length,
    aiResponses: honeypotLogs.filter(l => l.aiUsed).length,
    uniqueIPs:   new Set(honeypotLogs.map(l => l.ip)).size,
    suspiciousIPCount: suspiciousIPs.size,
  };

  const suspiciousList = [...suspiciousIPs.entries()].map(([ip, rec]) => ({
    ip,
    count: rec.count,
    firstSeen: rec.firstSeen,
    lastSeen: rec.lastSeen,
    paths: [...rec.paths],
    ua: rec.ua,
  })).sort((a, b) => b.count - a.count).slice(0, 50);

  return res.json({
    success: true,
    data: { stats, logs: honeypotLogs.slice(0, 100), suspiciousList },
  });
}

function clearHoneypotLogs(req, res) {
  honeypotLogs.length = 0;
  suspiciousIPs.clear();
  rateLimitMap.clear();
  return res.json({ success: true, message: 'Honeypot logs cleared' });
}

// ─────────────────────────────────────────────────────────────
//  GEMINI API KEY TEST (Telegram /checkai command မှ ခေါ်သည်)
// ─────────────────────────────────────────────────────────────
async function testGeminiApiKey() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return { ok: false, error: 'GEMINI_API_KEY environment variable မထည့်ရသေးပါ' };
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });
    const result = await model.generateContent('Reply with exactly: "OK"');
    const text   = result.response.text().trim().slice(0, 200);
    return { ok: true, model: 'gemini-2.0-flash', text };
  } catch (err) {
    return { ok: false, error: err.message || 'Unknown error' };
  }
}

// ─────────────────────────────────────────────────────────────
//  EXPORTS
// ─────────────────────────────────────────────────────────────
module.exports = {
  init,
  honeypotDetect,
  honeypotRateLimit,
  honeypotSystemStatus,
  getHoneypotLogs,
  clearHoneypotLogs,
  testGeminiApiKey,
  // expose state for external inspection if needed
  suspiciousIPs,
  honeypotLogs,
  HONEYPOT_ROUTE,
};
