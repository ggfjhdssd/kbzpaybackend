require('dotenv').config();
const crypto = require('crypto');

const express    = require('express');
const mongoose   = require('mongoose');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const multer     = require('multer');
const { Telegraf } = require('telegraf');
const { message }  = require('telegraf/filters');

// ═══════════════════════════════════════════════════════════════
//  GLOBAL ERROR HANDLERS
// ═══════════════════════════════════════════════════════════════
process.on('unhandledRejection', (reason, promise) => {
  console.error('⚠️  UnhandledRejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('⚠️  UncaughtException:', err.message);
});

// ═══════════════════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════════════════
const PORT           = process.env.PORT           || 5000;
const ADMIN_ID       = process.env.ADMIN_CHAT_ID;
const ADMIN_SECRET   = process.env.ADMIN_SECRET   || 'changeme_admin_secret';
const MIN_WITHDRAW   = Number(process.env.MIN_WITHDRAW)   || 100000;
const SERVICE_FEE    = Number(process.env.SERVICE_FEE)    || 5000;
const REFERRAL_BONUS = Number(process.env.REFERRAL_BONUS) || 5000;
const PAYMENT_PHONE  = process.env.PAYMENT_PHONE  || '09783646736';
const PAYMENT_NAME   = process.env.PAYMENT_NAME   || 'Yee Mon Naing';
const BOT_USERNAME   = process.env.BOT_USERNAME   || 'YourBotUsername';
const FRONTEND_URL   = 'https://kbzpayfrontend.vercel.app';
const CHANNEL_ID     = process.env.CHANNEL_ID    || '@Kbzzpay';
const CHANNEL_LINK   = process.env.CHANNEL_LINK  || 'https://t.me/Kbzzpay';

// ═══════════════════════════════════════════════════════════════
//  SECURITY: Data Masking Utilities
//  telegramId ကို Frontend ဆီ Base64 Mask လုပ်ပြီးမှ ပို့သည်
//  Inspect Element နဲ့ကြည့်ရင်တောင် ID အစစ် မမြင်ရ
// ═══════════════════════════════════════════════════════════════
const maskTid = (tid) =>
  Buffer.from(String(tid || '')).toString('base64');

const unmaskTid = (val) => {
  if (!val) return null;
  try {
    const decoded = Buffer.from(String(val), 'base64').toString('utf8');
    if (/^\d{5,15}$/.test(decoded)) return decoded;
  } catch {}
  if (/^\d{5,15}$/.test(String(val))) return String(val);
  return null;
};

// ═══════════════════════════════════════════════════════════════
//  SECURITY: Error Sanitization
//  File Path, DB Name, IP တွေ error response မှ ဖယ်ရှားသည်
// ═══════════════════════════════════════════════════════════════
const sanitizeErrMsg = (err) => {
  const code = err?.code || '';
  const name = err?.name || '';
  const raw  = err?.message || String(err) || '';

  if (code === 'E11000' || raw.includes('duplicate key'))
    return 'ရှိပြီးသား မှတ်တမ်း — ထပ်မကြိုးစားနဲ့ပါ';
  if (name === 'ValidationError' || raw.includes('ValidationError'))
    return 'ထည့်သွင်းသော ဒေတာ မမှန်ကန်ပါ';
  if (raw.includes('Cast to ObjectId') || raw.includes('ObjectId'))
    return 'Invalid request format';
  if (raw.includes('ECONNREFUSED') || raw.includes('ETIMEDOUT'))
    return 'Service ယာယီ မရနိုင်ပါ — နောက်မှ ထပ်ကြိုးစားပါ';
  return 'Request ကို ဆောင်ရွက်၍ မရပါ — ခေတ္တ ထပ်ကြိုးစားပါ';
};

// ═══════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const esc = (str) => String(str||'')
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const OK = ['image/jpeg','image/jpg','image/png','image/webp','image/gif'];
    if (OK.includes(file.mimetype)) cb(null, true);
    else cb(new Error('ပုံဖိုင်သာ တင်ခွင့်ရှိသည် (JPG/PNG/WEBP)'), false);
  },
});

const handleMulterError = (err, req, res, next) => {
  if (!err) return next();
  if (err.code === 'LIMIT_FILE_SIZE')
    return res.status(400).json({ success: false, message: 'ပုံဖိုင် 10MB ထက်ကြီးနေသည်' });
  if (err.code === 'LIMIT_UNEXPECTED_FILE')
    return res.status(400).json({ success: false, message: '"screenshot" field name သုံးပါ' });
  if (err.message?.includes('ပုံဖိုင်သာ'))
    return res.status(400).json({ success: false, message: err.message });
  next(err);
};

// ═══════════════════════════════════════════════════════════════
//  MONGOOSE MODELS
// ═══════════════════════════════════════════════════════════════
const userSchema = new mongoose.Schema({
  telegramId:     { type: String, required: true, unique: true },
  firstName:      { type: String, default: '' },
  lastName:       { type: String, default: '' },
  username:       { type: String, default: '' },
  balance:        { type: Number, default: 0, min: 0 },
  totalEarned:    { type: Number, default: 0 },
  totalWithdrawn: { type: Number, default: 0 },
  referrals:      { type: Number, default: 0 },
  referredBy:     { type: String, default: null },
  referralCode:   { type: String, unique: true, sparse: true },
  isBanned:       { type: Boolean, default: false },
  isBlocked:      { type: Boolean, default: false },
  banReason:      { type: String, default: '' },
  isAdmin:        { type: Boolean, default: false },
  lastSeen:       { type: Date, default: Date.now },
  lastBonusClaim: { type: Number, default: 0 },
}, { timestamps: true });

userSchema.index({ referralCode: 1 }, { sparse: true });
userSchema.index({ isBanned: 1 });
userSchema.index({ referrals: -1, totalEarned: -1 });
userSchema.index({ isBlocked: 1 });
userSchema.virtual('displayName').get(function () {
  return [this.firstName, this.lastName].filter(Boolean).join(' ')
    || this.username || `User ${this.telegramId}`;
});
userSchema.set('toJSON', { virtuals: true });
const User = mongoose.model('User', userSchema);

const withdrawalSchema = new mongoose.Schema({
  user:                { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  telegramId:          { type: String, required: true },
  amount:              { type: Number, required: true },
  fee:                 { type: Number, default: 5000 },
  netAmount:           { type: Number, required: true },
  userKpayPhone:       { type: String, default: '' },
  userKpayName:        { type: String, default: '' },
  telegramPhotoFileId: { type: String, default: '' },
  status:              { type: String, enum: ['pending','approved','rejected'], default: 'pending' },
  rejectionReason:     { type: String, default: '' },
  adminNote:           { type: String, default: '' },
  reviewedAt:          { type: Date },
  deletedAt:           { type: Date, default: null },
}, { timestamps: true });

withdrawalSchema.index({ telegramId: 1 });
withdrawalSchema.index({ status: 1 });
withdrawalSchema.index({ deletedAt: 1 }, { expireAfterSeconds: 259200, sparse: true });
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

const supportSchema = new mongoose.Schema({
  telegramId:  { type: String, required: true },
  displayName: { type: String, default: '' },
  text:        { type: String, required: true },
  direction:   { type: String, enum: ['user_to_admin','admin_to_user'], required: true },
  isRead:      { type: Boolean, default: false },
}, { timestamps: true });
supportSchema.index({ telegramId: 1 });
supportSchema.index({ createdAt: 1 }, { expireAfterSeconds: 259200 });
const SupportMsg = mongoose.model('SupportMessage', supportSchema);

const botMessageSchema = new mongoose.Schema({
  telegramId: { type: String, required: true, index: true },
  messageId:  { type: Number, required: true },
}, { timestamps: true });
botMessageSchema.index({ telegramId: 1, messageId: 1 }, { unique: true });
botMessageSchema.index({ createdAt: 1 }, { expireAfterSeconds: 604800 });
const BotMessage = mongoose.model('BotMessage', botMessageSchema);

const paymentConfigSchema = new mongoose.Schema({
  key:   { type: String, required: true, unique: true },
  phone: { type: String, default: '09783646736' },
  name:  { type: String, default: 'Yee Mon Naing' },
}, { timestamps: true });
const PaymentConfig = mongoose.model('PaymentConfig', paymentConfigSchema);

// ═══════════════════════════════════════════════════════════════
//  EXPRESS APP
// ═══════════════════════════════════════════════════════════════
const app = express();

app.use(helmet({ crossOriginResourcePolicy: false }));
app.disable('x-powered-by'); // Real header ဖယ်ရှားသည်

// ═══════════════════════════════════════════════════════════════
//  SECURITY: Fake Headers Middleware
//  Node.js သုံးမှန်း Hacker မသိအောင် PHP/Apache အဖြစ် ပြသည်
// ═══════════════════════════════════════════════════════════════
app.use((_req, res, next) => {
  res.setHeader('X-Powered-By', 'PHP/7.4.33');
  res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

const ALLOWED_ORIGINS = [
  FRONTEND_URL,
  'https://kbzpayfrontend.vercel.app',
  'https://kbzpaybackend.onrender.com',
  'http://localhost:3000',
  'http://localhost:5000',
];
const corsOpts = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    if (origin.endsWith('.vercel.app')) return cb(null, true);
    return cb(new Error('CORS blocked'));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','x-telegram-id','x-init-data','X-Telegram-Init-Data','x-admin-secret','Authorization'],
  credentials: true,
  optionsSuccessStatus: 200,
};
app.use(cors(corsOpts));
app.options('*', cors(corsOpts));
app.use(rateLimit({ windowMs: 60000, max: 90, standardHeaders: true, legacyHeaders: false, message: { success: false, message: 'Too many requests' } }));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

function parseTidFromInitData(initDataStr) {
  try {
    if (!initDataStr) return null;
    const params  = new URLSearchParams(initDataStr);
    const userStr = params.get('user');
    if (!userStr) return null;
    const u = JSON.parse(userStr);
    return u?.id ? String(u.id) : null;
  } catch { return null; }
}

// Base64 masked ID ပါ accept လုပ်သော getTidFromReq
function getTidFromReq(req) {
  const hRaw = (req.headers['x-telegram-id'] || '').trim();
  if (hRaw && hRaw !== 'demo' && hRaw !== 'null' && hRaw !== 'undefined') {
    const decoded = unmaskTid(hRaw);
    if (decoded) return decoded;
  }
  const bRaw = String(req.body?.telegramId || '').trim();
  if (bRaw && bRaw !== 'demo' && bRaw !== 'null' && bRaw !== 'undefined') {
    const decoded = unmaskTid(bRaw);
    if (decoded) return decoded;
  }
  const initData = req.headers['x-telegram-init-data'] || req.headers['x-init-data'] || '';
  if (initData) {
    const parsed = parseTidFromInitData(initData);
    if (parsed) return parsed;
  }
  return null;
}

const requireUser = asyncHandler(async (req, res, next) => {
  const tid = getTidFromReq(req);
  if (!tid) return res.status(401).json({ success: false, message: 'Telegram ID မရှိပါ — Bot မှ App ဖွင့်ပါ' });
  const u = await User.findOne({ telegramId: tid });
  if (!u) return res.status(404).json({ success: false, message: 'User not found. Please start the bot first.' });
  if (u.isBanned) return res.status(403).json({ success: false, message: `🚫 Account banned: ${esc(u.banReason)}` });
  req.user = u; next();
});

const requireAdmin = (req, res, next) => {
  const s = req.headers['x-admin-secret'];
  if (!s || s !== ADMIN_SECRET) return res.status(403).json({ success: false, message: 'Forbidden' });
  next();
};

let bot = null;

const sendTg = async (chatId, text, extra = {}) => {
  if (!bot) return null;
  try {
    const msg = await bot.telegram.sendMessage(String(chatId), text, { parse_mode: 'HTML', ...extra });
    if (msg?.message_id) BotMessage.create({ telegramId: String(chatId), messageId: msg.message_id }).catch(() => {});
    return msg;
  } catch (e) {
    if (e.response?.error_code === 403 || e.message?.includes('bot was blocked'))
      await User.findOneAndUpdate({ telegramId: String(chatId) }, { isBlocked: true }).catch(() => {});
    return null;
  }
};

const sendTgPhoto = async (chatId, buffer, filename, caption, extra = {}) => {
  if (!bot) return null;
  try {
    const msg = await bot.telegram.sendPhoto(String(chatId),
      { source: buffer, filename: filename || 'screenshot.jpg' },
      { caption, parse_mode: 'HTML', ...extra }
    );
    if (msg?.message_id) BotMessage.create({ telegramId: String(chatId), messageId: msg.message_id }).catch(() => {});
    return msg;
  } catch (e) {
    if (e.response?.error_code === 403 || e.message?.includes('bot was blocked'))
      await User.findOneAndUpdate({ telegramId: String(chatId) }, { isBlocked: true }).catch(() => {});
    return null;
  }
};

// ═══════════════════════════════════════════════════════════════
//  ROUTES
// ═══════════════════════════════════════════════════════════════
app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'KBZPay Backend', time: new Date().toISOString() }));

// ═══════════════════════════════════════════════════════════════
//  SECURITY: Honeypot Routes
//  Hacker တွေ probe လုပ်ရင် Fake Server Info ပြသည်
//  နေပြည်တော် Myanmar Server တစ်ခုကဲ့သို့ ထင်ယောင်ထင်မှားဖြစ်စေသည်
// ═══════════════════════════════════════════════════════════════
app.all(['/api/v1/system-status', '/admin/server-info', '/api/server', '/system/info'], (req, res) => {
  console.warn(`[🍯 HONEYPOT] ${new Date().toISOString()} | IP:${req.ip} | ${req.path} | UA:${(req.headers['user-agent']||'').slice(0,80)}`);
  const fakeUptime = Math.floor(Math.random() * 20 + 5);
  const fakeLoad   = (Math.random() * 0.5 + 0.1).toFixed(2);
  const fakeOctet  = Math.floor(Math.random() * 50 + 40);
  res.status(200).json({
    status: 'operational',
    server: {
      hostname: 'prod-web-01.kbzpay.internal',
      ip: `203.81.80.${fakeOctet}`,
      location: 'Naypyidaw, Myanmar',
      region: 'AP-Southeast-Myanmar',
      datacenter: 'KBZ DC-1 Naypyidaw',
      os: 'Ubuntu 20.04.6 LTS',
    },
    framework: { name: 'Laravel', version: '9.52.16', php: '7.4.33' },
    database:  { type: 'MySQL', version: '8.0.35', host: '10.10.0.12', name: 'kbzpay_production' },
    cache:     { type: 'Redis', version: '7.0.11', host: '10.10.0.14' },
    uptime: `${fakeUptime}d 7h 23m`, load: fakeLoad,
    timestamp: new Date().toISOString(),
  });
});

// ═══════════════════════════════════════════════════════════════
//  API ROUTES — Obfuscated Names
//  /api/v2/app-cfg              (was /api/config)
//  /api/v3/media-task-processor (was /api/ad-reward)
//  /api/v3/promo-grant-handler  (was /api/claim-bonus)
//  /api/v2/auth-session         (was POST /api/users/me)
//  /api/v2/rank-board           (was /api/users/leaderboard)
//  /api/v3/secure-payout-handler(was POST /api/withdrawals)
//  /api/v2/payout-records       (was GET /api/withdrawals/mine)
//  /api/v2/settled-payouts      (was GET /api/withdrawals/recent)
//  /api/v3/p2p-exchange-handler (was /api/p2p)
//  /api/mgmt/...                (was /api/admin/...)
// ═══════════════════════════════════════════════════════════════

app.get('/api/v2/app-cfg', asyncHandler(async (_req, res) => {
  const cfg = await PaymentConfig.findOne({ key: 'payment' }).catch(() => null);
  res.json({
    success: true,
    data: {
      paymentPhone:  cfg?.phone || PAYMENT_PHONE,
      paymentName:   cfg?.name  || PAYMENT_NAME,
      minWithdraw:   MIN_WITHDRAW,
      serviceFee:    SERVICE_FEE,
      referralBonus: REFERRAL_BONUS,
    },
  });
}));

app.post('/api/v3/media-task-processor', asyncHandler(async (req, res) => {
  const tid = getTidFromReq(req);
  if (!tid) return res.status(400).json({ success: false, message: 'Telegram ID မရှိပါ' });
  const reward = parseInt(req.body.amount) || 3000;
  if (reward <= 0 || reward > 10000)
    return res.status(400).json({ success: false, message: 'Invalid reward amount' });
  const updated = await User.findOneAndUpdate(
    { telegramId: tid },
    { $inc: { balance: reward, totalEarned: reward }, $setOnInsert: { telegramId: tid, referralCode: `ref_${tid}` } },
    { new: true, upsert: true }
  );
  res.json({ success: true, data: { newBalance: updated.balance } });
}));

app.post('/api/v3/promo-grant-handler', asyncHandler(async (req, res) => {
  const tid = getTidFromReq(req);
  if (!tid) return res.status(400).json({ success: false, message: 'Telegram ID မရှိပါ' });
  const BONUS = 3000, COOLDOWN = 2 * 60 * 60 * 1000, now = Date.now();
  let user = await User.findOne({ telegramId: tid });
  if (!user) user = await User.create({ telegramId: tid, referralCode: `ref_${tid}` });
  const elapsed = now - (user.lastBonusClaim || 0);
  if (elapsed < COOLDOWN) {
    const remainingSecs = Math.ceil((COOLDOWN - elapsed) / 1000);
    return res.status(429).json({ success: false, message: `${Math.ceil(remainingSecs/3600)} နာရီနောက်မှ ထပ်ယူနိုင်သည်`, cooldownSeconds: remainingSecs });
  }
  const updated = await User.findOneAndUpdate(
    { telegramId: tid },
    { $inc: { balance: BONUS, totalEarned: BONUS }, $set: { lastBonusClaim: now } },
    { new: true }
  );
  res.json({ success: true, data: { newBalance: updated.balance, reward: BONUS } });
}));

// User login — returns maskedId (Base64) instead of raw telegramId
app.post('/api/v2/auth-session', asyncHandler(async (req, res) => {
  let { telegramId, firstName, lastName, username, referralCode } = req.body;
  const resolvedTid = unmaskTid(telegramId) || telegramId;
  if (!resolvedTid) return res.status(400).json({ success: false, message: 'telegramId required' });
  telegramId = resolvedTid;

  let user = await User.findOne({ telegramId });
  if (!user) {
    const myCode = `ref_${telegramId}`;
    user = new User({ telegramId, firstName, lastName, username, referralCode: myCode });
    if (referralCode) {
      const cleanRefId = referralCode.replace('ref_', '');
      if (cleanRefId !== String(telegramId)) {
        const referrer = await User.findOne({ telegramId: cleanRefId });
        if (referrer && !referrer.isBanned) {
          await User.findByIdAndUpdate(referrer._id, { $inc: { balance: REFERRAL_BONUS, totalEarned: REFERRAL_BONUS, referrals: 1 } });
          user.referredBy = cleanRefId;
          await sendTg(cleanRefId, `🎉 <b>မိတ်ဆွေသစ် ရောက်လာပြီ!</b>\nReferral Bonus <b>${REFERRAL_BONUS.toLocaleString()} Ks</b> ထည့်ပေးပြီး`);
        }
      }
    }
    await user.save();
  } else {
    await User.findByIdAndUpdate(user._id, {
      firstName: firstName || user.firstName, lastName: lastName || user.lastName,
      username: username || user.username, lastSeen: new Date(), isBlocked: false,
    });
    user = await User.findById(user._id);
  }

  if (user.isBanned) return res.status(403).json({ success: false, message: `🚫 Account banned: ${esc(user.banReason)}` });

  // SECURITY: maskedId (Base64) ပေးပို့သည် — raw telegramId မပါ
  return res.json({
    success: true,
    data: {
      maskedId:       maskTid(user.telegramId),
      displayName:    user.displayName,
      firstName:      user.firstName,
      username:       user.username,
      balance:        user.balance,
      referrals:      user.referrals,
      totalEarned:    user.totalEarned,
      totalWithdrawn: user.totalWithdrawn,
      referralCode:   user.referralCode,
      referralLink:   `https://t.me/${BOT_USERNAME}?start=${user.referralCode}`,
      isAdmin:        user.isAdmin,
    },
  });
}));

app.get('/api/v2/rank-board', asyncHandler(async (_req, res) => {
  const users = await User.find({ isBanned: false })
    .sort({ referrals: -1, totalEarned: -1 }).limit(20)
    .select('firstName lastName username referrals totalEarned');
  res.json({ success: true, data: users.map((u, i) => ({
    rank: i + 1, name: u.displayName,
    avatar: u.displayName.split(' ').map(w => w[0]).join('').slice(0,2).toUpperCase(),
    referrals: u.referrals, earned: u.totalEarned,
  }))});
}));

// Withdrawal Submit
app.post('/api/v3/secure-payout-handler',
  requireUser,
  (req, res, next) => { upload.single('screenshot')(req, res, err => { if (err) return handleMulterError(err, req, res, next); next(); }); },
  asyncHandler(async (req, res) => {
    let balanceDeducted = false, deductAmount = 0;
    const user = req.user;
    try {
      const rawAmount  = req.body?.amount;
      const amount     = parseInt(rawAmount, 10);
      const uKpayPhone = (req.body?.userKpayPhone || '').trim();
      const uKpayName  = (req.body?.userKpayName  || '').trim();

      if (!req.file?.buffer) return res.status(400).json({ success: false, message: 'Screenshot ပုံတင်ရန် လိုအပ်သည်' });
      if (!rawAmount || isNaN(amount) || amount < MIN_WITHDRAW)
        return res.status(400).json({ success: false, message: `အနည်းဆုံး ${MIN_WITHDRAW.toLocaleString()} Ks ဖြစ်ရမည်` });
      if (user.balance < amount) return res.status(400).json({ success: false, message: 'လက်ကျန်ငွေ မလုံလောက်ပါ' });

      const hasPending = await Withdrawal.findOne({ telegramId: user.telegramId, status: 'pending' });
      if (hasPending) return res.status(409).json({ success: false, message: 'ကြိုတင်တင်ထားသော ငွေထုတ်မှု ရှိနေသေးပါသည်' });

      deductAmount = amount;
      const newBalance = user.balance - amount;
      await User.findByIdAndUpdate(user._id, { $inc: { balance: -amount } });
      balanceDeducted = true;

      let wd;
      try {
        wd = await Withdrawal.create({
          user: user._id, telegramId: user.telegramId, amount, fee: SERVICE_FEE,
          netAmount: amount - SERVICE_FEE, userKpayPhone: uKpayPhone, userKpayName: uKpayName,
        });
      } catch (dbErr) {
        await User.findByIdAndUpdate(user._id, { $inc: { balance: amount } }).catch(() => {});
        return res.status(500).json({ success: false, message: sanitizeErrMsg(dbErr) });
      }

      if (ADMIN_ID && bot) {
        const caption =
          `💸 <b>ငွေထုတ်ယူမှု တောင်းဆိုမှု</b>\n\n` +
          `👤 ${esc(user.displayName)} | @${user.username||'N/A'}\n` +
          `🆔 <code>${user.telegramId}</code>\n` +
          `💰 ${amount.toLocaleString()} Ks\n` +
          (uKpayPhone ? `💳 ${uKpayPhone} (${uKpayName||'N/A'})\n` : '') +
          `📅 ${new Date().toLocaleString()}`;
        const photoMsg = await sendTgPhoto(ADMIN_ID, req.file.buffer,
          req.file.originalname || 'screenshot.jpg', caption,
          { reply_markup: { inline_keyboard: [[
            { text: '✅ Approve', callback_data: `wd_approve_${wd._id}` },
            { text: '❌ Reject',  callback_data: `wd_reject_${wd._id}` },
          ]]}});
        if (photoMsg?.photo) {
          const fileId = photoMsg.photo[photoMsg.photo.length - 1].file_id;
          await Withdrawal.findByIdAndUpdate(wd._id, { telegramPhotoFileId: fileId }).catch(() => {});
        }
      }

      await sendTg(user.telegramId,
        `💸 <b>ငွေထုတ်ယူမှု တင်ပြီးပါပြီ</b>\n\n💰 ${amount.toLocaleString()} ကျပ်\n⏳ Processing...\n\n<b>၅ မှ ၁၅ မိနစ်အတွင်း</b> ငွေများ ရောက်ရှိမည်`
      );

      return res.status(201).json({
        success: true,
        message: 'ငွေထုတ်ယူမှု တင်ပြီးပါပြီ။',
        data: { id: wd._id, amount: wd.amount, fee: wd.fee, netAmount: wd.netAmount, status: wd.status, newBalance },
      });
    } catch (err) {
      if (balanceDeducted) await User.findByIdAndUpdate(user._id, { $inc: { balance: deductAmount } }).catch(() => {});
      return res.status(500).json({ success: false, message: sanitizeErrMsg(err) });
    }
  })
);

// P2P Submit
app.post('/api/v3/p2p-exchange-handler',
  (req, res, next) => { upload.single('screenshot')(req, res, err => { if (err) return handleMulterError(err, req, res, next); next(); }); },
  asyncHandler(async (req, res) => {
    const rawTid      = req.headers['x-telegram-id'];
    const resolvedTid = unmaskTid(rawTid) || rawTid;
    const user        = resolvedTid ? await User.findOne({ telegramId: resolvedTid }).catch(() => null) : null;
    const displayName = user?.displayName || (resolvedTid ? `User ${resolvedTid}` : 'Unknown');
    const uKpayPhone  = (req.body?.userKpayPhone || '').trim();
    const uKpayName   = (req.body?.userKpayName  || '').trim();
    const amount      = parseInt(req.body?.amount, 10);

    if (!req.file?.buffer) return res.status(400).json({ success: false, message: 'Screenshot ပုံတင်ရန် လိုအပ်သည်' });
    if (!amount || amount < 20000) return res.status(400).json({ success: false, message: 'အနည်းဆုံး 20,000 Ks ဖြစ်ရမည်' });

    if (ADMIN_ID && bot) {
      const caption =
        `💹 <b>Pay to Pay တောင်းဆိုမှု</b>\n\n` +
        `👤 ${esc(displayName)} | @${user?.username||'N/A'}\n` +
        `🆔 <code>${resolvedTid||'N/A'}</code>\n` +
        `💰 ${amount.toLocaleString()} Ks | ပြန်: ${(amount*5).toLocaleString()} Ks\n` +
        (uKpayPhone ? `💳 ${uKpayPhone} (${uKpayName||'N/A'})\n` : '') +
        `📅 ${new Date().toLocaleString()}`;
      await sendTgPhoto(ADMIN_ID, req.file.buffer, req.file.originalname || 'p2p.jpg', caption);
    }
    return res.status(201).json({ success: true, message: 'တင်ပြီးပါပြီ။ Admin မှ စစ်ဆေးပြီးနောက် Telegram မှ အကြောင်းကြားပါမည်' });
  })
);

app.get('/api/v2/payout-records', requireUser, asyncHandler(async (req, res) => {
  const wds = await Withdrawal.find({ telegramId: req.user.telegramId }).sort({ createdAt: -1 }).limit(20);
  res.json({ success: true, data: wds.map(w => ({
    id: w._id, amount: w.amount, fee: w.fee, netAmount: w.netAmount,
    status: w.status, createdAt: w.createdAt, reviewedAt: w.reviewedAt,
    rejectionReason: w.rejectionReason,
  }))});
}));

app.get('/api/v2/settled-payouts', asyncHandler(async (_req, res) => {
  const wds = await Withdrawal.find({ status: 'approved' }).sort({ updatedAt: -1 }).limit(20)
    .populate('user','firstName lastName username');
  res.json({ success: true, data: wds.map(w => ({
    id: w._id,
    name: w.user?.displayName || 'User',
    avatar: (w.user?.displayName||'U').split(' ').map(x=>x[0]).join('').slice(0,2).toUpperCase(),
    net: w.netAmount,
    date: w.updatedAt.toISOString().split('T')[0],
  }))});
}));

// ═══════════════════════════════════════════════════════════════
//  ADMIN ROUTES — /api/mgmt (obfuscated, was /api/admin)
// ═══════════════════════════════════════════════════════════════
const adminRouter = express.Router();
adminRouter.use(requireAdmin);

adminRouter.get('/stats', asyncHandler(async (_req, res) => {
  const [total, banned, blocked, pending, approved, rejected, balRes] = await Promise.all([
    User.countDocuments(), User.countDocuments({ isBanned: true }),
    User.countDocuments({ isBlocked: true }),
    Withdrawal.countDocuments({ status: 'pending' }),
    Withdrawal.countDocuments({ status: 'approved' }),
    Withdrawal.countDocuments({ status: 'rejected' }),
    User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' } } }]),
  ]);
  res.json({ success: true, data: { total, banned, blocked, withdrawals: { pending, approved, rejected }, totalBalance: balRes[0]?.total || 0 } });
}));

adminRouter.get('/users', asyncHandler(async (req, res) => {
  const { page=1, limit=30, search, banned } = req.query;
  const f = {};
  if (search) f.$or = [{ firstName: new RegExp(search,'i') },{ username: new RegExp(search,'i') },{ telegramId: search }];
  if (banned !== undefined) f.isBanned = banned === 'true';
  const [users, count] = await Promise.all([
    User.find(f).sort({ createdAt: -1 }).skip((page-1)*limit).limit(parseInt(limit)),
    User.countDocuments(f),
  ]);
  res.json({ success: true, data: users, total: count });
}));

adminRouter.post('/users/:tid/ban', asyncHandler(async (req, res) => {
  const { reason } = req.body;
  const u = await User.findOneAndUpdate({ telegramId: req.params.tid }, { isBanned: true, banReason: reason||'Violated terms' }, { new: true });
  if (!u) return res.status(404).json({ success: false, message: 'User not found' });
  await sendTg(u.telegramId, `🚫 <b>Account ပိတ်ထားပါသည်</b>\nအကြောင်း: ${reason||'Violated terms'}`);
  res.json({ success: true, data: u });
}));

adminRouter.post('/users/:tid/unban', asyncHandler(async (req, res) => {
  const u = await User.findOneAndUpdate({ telegramId: req.params.tid }, { isBanned: false, banReason: '' }, { new: true });
  if (!u) return res.status(404).json({ success: false, message: 'User not found' });
  await sendTg(u.telegramId, `✅ <b>Account ပြန်ဖွင့်ပေးပြီးပါပြီ</b>`);
  res.json({ success: true, data: u });
}));

adminRouter.patch('/users/:tid/balance', asyncHandler(async (req, res) => {
  const { action, amount, note } = req.body;
  if (!['add','subtract'].includes(action)) return res.status(400).json({ success: false, message: 'action: add|subtract' });
  const u = await User.findOne({ telegramId: req.params.tid });
  if (!u) return res.status(404).json({ success: false, message: 'User not found' });
  const delta = action === 'add' ? Math.abs(amount) : -Math.abs(amount);
  if (action === 'subtract' && u.balance < Math.abs(amount)) return res.status(400).json({ success: false, message: 'Insufficient balance' });
  const inc = { balance: delta }; if (action === 'add') inc.totalEarned = Math.abs(amount);
  const updated = await User.findByIdAndUpdate(u._id, { $inc: inc }, { new: true });
  await sendTg(u.telegramId, `💰 Admin မှ ${Math.abs(amount).toLocaleString()} Ks ${action==='add'?'ထည့်':'နုတ်'}ပေးပြီ\nလက်ကျန်: ${updated.balance.toLocaleString()} Ks${note?`\nမှတ်ချက်: ${note}`:''}`);
  res.json({ success: true, data: updated });
}));

adminRouter.patch('/users/:tid/referrals', asyncHandler(async (req, res) => {
  const { count } = req.body;
  const bonus = count * REFERRAL_BONUS;
  const u = await User.findOneAndUpdate({ telegramId: req.params.tid }, { $inc: { referrals: count, balance: bonus, totalEarned: bonus } }, { new: true });
  if (!u) return res.status(404).json({ success: false, message: 'User not found' });
  res.json({ success: true, data: u });
}));

adminRouter.get('/withdrawals', asyncHandler(async (req, res) => {
  const { status, page=1, limit=20 } = req.query;
  const f = {}; if (status) f.status = status;
  const [wds, total] = await Promise.all([
    Withdrawal.find(f).sort({ createdAt: -1 }).skip((page-1)*limit).limit(parseInt(limit)).populate('user','firstName lastName username telegramId'),
    Withdrawal.countDocuments(f),
  ]);
  res.json({ success: true, data: wds, total });
}));

adminRouter.post('/withdrawals/:id/approve', asyncHandler(async (req, res) => {
  const wd = await Withdrawal.findById(req.params.id).populate('user');
  if (!wd) return res.status(404).json({ success: false, message: 'Not found' });
  if (wd.status !== 'pending') return res.status(409).json({ success: false, message: 'Already processed' });
  wd.status = 'approved'; wd.reviewedAt = new Date(); wd.adminNote = req.body.note || '';
  await wd.save();
  await User.findByIdAndUpdate(wd.user._id, { $inc: { totalWithdrawn: wd.netAmount } });
  await sendTg(wd.telegramId, `✅ <b>ငွေထုတ်ယူမှု အတည်ပြုပြီး!</b>\n💰 ${wd.netAmount.toLocaleString()} Ks ပေးပို့မည်`);
  res.json({ success: true, data: wd });
}));

adminRouter.post('/withdrawals/:id/reject', asyncHandler(async (req, res) => {
  const { reason } = req.body;
  if (!reason) return res.status(400).json({ success: false, message: 'reason required' });
  const wd = await Withdrawal.findById(req.params.id).populate('user');
  if (!wd) return res.status(404).json({ success: false, message: 'Not found' });
  if (wd.status !== 'pending') return res.status(409).json({ success: false, message: 'Already processed' });
  wd.status = 'rejected'; wd.rejectionReason = reason; wd.reviewedAt = new Date(); wd.deletedAt = new Date();
  await wd.save();
  await User.findByIdAndUpdate(wd.user._id, { $inc: { balance: wd.amount + wd.fee } });
  await sendTg(wd.telegramId, `❌ <b>ငွေထုတ်ယူမှု ငြင်းပယ်</b>\nအကြောင်း: ${reason}\n💰 ${(wd.amount+wd.fee).toLocaleString()} Ks ပြန်ထည့်ပြီး`);
  res.json({ success: true, data: wd });
}));

adminRouter.get('/payment-config', asyncHandler(async (_req, res) => {
  const cfg = await PaymentConfig.findOne({ key: 'payment' });
  res.json({ success: true, data: cfg || { phone: PAYMENT_PHONE, name: PAYMENT_NAME } });
}));

adminRouter.post('/payment-config', asyncHandler(async (req, res) => {
  const { phone, name } = req.body;
  if (!phone || !name) return res.status(400).json({ success: false, message: 'phone and name required' });
  const cfg = await PaymentConfig.findOneAndUpdate({ key: 'payment' }, { phone: phone.trim(), name: name.trim() }, { upsert: true, new: true });
  res.json({ success: true, data: cfg });
}));

adminRouter.post('/broadcast', asyncHandler(async (req, res) => {
  const { message: msg } = req.body;
  if (!msg) return res.status(400).json({ success: false, message: 'message required' });
  const users = await User.find({ isBanned: false, isBlocked: false }).select('telegramId');
  let sent = 0, failed = 0;
  for (let i = 0; i < users.length; i++) {
    const ok = await sendTg(users[i].telegramId, `📢 <b>ကြေညာချက်</b>\n\n${msg}`);
    ok ? sent++ : failed++;
    if ((i + 1) % 20 === 0) await new Promise(r => setTimeout(r, 1000));
  }
  res.json({ success: true, data: { sent, failed, total: users.length } });
}));

app.use('/api/mgmt', adminRouter);
app.use((_req, res) => res.status(404).json({ success: false, message: 'Not found' }));

// ═══════════════════════════════════════════════════════════════
//  SECURITY: Global Error Handler — Sanitized
//  File path, DB name, Stack trace တွေ Client ဆီ မပို့
// ═══════════════════════════════════════════════════════════════
app.use((err, _req, res, _next) => {
  console.error('[ERR]', err?.code || '', err?.message || err);
  if (err.code === 'LIMIT_FILE_SIZE')       return res.status(400).json({ success: false, message: 'ပုံဖိုင် 10MB ထက်ကြီးနေသည်' });
  if (err.code === 'LIMIT_UNEXPECTED_FILE') return res.status(400).json({ success: false, message: '"screenshot" field name သုံးပါ' });
  if (err.message?.startsWith('CORS'))      return res.status(403).json({ success: false, message: 'Forbidden' });
  res.status(500).json({ success: false, message: sanitizeErrMsg(err) });
});

// ═══════════════════════════════════════════════════════════════
//  TELEGRAF BOT
// ═══════════════════════════════════════════════════════════════
function initBot() {
  if (!process.env.BOT_TOKEN) { console.warn('⚠️  BOT_TOKEN not set'); return; }
  bot = new Telegraf(process.env.BOT_TOKEN);
  const pendingReplies = {}, pendingRejections = {};

  async function isChannelMember(userId) {
    try {
      const m = await bot.telegram.getChatMember(CHANNEL_ID, Number(userId));
      return ['member','administrator','creator'].includes(m.status);
    } catch { return false; }
  }

  async function sendJoinPrompt(ctx, refCode = '') {
    const cbData = refCode ? `check_join_${ctx.from.id}_${refCode}` : `check_join_${ctx.from.id}_`;
    await ctx.reply(
      `👋 မင်္ဂလာပါ ${esc(ctx.from.first_name)}!\n\n⚠️ <b>Channel ကို အရင် Join ပါ</b>`,
      { parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '📢 Channel Join', url: CHANNEL_LINK }],[{ text: 'Joined ✅', callback_data: cbData }]] } }
    );
  }

  bot.start(async ctx => {
    const tgUser = ctx.from, chatId = String(ctx.chat.id), startParam = ctx.startPayload || '';
    try {
      if (chatId !== ADMIN_ID) {
        const joined = await isChannelMember(chatId);
        if (!joined) return sendJoinPrompt(ctx, startParam);
      }
      let user = await User.findOne({ telegramId: chatId });
      if (!user) {
        user = await User.create({ telegramId: chatId, firstName: tgUser.first_name||'', lastName: tgUser.last_name||'', username: tgUser.username||'', referralCode: `ref_${chatId}` });
        if (startParam) {
          const cleanRefId = startParam.replace('ref_', '');
          if (cleanRefId !== chatId) {
            const referrer = await User.findOne({ telegramId: cleanRefId });
            if (referrer && !referrer.isBanned) {
              await User.findByIdAndUpdate(referrer._id, { $inc: { balance: REFERRAL_BONUS, totalEarned: REFERRAL_BONUS, referrals: 1 } });
              user.referredBy = cleanRefId; await user.save();
              await sendTg(cleanRefId, `🎉 <b>မိတ်ဆွေသစ် ရောက်လာပြီ!</b>\nBonus <b>${REFERRAL_BONUS.toLocaleString()} Ks</b>`);
            }
          }
        }
      } else {
        await User.findByIdAndUpdate(user._id, { firstName: tgUser.first_name||user.firstName, lastName: tgUser.last_name||user.lastName, username: tgUser.username||user.username, lastSeen: new Date(), isBlocked: false });
      }
      if (user.isBanned) return ctx.reply(`🚫 Account ပိတ်ထားပါသည်\nအကြောင်း: ${esc(user.banReason)}`);
      const r = await ctx.reply(`👋 မင်္ဂလာပါ ${esc(tgUser.first_name)}\nKBZPay Mini App မှ ကြိုဆိုပါသည် 🎉\n\n💰 <b>App ဖွင့်မည်</b> ကိုနှိပ်ပါ`,
        { parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '💰 App ဖွင့်မည်', web_app: { url: FRONTEND_URL } }]] } });
      if (r?.message_id) BotMessage.create({ telegramId: chatId, messageId: r.message_id }).catch(() => {});
      if (ctx.message?.message_id) BotMessage.create({ telegramId: chatId, messageId: ctx.message.message_id }).catch(() => {});
    } catch (e) { console.error('Bot /start error:', e.message); }
  });

  bot.command('admin', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    ctx.reply(`🛠 <b>Admin Commands</b>\n\n/ban [id] [reason]\n/unban [id]\n/userinfo [id]\n/addmoney [id] [amt]\n/reducemoney [id] [amt]\n/addrefs [id] [count]\n/msg [id] [text]\n/broadcast [text]\n/stats\n/listusers [page]\n/topusers\n/richusers\n/delete [id]\n/setpayment [phone] [name]`, { parse_mode: 'HTML' });
  });

  bot.command('setpayment', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const parts = ctx.message.text.split(' ');
    if (parts.length < 3) return ctx.reply('Usage: /setpayment [phone] [name]');
    const phone = parts[1], name = parts.slice(2).join(' ');
    try {
      await PaymentConfig.findOneAndUpdate({ key: 'payment' }, { phone: phone.trim(), name: name.trim() }, { upsert: true, new: true });
      ctx.reply(`✅ Payment Config ပြောင်းပြီး\n📱 ${phone}\n👤 ${name}`, { parse_mode: 'HTML' });
    } catch { ctx.reply('❌ မအောင်မြင်ပါ'); }
  });

  bot.command('msg', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const parts = ctx.message.text.split(' ');
    if (parts.length < 3) return ctx.reply('Usage: /msg [id] [text]');
    const tid = parts[1], text = parts.slice(2).join(' ');
    const u = await User.findOne({ telegramId: tid }).catch(() => null);
    if (!u) return ctx.reply(`❌ User ${tid} not found`);
    const ok = await sendTg(tid, `📩 <b>Admin ထံမှ ပြန်စာ:</b>\n\n${esc(text)}`);
    if (ok) { await SupportMsg.create({ telegramId: tid, displayName: 'Admin', text, direction: 'admin_to_user' }).catch(() => {}); ctx.reply(`✅ Sent to ${esc(u.displayName)}`); }
    else ctx.reply('❌ Failed — user may have blocked bot');
  });

  bot.command('broadcast', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const text = ctx.message.text.replace('/broadcast', '').trim();
    if (!text) return ctx.reply('Usage: /broadcast [message]');
    const users = await User.find({ isBanned: false, isBlocked: false }).select('telegramId').catch(() => []);
    ctx.reply(`📢 Broadcasting to ${users.length} users...`);
    let sent = 0, failed = 0;
    for (let i = 0; i < users.length; i++) {
      (await sendTg(users[i].telegramId, `📢 <b>ကြေညာချက်</b>\n\n${esc(text)}`)) ? sent++ : failed++;
      if ((i + 1) % 20 === 0) await new Promise(r => setTimeout(r, 1000));
    }
    ctx.reply(`✅ Done\nSent: ${sent} | Failed: ${failed}`);
  });

  bot.command('ban', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [,tid,...rs] = ctx.message.text.split(' ');
    const reason = rs.join(' ') || 'Violated terms';
    if (!tid) return ctx.reply('Usage: /ban [id] [reason]');
    const u = await User.findOneAndUpdate({ telegramId: tid }, { isBanned: true, banReason: reason }, { new: true }).catch(()=>null);
    if (!u) return ctx.reply(`❌ Not found`);
    await sendTg(tid, `🚫 Account ပိတ်ထားပါသည်\nအကြောင်း: ${esc(reason)}`);
    ctx.reply(`✅ Banned: ${esc(u.displayName)}`);
  });

  bot.command('unban', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const tid = ctx.message.text.split(' ')[1];
    if (!tid) return ctx.reply('Usage: /unban [id]');
    const u = await User.findOneAndUpdate({ telegramId: tid }, { isBanned: false, banReason: '' }, { new: true }).catch(()=>null);
    if (!u) return ctx.reply('❌ Not found');
    await sendTg(tid, '✅ Account ပြန်ဖွင့်ပြီး');
    ctx.reply(`✅ Unbanned: ${esc(u.displayName)}`);
  });

  bot.command('addmoney', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [,tid,amtStr] = ctx.message.text.split(' ');
    if (!tid||!amtStr) return ctx.reply('Usage: /addmoney [id] [amount]');
    const amt = parseInt(amtStr);
    const u = await User.findOneAndUpdate({ telegramId: tid }, { $inc: { balance: amt, totalEarned: amt } }, { new: true }).catch(()=>null);
    if (!u) return ctx.reply('❌ Not found');
    await sendTg(tid, `💰 Admin မှ ${amt.toLocaleString()} Ks ထည့်ပေးပြီ`);
    ctx.reply(`✅ Added ${amt.toLocaleString()} Ks → ${esc(u.displayName)}`);
  });

  bot.command('reducemoney', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [,tid,amtStr] = ctx.message.text.split(' ');
    if (!tid||!amtStr) return ctx.reply('Usage: /reducemoney [id] [amount]');
    const amt = parseInt(amtStr), u = await User.findOne({ telegramId: tid }).catch(()=>null);
    if (!u) return ctx.reply('❌ Not found');
    if (u.balance < amt) return ctx.reply('❌ Insufficient balance');
    await User.findByIdAndUpdate(u._id, { $inc: { balance: -amt } });
    ctx.reply(`✅ Reduced ${amt.toLocaleString()} Ks`);
  });

  bot.command('addrefs', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [,tid,cStr] = ctx.message.text.split(' ');
    if (!tid||!cStr) return ctx.reply('Usage: /addrefs [id] [count]');
    const count = parseInt(cStr), bonus = count * REFERRAL_BONUS;
    const u = await User.findOneAndUpdate({ telegramId: tid }, { $inc: { referrals: count, balance: bonus, totalEarned: bonus } }, { new: true }).catch(()=>null);
    if (!u) return ctx.reply('❌ Not found');
    ctx.reply(`✅ Added ${count} refs (+${bonus.toLocaleString()} Ks)`);
  });

  bot.command('userinfo', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const tid = ctx.message.text.split(' ')[1];
    if (!tid) return ctx.reply('Usage: /userinfo [id]');
    const u = await User.findOne({ telegramId: tid }).catch(()=>null);
    if (!u) return ctx.reply('❌ Not found');
    const pw = await Withdrawal.countDocuments({ telegramId: tid, status: 'pending' });
    ctx.reply(
      `👤 <b>User Info</b>\n━━━━━━━━━━\n📛 ${esc(u.displayName)}\n🔖 @${u.username||'N/A'}\n🆔 <code>${u.telegramId}</code>\n━━━━━━━━━━\n💰 ${u.balance.toLocaleString()} Ks\n📈 Earned: ${u.totalEarned.toLocaleString()} Ks\n📤 Withdrawn: ${u.totalWithdrawn.toLocaleString()} Ks\n👥 Refs: ${u.referrals} | ⏳ Pending WD: ${pw}\n🚫 Banned: ${u.isBanned?'Yes':'No'}\n📅 ${u.createdAt.toLocaleDateString()}`,
      { parse_mode: 'HTML' }
    );
  });

  bot.command('stats', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [total, banned, blocked, pending, approved, rejected] = await Promise.all([
      User.countDocuments(), User.countDocuments({ isBanned: true }), User.countDocuments({ isBlocked: true }),
      Withdrawal.countDocuments({ status: 'pending' }), Withdrawal.countDocuments({ status: 'approved' }), Withdrawal.countDocuments({ status: 'rejected' }),
    ]);
    const [balRes, todayU] = await Promise.all([
      User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' }, te: { $sum: '$totalEarned' } } }]),
      User.countDocuments({ createdAt: { $gte: new Date(new Date().setHours(0,0,0,0)) } }),
    ]);
    ctx.reply(
      `📊 <b>Statistics</b>\n━━━━━━━━━━\n👥 Users: ${total} (Today: ${todayU})\n🚫 Banned: ${banned} | 🔇 Blocked: ${blocked}\n━━━━━━━━━━\n⏳ Pending WD: ${pending}\n✅ Approved: ${approved} | ❌ Rejected: ${rejected}\n━━━━━━━━━━\n💰 Total Balance: ${(balRes[0]?.total||0).toLocaleString()} Ks`,
      { parse_mode: 'HTML' }
    );
  });

  bot.command('listusers', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const page = parseInt(ctx.message.text.split(' ')[1]) || 1;
    const limit = 10, skip = (page-1)*limit;
    const [users, total] = await Promise.all([User.find().sort({ createdAt: -1 }).skip(skip).limit(limit), User.countDocuments()]);
    if (!users.length) return ctx.reply(`❌ Page ${page} မရှိပါ`);
    let text = `👥 Page ${page}/${Math.ceil(total/limit)} | Total: ${total}\n━━━━━━━━━━\n`;
    users.forEach((u,i) => { text += `${skip+i+1}. ${esc(u.displayName)} <code>${u.telegramId}</code>\n💰 ${u.balance.toLocaleString()} | 👥 ${u.referrals}${u.isBanned?' 🚫':''}\n`; });
    ctx.reply(text, { parse_mode: 'HTML' });
  });

  bot.command('topusers', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const users = await User.find({ isBanned: false }).sort({ referrals: -1 }).limit(10);
    let text = `🏆 <b>Top 10</b>\n━━━━━━━━━━\n`;
    users.forEach((u,i) => { text += `${['🥇','🥈','🥉'][i]||`${i+1}.`} ${esc(u.displayName)} — ${u.referrals} refs\n`; });
    ctx.reply(text, { parse_mode: 'HTML' });
  });

  bot.command('richusers', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const users = await User.find({ isBanned: false }).sort({ balance: -1 }).limit(10);
    let text = `💰 <b>Top Rich</b>\n━━━━━━━━━━\n`;
    users.forEach((u,i) => { text += `${i+1}. ${esc(u.displayName)} — ${u.balance.toLocaleString()} Ks\n`; });
    ctx.reply(text, { parse_mode: 'HTML' });
  });

  bot.command('delete', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const tid = ctx.message.text.split(' ')[1]?.trim();
    if (!tid) return ctx.reply('Usage: /delete [telegramId]');
    try {
      const u = await User.findOne({ telegramId: tid });
      if (!u) return ctx.reply(`❌ User <code>${esc(tid)}</code> မတွေ့ပါ`, { parse_mode: 'HTML' });
      await sendTg(tid, `လူကြီးမင်းသည်ရုပ်‌‌ေလးကလည်း‌ချောအသား‌ေလးကလည်းညို‌ေချာ‌ေလးဖြစ်ပြီးစေသနာလည်းအရမ်းကောင်းသောသူတစ်ဦးဖြစ်ပါတယ်ရှင့်🥰🥰\n\nပိုက်ဆံလွှဲပြောင်းနေပါသည်`);
      const pm = await ctx.reply(`⏳ Deleting ${esc(u.displayName)}...`, { parse_mode: 'HTML' });
      const msgs = await BotMessage.find({ telegramId: tid }).select('messageId').lean();
      let tgD = 0, tgF = 0;
      for (const { messageId } of msgs) {
        try { await bot.telegram.deleteMessage(tid, messageId); tgD++; } catch { tgF++; }
        await new Promise(r => setTimeout(r, 50));
      }
      const [wdR, smR] = await Promise.all([Withdrawal.deleteMany({ telegramId: tid }), SupportMsg.deleteMany({ telegramId: tid })]);
      await BotMessage.deleteMany({ telegramId: tid });
      await User.deleteOne({ telegramId: tid });
      const rpt = `🗑 <b>Done</b>\n👤 ${esc(u.displayName)} | <code>${tid}</code>\n📱 TG: ${tgD} deleted (${tgF} skipped)\n💸 WD: ${wdR.deletedCount} | 💬 Msgs: ${smR.deletedCount}`;
      await bot.telegram.editMessageText(ADMIN_ID, pm.message_id, undefined, rpt, { parse_mode: 'HTML' }).catch(() => ctx.reply(rpt, { parse_mode: 'HTML' }));
    } catch { ctx.reply('❌ မအောင်မြင်ပါ'); }
  });

  // Text messages
  bot.on(message('text'), async ctx => {
    if (ctx.message.text.startsWith('/')) return;
    const chatId = String(ctx.chat.id);

    if (chatId === ADMIN_ID) {
      if (pendingReplies[ADMIN_ID]) {
        const targetId = pendingReplies[ADMIN_ID]; delete pendingReplies[ADMIN_ID];
        await sendTg(targetId, `📩 <b>Admin ထံမှ ပြန်စာ:</b>\n\n${esc(ctx.message.text)}`);
        await SupportMsg.create({ telegramId: targetId, displayName: 'Admin', text: ctx.message.text, direction: 'admin_to_user' }).catch(()=>{});
        return ctx.reply(`✅ Reply sent to ${targetId}`);
      }
      if (pendingRejections[ADMIN_ID]) {
        const wdId = pendingRejections[ADMIN_ID]; delete pendingRejections[ADMIN_ID];
        const wd = await Withdrawal.findById(wdId).populate('user').catch(()=>null);
        if (wd && wd.status === 'pending') {
          wd.status = 'rejected'; wd.rejectionReason = ctx.message.text; wd.reviewedAt = new Date(); wd.deletedAt = new Date();
          await wd.save();
          await User.findByIdAndUpdate(wd.user._id, { $inc: { balance: wd.amount + wd.fee } });
          await sendTg(wd.telegramId, `❌ <b>ငွေထုတ်ယူမှု ငြင်းပယ်</b>\nအကြောင်း: ${ctx.message.text}\n💰 ${(wd.amount+wd.fee).toLocaleString()} Ks ပြန်ထည့်ပြီး`);
          return ctx.reply('✅ Rejected — refunded');
        }
        return ctx.reply('❌ Not found or already processed');
      }
      return;
    }

    const u = await User.findOne({ telegramId: chatId }).catch(()=>null);
    if (!u || u.isBanned) return;
    if (ctx.message?.message_id) BotMessage.create({ telegramId: chatId, messageId: ctx.message.message_id }).catch(() => {});
    await SupportMsg.create({ telegramId: chatId, displayName: u.displayName, text: ctx.message.text, direction: 'user_to_admin' }).catch(()=>{});
    if (ADMIN_ID) {
      await sendTg(ADMIN_ID,
        `📨 <b>Support</b>\n👤 ${esc(u.displayName)} (@${u.username||'N/A'})\n🆔 <code>${chatId}</code>\n\n💬 ${esc(ctx.message.text)}`,
        { reply_markup: { inline_keyboard: [[{ text: '↩️ Reply', callback_data: `reply_${chatId}` }]] } }
      );
    }
    const ack = await ctx.reply('✅ Admin ထံ ပေးပို့ပြီး — မကြာမီ ပြန်ကြားပါမည်');
    if (ack?.message_id) BotMessage.create({ telegramId: chatId, messageId: ack.message_id }).catch(() => {});
  });

  // ═══════════════════════════════════════════════════════════════
  //  NEW FEATURE: Photo Forward
  //  User မှ Bot ကို ဓာတ်ပုံ ပို့ရင် Admin ဆီ Forward လုပ်သည်
  // ═══════════════════════════════════════════════════════════════
  bot.on(message('photo'), async ctx => {
    const chatId = String(ctx.chat.id);
    if (chatId === ADMIN_ID) return; // Admin ဆီမှ ပုံ skip

    const u = await User.findOne({ telegramId: chatId }).catch(() => null);
    if (!u || u.isBanned) return;

    // Track message
    if (ctx.message?.message_id) BotMessage.create({ telegramId: chatId, messageId: ctx.message.message_id }).catch(() => {});

    const caption = ctx.message.caption || '';
    await SupportMsg.create({
      telegramId: chatId, displayName: u.displayName,
      text: `[📸 Photo]${caption ? ' — ' + caption : ''}`,
      direction: 'user_to_admin',
    }).catch(() => {});

    // Admin ဆီ forward လုပ်သည်
    if (ADMIN_ID) {
      const photos    = ctx.message.photo;
      const fileId    = photos[photos.length - 1].file_id; // Highest resolution
      const adminCaption =
        `📸 <b>User ထံမှ ဓာတ်ပုံ</b>\n` +
        `👤 ${esc(u.displayName)} (@${u.username||'N/A'})\n` +
        `🆔 <code>${chatId}</code>\n` +
        (caption ? `💬 ${esc(caption)}\n` : '') +
        `📅 ${new Date().toLocaleString()}`;
      try {
        await bot.telegram.sendPhoto(ADMIN_ID, fileId, {
          caption: adminCaption,
          parse_mode: 'HTML',
          reply_markup: { inline_keyboard: [[{ text: '↩️ Reply', callback_data: `reply_${chatId}` }]] },
        });
      } catch (e) { console.warn('[photo-forward] error:', e.message); }
    }

    const ack = await ctx.reply('📸 ဓာတ်ပုံ Admin ဆီ ပေးပို့ပြီး — မကြာမီ ပြန်ကြားပါမည်').catch(() => null);
    if (ack?.message_id) BotMessage.create({ telegramId: chatId, messageId: ack.message_id }).catch(() => {});
  });

  // Callback queries
  bot.on('callback_query', async ctx => {
    const adminId = String(ctx.from.id), data = ctx.callbackQuery.data;

    if (data.startsWith('check_join_')) {
      const userId = String(ctx.from.id);
      if (!(await isChannelMember(userId))) { await ctx.answerCbQuery('⚠️ Channel မ Join ရသေးပါ', { show_alert: true }); return; }
      await ctx.deleteMessage().catch(() => {});
      await ctx.answerCbQuery('✅ Channel Join ပြီး!');
      const parts = data.split('_'), rawRef = parts.slice(3).join('_'), startParam = rawRef || '';
      const tgUser = ctx.from, chatId = userId;
      try {
        let user = await User.findOne({ telegramId: chatId });
        if (!user) {
          user = new User({ telegramId: chatId, firstName: tgUser.first_name||'', lastName: tgUser.last_name||'', username: tgUser.username||'', referralCode: `ref_${chatId}` });
          if (startParam) {
            const cleanRefId = startParam.replace('ref_', '');
            if (cleanRefId && cleanRefId !== chatId) {
              const referrer = await User.findOne({ telegramId: cleanRefId });
              if (referrer && !referrer.isBanned) {
                await User.findByIdAndUpdate(referrer._id, { $inc: { balance: REFERRAL_BONUS, totalEarned: REFERRAL_BONUS, referrals: 1 } });
                user.referredBy = cleanRefId;
                await sendTg(cleanRefId, `🎉 မိတ်ဆွေသစ် ရောက်လာပြီ!\nBonus <b>${REFERRAL_BONUS.toLocaleString()} Ks</b>`);
              }
            }
          }
          await user.save();
        } else {
          await User.findByIdAndUpdate(user._id, { firstName: tgUser.first_name||user.firstName, lastName: tgUser.last_name||user.lastName, username: tgUser.username||user.username, lastSeen: new Date(), isBlocked: false });
        }
        if (user.isBanned) return ctx.reply('🚫 Account ပိတ်ထားပါသည်');
        await ctx.reply(`👋 မင်္ဂလာပါ ${esc(tgUser.first_name)}\nKBZPay Mini App မှ ကြိုဆိုပါသည် 🎉`,
          { parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '💰 App ဖွင့်မည်', web_app: { url: FRONTEND_URL } }]] } });
      } catch (e) { console.error('check_join error:', e.message); }
      return;
    }

    if (adminId !== ADMIN_ID) return ctx.answerCbQuery('⛔ Unauthorized');

    if (data.startsWith('reply_')) {
      pendingReplies[ADMIN_ID] = data.replace('reply_','');
      await ctx.answerCbQuery('📝 Type reply');
      return ctx.reply(`✏️ Reply for <code>${pendingReplies[ADMIN_ID]}</code>:`, { parse_mode: 'HTML' });
    }
    if (data.startsWith('wd_approve_')) {
      const wd = await Withdrawal.findById(data.replace('wd_approve_','')).populate('user').catch(()=>null);
      if (!wd || wd.status !== 'pending') return ctx.answerCbQuery('⚠️ Already processed');
      wd.status = 'approved'; wd.reviewedAt = new Date(); await wd.save();
      await User.findByIdAndUpdate(wd.user._id, { $inc: { totalWithdrawn: wd.netAmount } });
      await ctx.answerCbQuery('✅ Approved!');
      await ctx.editMessageReplyMarkup({ inline_keyboard: [] }).catch(()=>{});
      await sendTg(wd.telegramId, `✅ <b>ငွေထုတ်ယူမှု အတည်ပြုပြီး!</b>\n💰 ${wd.netAmount.toLocaleString()} Ks ပေးပို့မည်`);
      return ctx.reply(`✅ Approved ${wd.netAmount.toLocaleString()} Ks`, { parse_mode: 'HTML' });
    }
    if (data.startsWith('wd_reject_')) {
      pendingRejections[ADMIN_ID] = data.replace('wd_reject_','');
      await ctx.answerCbQuery('✏️ Send reason');
      await ctx.editMessageReplyMarkup({ inline_keyboard: [] }).catch(()=>{});
      return ctx.reply(`📝 ငြင်းပယ်ရမည့် အကြောင်းပြချက် ရေးပါ\nWD: <code>${pendingRejections[ADMIN_ID]}</code>`, { parse_mode: 'HTML' });
    }
    ctx.answerCbQuery();
  });

  bot.launch({ dropPendingUpdates: true })
    .then(() => console.log('🤖 Bot started'))
    .catch(e => console.error('Bot launch error:', e.message));

  process.once('SIGINT',  () => bot.stop('SIGINT'));
  process.once('SIGTERM', () => bot.stop('SIGTERM'));
}

// ═══════════════════════════════════════════════════════════════
//  MONGOOSE CONNECTION
// ═══════════════════════════════════════════════════════════════
let isConnected = false;
async function connectDB() {
  if (isConnected) return;
  try {
    await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000, heartbeatFrequencyMS: 30000 });
    isConnected = true;
    console.log('✅ MongoDB connected');
  } catch {
    console.error('❌ MongoDB connection failed — retrying in 5s');
    setTimeout(connectDB, 5000);
  }
}
mongoose.connection.on('disconnected', () => { isConnected = false; setTimeout(connectDB, 3000); });
mongoose.connection.on('reconnected',  () => { isConnected = true; });

(async () => {
  await connectDB();
  initBot();
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
})();
