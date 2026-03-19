require('dotenv').config();

const express    = require('express');
const mongoose   = require('mongoose');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const multer     = require('multer');
const { Telegraf } = require('telegraf');
const { message }  = require('telegraf/filters');

// ═══════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════
const PORT           = process.env.PORT           || 5000;
const ADMIN_ID       = process.env.ADMIN_CHAT_ID;
const ADMIN_SECRET   = process.env.ADMIN_SECRET   || 'changeme_admin_secret';
const MIN_WITHDRAW   = Number(process.env.MIN_WITHDRAW)   || 100000;
const SERVICE_FEE    = Number(process.env.SERVICE_FEE)    || 5000;
const REFERRAL_BONUS = Number(process.env.REFERRAL_BONUS) || 5000;
const PAYMENT_PHONE  = process.env.PAYMENT_PHONE  || '09702310926';
const PAYMENT_NAME   = process.env.PAYMENT_NAME   || 'Daw Mi Thaung';
const BOT_USERNAME   = process.env.BOT_USERNAME   || 'YourBotUsername';
const FRONTEND_URL   = 'https://kbzpayfrontend.vercel.app';

// ═══════════════════════════════════════════════════
//  MULTER — Memory storage (Cloudinary မသုံးပါ)
//  Buffer ကို Telegram Bot မှတဆင့် Admin ဆီ တိုက်ရိုက်ပို့
// ═══════════════════════════════════════════════════
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const OK = ['image/jpeg','image/jpg','image/png','image/webp','image/gif'];
    if (OK.includes(file.mimetype)) cb(null, true);
    else cb(new Error(`ပုံဖိုင်သာ တင်ခွင့်ရှိသည် (JPG/PNG/WEBP) — ရရှိသောဖိုင်: ${file.mimetype}`), false);
  },
});

const handleMulterError = (err, req, res, next) => {
  if (!err) return next();
  if (err.code === 'LIMIT_FILE_SIZE')
    return res.status(400).json({ success: false, message: 'ပုံဖိုင် 10MB ထက်ကြီးနေသည်' });
  if (err.code === 'LIMIT_UNEXPECTED_FILE')
    return res.status(400).json({ success: false, message: `"screenshot" field name သုံးပါ (received: ${err.field})` });
  if (err.message?.includes('ပုံဖိုင်သာ'))
    return res.status(400).json({ success: false, message: err.message });
  next(err);
};

// ═══════════════════════════════════════════════════
//  MONGOOSE MODELS
// ═══════════════════════════════════════════════════
const userSchema = new mongoose.Schema({
  telegramId:     { type: String, required: true, unique: true, index: true },
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
  banReason:      { type: String, default: '' },
  isAdmin:        { type: Boolean, default: false },
  lastSeen:       { type: Date, default: Date.now },
}, { timestamps: true });
userSchema.virtual('displayName').get(function () {
  return [this.firstName, this.lastName].filter(Boolean).join(' ') || this.username || `User ${this.telegramId}`;
});
userSchema.set('toJSON', { virtuals: true });
const User = mongoose.model('User', userSchema);

// Withdrawal — telegramPhotoFileId သိမ်း (Cloudinary မသုံးပါ)
const withdrawalSchema = new mongoose.Schema({
  user:                { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  telegramId:          { type: String, required: true, index: true },
  amount:              { type: Number, required: true },
  fee:                 { type: Number, default: 5000 },
  netAmount:           { type: Number, required: true },
  telegramPhotoFileId: { type: String, default: '' },
  status:              { type: String, enum: ['pending','approved','rejected'], default: 'pending', index: true },
  rejectionReason:     { type: String, default: '' },
  adminNote:           { type: String, default: '' },
  reviewedAt:          { type: Date },
}, { timestamps: true });
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

const supportSchema = new mongoose.Schema({
  telegramId:  { type: String, required: true, index: true },
  displayName: { type: String, default: '' },
  text:        { type: String, required: true },
  direction:   { type: String, enum: ['user_to_admin','admin_to_user'], required: true },
  isRead:      { type: Boolean, default: false },
}, { timestamps: true });
const SupportMsg = mongoose.model('SupportMessage', supportSchema);

// ═══════════════════════════════════════════════════
//  EXPRESS
// ═══════════════════════════════════════════════════
const app = express();
app.use(helmet({ crossOriginResourcePolicy: false }));

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
    return cb(new Error(`CORS blocked: ${origin}`));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','x-telegram-id','x-admin-secret','Authorization'],
  credentials: true,
  optionsSuccessStatus: 200,
};
app.use(cors(corsOpts));
app.options('*', cors(corsOpts));

app.use(rateLimit({ windowMs: 60000, max: 90, standardHeaders: true, legacyHeaders: false, message: { success: false, message: 'Too many requests' } }));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// Auth
const requireUser = async (req, res, next) => {
  const tid = req.headers['x-telegram-id'];
  if (!tid) return res.status(401).json({ success: false, message: 'Missing x-telegram-id header' });
  const u = await User.findOne({ telegramId: tid }).catch(() => null);
  if (!u) return res.status(404).json({ success: false, message: 'User not found. Please start the bot first.' });
  if (u.isBanned) return res.status(403).json({ success: false, message: `🚫 Account banned: ${u.banReason}` });
  req.user = u; next();
};
const requireAdmin = (req, res, next) => {
  const s = req.headers['x-admin-secret'];
  if (!s || s !== ADMIN_SECRET) return res.status(403).json({ success: false, message: 'Forbidden' });
  next();
};

// Bot send helpers
const sendTg = (chatId, text, extra = {}) => {
  if (!bot) return Promise.resolve(null);
  return bot.telegram.sendMessage(String(chatId), text, { parse_mode: 'HTML', ...extra })
    .catch(e => { console.warn(`sendTg(${chatId}) failed:`, e.message); return null; });
};
const sendTgPhoto = (chatId, buffer, filename, caption, extra = {}) => {
  if (!bot) return Promise.resolve(null);
  return bot.telegram.sendPhoto(String(chatId),
    { source: buffer, filename: filename || 'screenshot.jpg' },
    { caption, parse_mode: 'HTML', ...extra }
  ).catch(e => { console.warn(`sendTgPhoto(${chatId}) failed:`, e.message); return null; });
};

// ═══════════════════════════════════════════════════
//  PUBLIC ROUTES
// ═══════════════════════════════════════════════════
app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'KBZPay Backend', time: new Date().toISOString() }));

app.get('/api/config', (_req, res) => res.json({
  success: true,
  data: { paymentPhone: PAYMENT_PHONE, paymentName: PAYMENT_NAME, minWithdraw: MIN_WITHDRAW, serviceFee: SERVICE_FEE, referralBonus: REFERRAL_BONUS },
}));

app.post('/api/users/me', async (req, res) => {
  try {
    const { telegramId, firstName, lastName, username, referralCode } = req.body;
    if (!telegramId) return res.status(400).json({ success: false, message: 'telegramId required' });
    let user = await User.findOne({ telegramId });
    if (!user) {
      const myCode = `ref_${telegramId}`;
      user = await User.create({ telegramId, firstName, lastName, username, referralCode: myCode });
      if (referralCode && referralCode !== myCode) {
        const refId = referralCode.replace('ref_', '');
        const referrer = await User.findOne({ telegramId: refId });
        if (referrer && !referrer.isBanned) {
          await User.findByIdAndUpdate(referrer._id, { $inc: { balance: REFERRAL_BONUS, totalEarned: REFERRAL_BONUS, referrals: 1 } });
          user.referredBy = refId; await user.save();
          await sendTg(refId, `🎉 <b>မိတ်ဆွေ ဝင်ရောက်ပြီ!</b>\n💰 ${REFERRAL_BONUS.toLocaleString()} Ks ထည့်ပေးပြီးပါပြီ`);
        }
      }
    } else {
      await User.findByIdAndUpdate(user._id, { firstName: firstName || user.firstName, lastName: lastName || user.lastName, username: username || user.username, lastSeen: new Date() });
      user = await User.findById(user._id);
    }
    if (user.isBanned) return res.status(403).json({ success: false, message: `🚫 Account banned: ${user.banReason}` });
    return res.json({ success: true, data: {
      telegramId: user.telegramId, displayName: user.displayName, firstName: user.firstName,
      username: user.username, balance: user.balance, referrals: user.referrals,
      totalEarned: user.totalEarned, totalWithdrawn: user.totalWithdrawn,
      referralCode: user.referralCode, referralLink: `https://t.me/${BOT_USERNAME}?start=${user.referralCode}`,
      isAdmin: user.isAdmin,
    }});
  } catch (err) { console.error('/api/users/me:', err); res.status(500).json({ success: false, message: 'Server error' }); }
});

app.get('/api/users/leaderboard', async (_req, res) => {
  try {
    const users = await User.find({ isBanned: false }).sort({ referrals: -1, totalEarned: -1 }).limit(20).select('telegramId firstName lastName username referrals totalEarned');
    res.json({ success: true, data: users.map((u, i) => ({ rank: i+1, name: u.displayName, avatar: u.displayName.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase(), referrals: u.referrals, earned: u.totalEarned })) });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

// ═══════════════════════════════════════════════════
//  WITHDRAWAL SUBMIT
//  Screenshot → memory buffer → Telegram Bot → Admin
// ═══════════════════════════════════════════════════
app.post('/api/withdrawals',
  requireUser,
  (req, res, next) => { upload.single('screenshot')(req, res, err => { if (err) return handleMulterError(err, req, res, next); next(); }); },
  async (req, res) => {
    let balanceDeducted = false, deductAmount = 0;
    try {
      const user      = req.user;
      const rawAmount = req.body?.amount;
      const amount    = parseInt(rawAmount, 10);

      if (!req.file?.buffer)
        return res.status(400).json({ success: false, message: 'Screenshot ပုံတင်ရန် လိုအပ်သည်' });
      if (!rawAmount || isNaN(amount) || amount < MIN_WITHDRAW)
        return res.status(400).json({ success: false, message: `အနည်းဆုံး ${MIN_WITHDRAW.toLocaleString()} Ks ဖြစ်ရမည်` });

      const totalDeduct = amount + SERVICE_FEE;
      if (user.balance < totalDeduct)
        return res.status(400).json({ success: false, message: `လက်ကျန်ငွေ မလုံလောက်ပါ (${amount.toLocaleString()} + ဝန်ဆောင်ခ ${SERVICE_FEE.toLocaleString()} = ${totalDeduct.toLocaleString()} Ks)` });

      const hasPending = await Withdrawal.findOne({ telegramId: user.telegramId, status: 'pending' });
      if (hasPending)
        return res.status(409).json({ success: false, message: 'ကြိုတင်တင်ထားသော ငွေထုတ်မှု ရှိနေသေးပါသည်' });

      // Deduct balance
      deductAmount     = totalDeduct;
      const newBalance = user.balance - totalDeduct;
      await User.findByIdAndUpdate(user._id, { $inc: { balance: -totalDeduct } });
      balanceDeducted  = true;

      // Save record
      let wd;
      try {
        wd = await Withdrawal.create({ user: user._id, telegramId: user.telegramId, amount, fee: SERVICE_FEE, netAmount: amount - SERVICE_FEE });
      } catch (dbErr) {
        await User.findByIdAndUpdate(user._id, { $inc: { balance: deductAmount } }).catch(() => {});
        return res.status(500).json({ success: false, message: 'မှတ်တမ်းသိမ်းရာတွင် error — balance ပြန်ထည့်ပေးပြီးပါပြီ' });
      }

      // Send photo + info to admin
      if (ADMIN_ID && bot) {
        const caption =
          `💸 <b>ငွေထုတ်ယူမှု တောင်းဆိုမှု</b>\n\n` +
          `👤 <b>နာမည်:</b> ${user.displayName}\n` +
          `🔖 <b>Username:</b> @${user.username || 'N/A'}\n` +
          `🆔 <b>Telegram ID:</b> <code>${user.telegramId}</code>\n` +
          `💰 <b>ထုတ်ယူမည့်ငွေ:</b> ${amount.toLocaleString()} Ks\n` +
          `💳 <b>ဝန်ဆောင်ခ:</b> ${SERVICE_FEE.toLocaleString()} Ks\n` +
          `✅ <b>လက်ခံရမည်:</b> ${(amount - SERVICE_FEE).toLocaleString()} Ks\n` +
          `📅 ${new Date().toLocaleString()}`;

        const photoMsg = await sendTgPhoto(
          ADMIN_ID,
          req.file.buffer,
          req.file.originalname || 'screenshot.jpg',
          caption,
          { reply_markup: { inline_keyboard: [[
            { text: '✅ Approve', callback_data: `wd_approve_${wd._id}` },
            { text: '❌ Reject',  callback_data: `wd_reject_${wd._id}`  },
          ]] }}
        );
        // Cache Telegram file_id
        if (photoMsg?.photo) {
          const fileId = photoMsg.photo[photoMsg.photo.length - 1].file_id;
          await Withdrawal.findByIdAndUpdate(wd._id, { telegramPhotoFileId: fileId }).catch(() => {});
        }
      }

      return res.status(201).json({
        success: true,
        message: 'ငွေထုတ်ယူမှု တင်ပြီးပါပြီ။ Admin မှ စစ်ဆေးပြီးနောက် Telegram မှ အကြောင်းကြားပါမည်။',
        data: { id: wd._id, amount: wd.amount, fee: wd.fee, netAmount: wd.netAmount, status: wd.status, newBalance },
      });
    } catch (err) {
      console.error('Withdrawal error:', err.message);
      if (balanceDeducted && req.user)
        await User.findByIdAndUpdate(req.user._id, { $inc: { balance: deductAmount } }).catch(() => {});
      return res.status(500).json({ success: false, message: err.message || 'Server error' });
    }
  }
);

app.get('/api/withdrawals/mine', requireUser, async (req, res) => {
  try {
    const wds = await Withdrawal.find({ telegramId: req.user.telegramId }).sort({ createdAt: -1 }).limit(20);
    res.json({ success: true, data: wds });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

app.get('/api/withdrawals/recent', async (_req, res) => {
  try {
    const wds = await Withdrawal.find({ status: 'approved' }).sort({ updatedAt: -1 }).limit(20).populate('user','firstName lastName username');
    res.json({ success: true, data: wds.map(w => ({ id: w._id, name: w.user?.displayName || 'User', avatar: (w.user?.displayName||'U').split(' ').map(x=>x[0]).join('').slice(0,2).toUpperCase(), net: w.netAmount, date: w.updatedAt.toISOString().split('T')[0] })) });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

// ═══════════════════════════════════════════════════
//  ADMIN ROUTES
// ═══════════════════════════════════════════════════
const adminRouter = express.Router();
adminRouter.use(requireAdmin);

adminRouter.get('/stats', async (_req, res) => {
  try {
    const [total, banned, pending, approved, rejected, balRes] = await Promise.all([
      User.countDocuments(), User.countDocuments({ isBanned: true }),
      Withdrawal.countDocuments({ status: 'pending' }), Withdrawal.countDocuments({ status: 'approved' }),
      Withdrawal.countDocuments({ status: 'rejected' }), User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' } } }]),
    ]);
    res.json({ success: true, data: { total, banned, withdrawals: { pending, approved, rejected }, totalBalance: balRes[0]?.total || 0 } });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.get('/users', async (req, res) => {
  try {
    const { page=1, limit=30, search, banned } = req.query;
    const f = {};
    if (search) f.$or = [{ firstName: new RegExp(search,'i') },{ username: new RegExp(search,'i') },{ telegramId: search }];
    if (banned !== undefined) f.isBanned = banned === 'true';
    const [users, count] = await Promise.all([User.find(f).sort({ createdAt:-1 }).skip((page-1)*limit).limit(parseInt(limit)), User.countDocuments(f)]);
    res.json({ success: true, data: users, total: count });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.post('/users/:tid/ban', async (req, res) => {
  try {
    const { reason } = req.body;
    const u = await User.findOneAndUpdate({ telegramId: req.params.tid }, { isBanned: true, banReason: reason||'Violated terms' }, { new: true });
    if (!u) return res.status(404).json({ success: false, message: 'User not found' });
    await sendTg(u.telegramId, `🚫 <b>Account ပိတ်ထားပါသည်</b>\nအကြောင်း: ${reason||'Violated terms'}`);
    res.json({ success: true, data: u });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.post('/users/:tid/unban', async (req, res) => {
  try {
    const u = await User.findOneAndUpdate({ telegramId: req.params.tid }, { isBanned: false, banReason: '' }, { new: true });
    if (!u) return res.status(404).json({ success: false, message: 'User not found' });
    await sendTg(u.telegramId, `✅ <b>Account ပြန်ဖွင့်ပေးပြီးပါပြီ</b>`);
    res.json({ success: true, data: u });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.patch('/users/:tid/balance', async (req, res) => {
  try {
    const { action, amount, note } = req.body;
    if (!['add','subtract'].includes(action)) return res.status(400).json({ success: false, message: 'action: add|subtract' });
    const u = await User.findOne({ telegramId: req.params.tid });
    if (!u) return res.status(404).json({ success: false, message: 'User not found' });
    const delta = action === 'add' ? Math.abs(amount) : -Math.abs(amount);
    if (action === 'subtract' && u.balance < Math.abs(amount)) return res.status(400).json({ success: false, message: 'Insufficient balance' });
    const inc = { balance: delta }; if (action === 'add') inc.totalEarned = Math.abs(amount);
    const updated = await User.findByIdAndUpdate(u._id, { $inc: inc }, { new: true });
    await sendTg(u.telegramId, `💰 <b>Admin မှ ${Math.abs(amount).toLocaleString()} Ks ${action==='add'?'ထည့်':'နုတ်'}ပေးပါပြီ</b>\nလက်ကျန်: ${updated.balance.toLocaleString()} Ks${note?`\nမှတ်ချက်: ${note}`:''}`);
    res.json({ success: true, data: updated });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.patch('/users/:tid/referrals', async (req, res) => {
  try {
    const { count } = req.body;
    const bonus = count * REFERRAL_BONUS;
    const u = await User.findOneAndUpdate({ telegramId: req.params.tid }, { $inc: { referrals: count, balance: bonus, totalEarned: bonus } }, { new: true });
    if (!u) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, data: u });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.get('/withdrawals', async (req, res) => {
  try {
    const { status, page=1, limit=20 } = req.query;
    const f = {}; if (status) f.status = status;
    const [wds, total] = await Promise.all([
      Withdrawal.find(f).sort({ createdAt:-1 }).skip((page-1)*limit).limit(parseInt(limit)).populate('user','firstName lastName username telegramId'),
      Withdrawal.countDocuments(f),
    ]);
    res.json({ success: true, data: wds, total });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.post('/withdrawals/:id/approve', async (req, res) => {
  try {
    const wd = await Withdrawal.findById(req.params.id).populate('user');
    if (!wd) return res.status(404).json({ success: false, message: 'Not found' });
    if (wd.status !== 'pending') return res.status(409).json({ success: false, message: 'Already processed' });
    wd.status = 'approved'; wd.reviewedAt = new Date(); wd.adminNote = req.body.note || '';
    await wd.save();
    await User.findByIdAndUpdate(wd.user._id, { $inc: { totalWithdrawn: wd.netAmount } });
    await sendTg(wd.telegramId, `✅ <b>ငွေထုတ်ယူမှု အတည်ပြုပြီးပါပြီ!</b>\n💰 ${wd.netAmount.toLocaleString()} Ks ကို မကြာမီ ပေးပို့ပါမည်`);
    res.json({ success: true, data: wd });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.post('/withdrawals/:id/reject', async (req, res) => {
  try {
    const { reason } = req.body;
    if (!reason) return res.status(400).json({ success: false, message: 'reason required' });
    const wd = await Withdrawal.findById(req.params.id).populate('user');
    if (!wd) return res.status(404).json({ success: false, message: 'Not found' });
    if (wd.status !== 'pending') return res.status(409).json({ success: false, message: 'Already processed' });
    wd.status = 'rejected'; wd.rejectionReason = reason; wd.reviewedAt = new Date();
    await wd.save();
    await User.findByIdAndUpdate(wd.user._id, { $inc: { balance: wd.amount + wd.fee } });
    await sendTg(wd.telegramId, `❌ <b>ငွေထုတ်ယူမှု ငြင်းပယ်ပါသည်</b>\n\nအကြောင်းပြချက်: ${reason}\n\n💰 ${(wd.amount+wd.fee).toLocaleString()} Ks ပြန်ထည့်ပေးပြီးပါပြီ`);
    res.json({ success: true, data: wd });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.post('/broadcast', async (req, res) => {
  try {
    const { message: msg } = req.body;
    if (!msg) return res.status(400).json({ success: false, message: 'message required' });
    const users = await User.find({ isBanned: false }).select('telegramId');
    let sent=0, failed=0;
    for (const u of users) { const ok = await sendTg(u.telegramId, `📢 <b>ကြေညာချက်</b>\n\n${msg}`); ok ? sent++ : failed++; await new Promise(r=>setTimeout(r,60)); }
    res.json({ success: true, data: { sent, failed, total: users.length } });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

app.use('/api/admin', adminRouter);
app.use((_req, res) => res.status(404).json({ success: false, message: 'Route not found' }));
app.use((err, _req, res, _next) => {
  console.error('Global error:', err.code||'', err.message);
  if (err.code === 'LIMIT_FILE_SIZE')       return res.status(400).json({ success: false, message: 'ပုံဖိုင် 10MB ထက်ကြီးနေသည်' });
  if (err.code === 'LIMIT_UNEXPECTED_FILE') return res.status(400).json({ success: false, message: `"screenshot" field name သုံးပါ` });
  if (err.message?.startsWith('CORS'))      return res.status(403).json({ success: false, message: err.message });
  if (err.name === 'ValidationError')       return res.status(400).json({ success: false, message: err.message });
  res.status(500).json({ success: false, message: err.message || 'Internal server error' });
});

// ═══════════════════════════════════════════════════
//  TELEGRAF BOT
// ═══════════════════════════════════════════════════
let bot = null;

function initBot() {
  if (!process.env.BOT_TOKEN) { console.warn('⚠️  BOT_TOKEN not set — bot disabled'); return; }
  bot = new Telegraf(process.env.BOT_TOKEN);

  const pendingReplies    = {};
  const pendingRejections = {};

  bot.start(async ctx => {
    const tgUser=ctx.from, chatId=String(ctx.chat.id), startParam=ctx.startPayload||'';
    try {
      let user = await User.findOne({ telegramId: chatId });
      if (!user) {
        const myCode = `ref_${chatId}`;
        user = await User.create({ telegramId: chatId, firstName: tgUser.first_name||'', lastName: tgUser.last_name||'', username: tgUser.username||'', referralCode: myCode });
        if (startParam.startsWith('ref_') && startParam !== myCode) {
          const refId=startParam.replace('ref_',''), referrer=await User.findOne({ telegramId: refId });
          if (referrer && !referrer.isBanned) {
            await User.findByIdAndUpdate(referrer._id, { $inc: { balance: REFERRAL_BONUS, totalEarned: REFERRAL_BONUS, referrals: 1 } });
            user.referredBy=refId; await user.save();
            await sendTg(refId, `🎉 <b>မိတ်ဆွေ ဝင်ရောက်ပြီ!</b>\n💰 ${REFERRAL_BONUS.toLocaleString()} Ks ထည့်ပေးပြီးပါပြီ`);
          }
        }
      } else {
        await User.findByIdAndUpdate(user._id, { firstName: tgUser.first_name||user.firstName, lastName: tgUser.last_name||user.lastName, username: tgUser.username||user.username, lastSeen: new Date() });
      }
      if (user.isBanned) return ctx.reply(`🚫 Account ပိတ်ထားပါသည်\nအကြောင်း: ${user.banReason}`);
      await ctx.reply(`👋 မင်္ဂလာပါ ${tgUser.first_name}!\n\nKBZPay Mini App သို့ ကြိုဆိုပါသည် 🎉`,
        { reply_markup: { inline_keyboard: [[{ text: '💰 App ဖွင့်မည်', web_app: { url: FRONTEND_URL } }]] } });
    } catch(e) { console.error('Bot /start error:', e.message); }
  });

  bot.command('admin', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    ctx.reply(`🛠 <b>Admin Commands</b>\n/ban [id] [reason]\n/unban [id]\n/addmoney [id] [amount]\n/reducemoney [id] [amount]\n/addrefs [id] [count]\n/userinfo [id]\n/stats`, { parse_mode:'HTML' });
  });

  bot.command('ban', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const p=ctx.message.text.split(' '), tid=p[1], reason=p.slice(2).join(' ')||'Violated terms';
    if (!tid) return ctx.reply('Usage: /ban [id] [reason]');
    const u=await User.findOneAndUpdate({telegramId:tid},{isBanned:true,banReason:reason},{new:true}).catch(()=>null);
    if (!u) return ctx.reply(`❌ User ${tid} not found`);
    await sendTg(tid, `🚫 Account ပိတ်ထားပါသည်\nအကြောင်း: ${reason}`);
    ctx.reply(`✅ Banned: ${u.displayName}`);
  });

  bot.command('unban', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const tid=ctx.message.text.split(' ')[1];
    if (!tid) return ctx.reply('Usage: /unban [id]');
    const u=await User.findOneAndUpdate({telegramId:tid},{isBanned:false,banReason:''},{new:true}).catch(()=>null);
    if (!u) return ctx.reply(`❌ Not found`);
    await sendTg(tid, `✅ Account ပြန်ဖွင့်ပေးပြီးပါပြီ`);
    ctx.reply(`✅ Unbanned: ${u.displayName}`);
  });

  bot.command('addmoney', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [,tid,amtStr]=ctx.message.text.split(' ');
    if (!tid||!amtStr) return ctx.reply('Usage: /addmoney [id] [amount]');
    const amt=parseInt(amtStr);
    const u=await User.findOneAndUpdate({telegramId:tid},{$inc:{balance:amt,totalEarned:amt}},{new:true}).catch(()=>null);
    if (!u) return ctx.reply('❌ Not found');
    await sendTg(tid, `💰 Admin မှ ${amt.toLocaleString()} Ks ထည့်ပေးပါပြီ\nလက်ကျန်: ${u.balance.toLocaleString()} Ks`);
    ctx.reply(`✅ Added ${amt.toLocaleString()} Ks → ${u.displayName} (Balance: ${u.balance.toLocaleString()} Ks)`);
  });

  bot.command('reducemoney', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [,tid,amtStr]=ctx.message.text.split(' ');
    if (!tid||!amtStr) return ctx.reply('Usage: /reducemoney [id] [amount]');
    const amt=parseInt(amtStr), u=await User.findOne({telegramId:tid}).catch(()=>null);
    if (!u) return ctx.reply('❌ Not found');
    if (u.balance<amt) return ctx.reply(`❌ Insufficient (${u.balance.toLocaleString()} Ks)`);
    await User.findByIdAndUpdate(u._id,{$inc:{balance:-amt}});
    ctx.reply(`✅ Reduced ${amt.toLocaleString()} Ks from ${u.displayName}`);
  });

  bot.command('addrefs', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [,tid,countStr]=ctx.message.text.split(' ');
    if (!tid||!countStr) return ctx.reply('Usage: /addrefs [id] [count]');
    const count=parseInt(countStr), bonus=count*REFERRAL_BONUS;
    const u=await User.findOneAndUpdate({telegramId:tid},{$inc:{referrals:count,balance:bonus,totalEarned:bonus}},{new:true}).catch(()=>null);
    if (!u) return ctx.reply('❌ Not found');
    ctx.reply(`✅ Added ${count} refs (+${bonus.toLocaleString()} Ks) → ${u.displayName}`);
  });

  bot.command('userinfo', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const tid=ctx.message.text.split(' ')[1];
    if (!tid) return ctx.reply('Usage: /userinfo [id]');
    const u=await User.findOne({telegramId:tid}).catch(()=>null);
    if (!u) return ctx.reply('❌ Not found');
    ctx.reply(`👤 <b>User Info</b>\nName: ${u.displayName}\nUsername: @${u.username||'N/A'}\nID: <code>${u.telegramId}</code>\nBalance: ${u.balance.toLocaleString()} Ks\nReferrals: ${u.referrals}\nTotal Earned: ${u.totalEarned.toLocaleString()} Ks\nBanned: ${u.isBanned?'🚫 Yes':'✅ No'}`, { parse_mode:'HTML' });
  });

  bot.command('stats', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [total,banned,pending]=await Promise.all([User.countDocuments(),User.countDocuments({isBanned:true}),Withdrawal.countDocuments({status:'pending'})]);
    const bal=await User.aggregate([{$group:{_id:null,total:{$sum:'$balance'}}}]);
    ctx.reply(`📊 <b>App Stats</b>\n👥 Users: ${total}\n🚫 Banned: ${banned}\n⏳ Pending WD: ${pending}\n💰 Total Balance: ${(bal[0]?.total||0).toLocaleString()} Ks`, { parse_mode:'HTML' });
  });

  // Support chat: user → admin
  bot.on(message('text'), async ctx => {
    if (ctx.message.text.startsWith('/')) return;
    const chatId=String(ctx.chat.id);

    if (chatId === ADMIN_ID) {
      // Admin replying support
      if (pendingReplies[ADMIN_ID]) {
        const targetId=pendingReplies[ADMIN_ID]; delete pendingReplies[ADMIN_ID];
        await sendTg(targetId, `📩 <b>Admin ထံမှ ပြန်စာ:</b>\n\n${ctx.message.text}`);
        await SupportMsg.create({ telegramId: targetId, displayName: 'Admin', text: ctx.message.text, direction: 'admin_to_user' }).catch(()=>{});
        return ctx.reply(`✅ Reply sent to ${targetId}`);
      }
      // Admin sending rejection reason
      if (pendingRejections[ADMIN_ID]) {
        const wdId=pendingRejections[ADMIN_ID]; delete pendingRejections[ADMIN_ID];
        const reason=ctx.message.text;
        const wd=await Withdrawal.findById(wdId).populate('user').catch(()=>null);
        if (wd && wd.status==='pending') {
          wd.status='rejected'; wd.rejectionReason=reason; wd.reviewedAt=new Date(); await wd.save();
          await User.findByIdAndUpdate(wd.user._id, { $inc: { balance: wd.amount+wd.fee } });
          await sendTg(wd.telegramId,
            `❌ <b>ငွေထုတ်ယူမှု ငြင်းပယ်ပါသည်</b>\n\nအကြောင်းပြချက်: ${reason}\n\n💰 ${(wd.amount+wd.fee).toLocaleString()} Ks ပြန်ထည့်ပေးပြီးပါပြီ`
          );
          return ctx.reply(`✅ Rejected — ${wd.telegramId} balance refunded`);
        }
        return ctx.reply('❌ Withdrawal not found or already processed');
      }
      return;
    }

    const u=await User.findOne({ telegramId: chatId }).catch(()=>null);
    if (!u || u.isBanned) return;
    await SupportMsg.create({ telegramId: chatId, displayName: u.displayName, text: ctx.message.text, direction: 'user_to_admin' }).catch(()=>{});
    if (ADMIN_ID) {
      await sendTg(ADMIN_ID,
        `📨 <b>Support Message</b>\n👤 ${u.displayName} (@${u.username||'N/A'})\n🆔 <code>${chatId}</code>\n\n💬 ${ctx.message.text}`,
        { reply_markup: { inline_keyboard: [[{ text: '↩️ Reply', callback_data: `reply_${chatId}` }]] } }
      );
    }
    ctx.reply('✅ မက်ဆေ့ကို Admin ထံ ပေးပို့ပြီးပါပြီ။ မကြာမီ ပြန်လည်ဖြေကြားပါမည်။');
  });

  // Admin inline buttons: Approve / Reject
  bot.on('callback_query', async ctx => {
    const adminId=String(ctx.from.id);
    if (adminId !== ADMIN_ID) return ctx.answerCbQuery('⛔ Unauthorized');
    const data=ctx.callbackQuery.data;

    // Support reply
    if (data.startsWith('reply_')) {
      pendingReplies[ADMIN_ID]=data.replace('reply_','');
      await ctx.answerCbQuery('📝 Type reply now');
      return ctx.reply(`✏️ Type your reply for user <code>${pendingReplies[ADMIN_ID]}</code>:`, { parse_mode:'HTML' });
    }

    // ── APPROVE ──────────────────────────────────────────────────────────────
    if (data.startsWith('wd_approve_')) {
      const wdId=data.replace('wd_approve_','');
      const wd=await Withdrawal.findById(wdId).populate('user').catch(()=>null);
      if (!wd || wd.status!=='pending') return ctx.answerCbQuery('⚠️ Already processed');
      wd.status='approved'; wd.reviewedAt=new Date(); await wd.save();
      await User.findByIdAndUpdate(wd.user._id, { $inc: { totalWithdrawn: wd.netAmount } });
      await ctx.answerCbQuery('✅ Approved!');
      await ctx.editMessageReplyMarkup({ inline_keyboard: [] }).catch(()=>{});
      // Notify user
      await sendTg(wd.telegramId,
        `✅ <b>ငွေထုတ်ယူမှု အတည်ပြုပြီးပါပြီ!</b>\n\n` +
        `💰 <b>${wd.netAmount.toLocaleString()} Ks</b> ကို မကြာမီ ပေးပို့ပါမည်\n` +
        `📅 ${new Date().toLocaleString()}`
      );
      return ctx.reply(
        `✅ <b>Approved!</b>\n👤 ${wd.user?.displayName}\n🆔 ${wd.telegramId}\n💰 ${wd.netAmount.toLocaleString()} Ks`,
        { parse_mode:'HTML' }
      );
    }

    // ── REJECT (step 1: remove buttons, ask for reason) ───────────────────────
    if (data.startsWith('wd_reject_')) {
      pendingRejections[ADMIN_ID]=data.replace('wd_reject_','');
      await ctx.answerCbQuery('✏️ Send rejection reason');
      await ctx.editMessageReplyMarkup({ inline_keyboard: [] }).catch(()=>{});
      return ctx.reply(
        `📝 <b>ငြင်းပယ်ရမည့် အကြောင်းပြချက် ရေးပါ</b>\n` +
        `Withdrawal ID: <code>${pendingRejections[ADMIN_ID]}</code>\n\n` +
        `ဤ message ကို User ဆီ တိုက်ရိုက်ပေးပို့ပါမည်`,
        { parse_mode:'HTML' }
      );
    }

    ctx.answerCbQuery();
  });

  bot.launch({ dropPendingUpdates: true })
    .then(()=>console.log('🤖 Bot started'))
    .catch(e=>console.error('Bot launch error:', e.message));

  process.once('SIGINT',  ()=>bot.stop('SIGINT'));
  process.once('SIGTERM', ()=>bot.stop('SIGTERM'));
}

// ═══════════════════════════════════════════════════
//  STARTUP
// ═══════════════════════════════════════════════════
(async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
    console.log('✅ MongoDB connected');
    initBot();
    app.listen(PORT, ()=>console.log(`🚀 Server running on port ${PORT}`));
  } catch (err) {
    console.error('❌ Startup failed:', err.message);
    process.exit(1);
  }
})();
