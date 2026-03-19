require('dotenv').config();

const express      = require('express');
const mongoose     = require('mongoose');
const cors         = require('cors');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const multer       = require('multer');
const { v2: cloudinary } = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const { Telegraf }  = require('telegraf');
const { message }   = require('telegraf/filters');

// ═══════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════
const PORT           = process.env.PORT          || 5000;
const ADMIN_ID       = process.env.ADMIN_CHAT_ID;
const ADMIN_SECRET   = process.env.ADMIN_SECRET  || 'changeme_admin_secret';
const MIN_WITHDRAW   = Number(process.env.MIN_WITHDRAW)   || 100000;
const SERVICE_FEE    = Number(process.env.SERVICE_FEE)    || 5000;
const REFERRAL_BONUS = Number(process.env.REFERRAL_BONUS) || 5000;
const PAYMENT_PHONE  = process.env.PAYMENT_PHONE || '09702310926';
const PAYMENT_NAME   = process.env.PAYMENT_NAME  || 'Daw Mi Thaung';
const BOT_USERNAME   = process.env.BOT_USERNAME  || 'YourBotUsername';
const FRONTEND_URL   = 'https://kbzpayfrontend.vercel.app';

// ═══════════════════════════════════════════
//  CLOUDINARY SETUP
// ═══════════════════════════════════════════
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: async (_req, file) => ({
    folder:          'kbzpay_withdrawals',
    allowed_formats: ['jpg','jpeg','png','webp'],
    transformation:  [{ width: 1400, crop: 'limit', quality: 'auto:good' }],
    public_id:       `wd_${Date.now()}_${Math.random().toString(36).slice(2,8)}`,
    resource_type:   'image',
  }),
});

const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024,  // 10 MB max
    files: 1,
  },
  fileFilter: (_req, file, cb) => {
    const ALLOWED_MIME = ['image/jpeg','image/jpg','image/png','image/webp','image/gif'];
    if (ALLOWED_MIME.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`ပုံဖိုင်သာ တင်ခွင့်ရှိသည် (JPG, PNG, WEBP)။ တင်ထားသောဖိုင်: ${file.mimetype}`), false);
    }
  },
});

// Multer error handler middleware — call this after upload middleware
const handleMulterError = (err, req, res, next) => {
  if (!err) return next();
  // Multer-specific errors
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({
      success: false,
      message: 'ပုံဖိုင်သည် 10MB ထက်ကြီးနေသည်။ သေးငယ်သောပုံတင်ပါ။',
    });
  }
  if (err.code === 'LIMIT_FILE_COUNT') {
    return res.status(400).json({ success: false, message: 'ပုံတစ်ပုံသာ တင်ခွင့်ရှိသည်' });
  }
  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json({
      success: false,
      message: `Field name မှားနေသည်။ "screenshot" ဟု သုံးပါ (received: ${err.field})`,
    });
  }
  // Custom fileFilter error
  if (err.message && err.message.includes('ပုံဖိုင်သာ')) {
    return res.status(400).json({ success: false, message: err.message });
  }
  // Cloudinary or other upload errors
  if (err.http_code || err.name === 'Error') {
    console.error('Upload/Cloudinary error:', err);
    return res.status(502).json({
      success: false,
      message: 'ပုံတင်ရာတွင် error ဖြစ်သည်။ နောက်မှ ထပ်ကြိုးစားပါ။',
    });
  }
  // Pass to global error handler
  next(err);
};

// ═══════════════════════════════════════════
//  MONGOOSE MODELS
// ═══════════════════════════════════════════

// User
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
  return [this.firstName, this.lastName].filter(Boolean).join(' ')
    || this.username || `User ${this.telegramId}`;
});
userSchema.set('toJSON', { virtuals: true });
const User = mongoose.model('User', userSchema);

// Withdrawal
const withdrawalSchema = new mongoose.Schema({
  user:               { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  telegramId:         { type: String, required: true, index: true },
  amount:             { type: Number, required: true },
  fee:                { type: Number, default: 5000 },
  netAmount:          { type: Number, required: true },
  screenshotUrl:      { type: String, required: true },
  screenshotPublicId: { type: String },
  status:             { type: String, enum: ['pending','approved','rejected'], default: 'pending', index: true },
  rejectionReason:    { type: String, default: '' },
  adminNote:          { type: String, default: '' },
  reviewedBy:         { type: String, default: '' },
  reviewedAt:         { type: Date },
}, { timestamps: true });
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Support Messages
const supportSchema = new mongoose.Schema({
  telegramId:  { type: String, required: true, index: true },
  displayName: { type: String, default: '' },
  text:        { type: String, required: true },
  direction:   { type: String, enum: ['user_to_admin','admin_to_user'], required: true },
  isRead:      { type: Boolean, default: false },
}, { timestamps: true });
const SupportMsg = mongoose.model('SupportMessage', supportSchema);

// ═══════════════════════════════════════════
//  EXPRESS APP
// ═══════════════════════════════════════════
const app = express();

app.use(helmet({ crossOriginResourcePolicy: false }));

// ── CORS — Fix for FormData/file upload from Vercel frontend ─────────────────
const ALLOWED_ORIGINS = [
  FRONTEND_URL,
  'https://kbzpayfrontend.vercel.app',
  'https://kbzpaybackend.onrender.com',
  'http://localhost:3000',
  'http://localhost:5000',
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, Telegram WebApp)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    // Allow any vercel.app preview URLs
    if (origin.endsWith('.vercel.app')) return callback(null, true);
    return callback(new Error(`CORS blocked: ${origin}`));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'x-telegram-id',
    'x-admin-secret',
    'Authorization',
  ],
  credentials: true,
  optionsSuccessStatus: 200, // Some browsers (IE11) choke on 204
}));

// Handle preflight OPTIONS for all routes (important for FormData uploads)
app.options('*', cors());
app.use(rateLimit({
  windowMs: 60 * 1000, max: 90,
  standardHeaders: true, legacyHeaders: false,
  message: { success: false, message: 'Too many requests' },
}));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Middleware ────────────────────────────────────────────────────────────────
const requireUser = async (req, res, next) => {
  const tid = req.headers['x-telegram-id'];
  if (!tid) return res.status(401).json({ success: false, message: 'Missing x-telegram-id header' });
  const u = await User.findOne({ telegramId: tid }).catch(() => null);
  if (!u) return res.status(404).json({ success: false, message: 'User not found. Please start the bot first.' });
  if (u.isBanned) return res.status(403).json({ success: false, message: `🚫 Account banned: ${u.banReason}` });
  req.user = u;
  next();
};

const requireAdmin = (req, res, next) => {
  const s = req.headers['x-admin-secret'];
  if (!s || s !== ADMIN_SECRET) return res.status(403).json({ success: false, message: 'Forbidden' });
  next();
};

// Safe Telegram sender
const sendTg = (chatId, text, extra = {}) => {
  if (!bot) return Promise.resolve();
  return bot.telegram.sendMessage(chatId, text, { parse_mode: 'HTML', ...extra })
    .catch(e => console.warn(`Telegram send to ${chatId} failed:`, e.message));
};

// ═══════════════════════════════════════════
//  PUBLIC ROUTES
// ═══════════════════════════════════════════

// Health check
app.get('/health', (_req, res) => res.json({
  status: 'ok',
  service: 'KBZPay Backend',
  url: 'https://kbzpaybackend.onrender.com',
  time: new Date().toISOString(),
}));

// App config
app.get('/api/config', (_req, res) => res.json({
  success: true,
  data: {
    paymentPhone:  PAYMENT_PHONE,
    paymentName:   PAYMENT_NAME,
    minWithdraw:   MIN_WITHDRAW,
    serviceFee:    SERVICE_FEE,
    referralBonus: REFERRAL_BONUS,
    frontendUrl:   FRONTEND_URL,
  },
}));

// ── Users: init/login ─────────────────────────────────────────────────────────
app.post('/api/users/me', async (req, res) => {
  try {
    const { telegramId, firstName, lastName, username, referralCode } = req.body;
    if (!telegramId) return res.status(400).json({ success: false, message: 'telegramId required' });

    let user = await User.findOne({ telegramId });

    if (!user) {
      const myCode = `ref_${telegramId}`;
      user = await User.create({ telegramId, firstName, lastName, username, referralCode: myCode });

      // Process referral bonus
      if (referralCode && referralCode !== myCode) {
        const refId = referralCode.replace('ref_', '');
        const referrer = await User.findOne({ telegramId: refId });
        if (referrer && !referrer.isBanned) {
          await User.findByIdAndUpdate(referrer._id, {
            $inc: { balance: REFERRAL_BONUS, totalEarned: REFERRAL_BONUS, referrals: 1 },
          });
          user.referredBy = refId;
          await user.save();
          await sendTg(refId,
            `🎉 <b>မိတ်ဆွေ ဝင်ရောက်ပြီ!</b>\n💰 ${REFERRAL_BONUS.toLocaleString()} Ks ထည့်ပေးပြီးပါပြီ`
          );
        }
      }
    } else {
      await User.findByIdAndUpdate(user._id, {
        firstName: firstName || user.firstName,
        lastName:  lastName  || user.lastName,
        username:  username  || user.username,
        lastSeen:  new Date(),
      });
      user = await User.findById(user._id);
    }

    if (user.isBanned) {
      return res.status(403).json({ success: false, message: `🚫 Account banned: ${user.banReason}` });
    }

    return res.json({
      success: true,
      data: {
        telegramId:     user.telegramId,
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
  } catch (err) {
    console.error('/api/users/me error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── Leaderboard ───────────────────────────────────────────────────────────────
app.get('/api/users/leaderboard', async (_req, res) => {
  try {
    const users = await User.find({ isBanned: false })
      .sort({ referrals: -1, totalEarned: -1 })
      .limit(20)
      .select('telegramId firstName lastName username referrals totalEarned');

    const data = users.map((u, i) => ({
      rank:      i + 1,
      name:      u.displayName,
      avatar:    u.displayName.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase(),
      referrals: u.referrals,
      earned:    u.totalEarned,
    }));

    res.json({ success: true, data });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ── Withdrawal: submit ────────────────────────────────────────────────────────
app.post('/api/withdrawals',
  requireUser,
  // Wrap multer to intercept upload errors before they hit global handler
  (req, res, next) => {
    upload.single('screenshot')(req, res, (err) => {
      if (err) return handleMulterError(err, req, res, next);
      next();
    });
  },
  async (req, res) => {
    let balanceDeducted = false;
    let deductAmount    = 0;

    try {
      const user = req.user;

      // ── FormData: amount comes as string — parseInt safely ───────────────
      const rawAmount = req.body && req.body.amount;
      const amount    = parseInt(rawAmount, 10);

      // ── Validate screenshot ──────────────────────────────────────────────
      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: 'Screenshot ပုံတင်ရန် လိုအပ်သည်',
        });
      }

      // ── Validate Cloudinary returned a URL ──────────────────────────────
      if (!req.file.path) {
        return res.status(502).json({
          success: false,
          message: 'Cloudinary သို့ ပုံ မတင်နိုင်ပါ။ နောက်မှ ထပ်ကြိုးစားပါ။',
        });
      }

      // ── Validate amount ──────────────────────────────────────────────────
      if (!rawAmount || isNaN(amount) || amount < MIN_WITHDRAW) {
        return res.status(400).json({
          success: false,
          message: `ထုတ်ယူမည့်ပမာဏ မမှန်ကန်ပါ။ အနည်းဆုံး ${MIN_WITHDRAW.toLocaleString()} MMK ဖြစ်ရမည်`,
        });
      }

      // ── Validate balance ─────────────────────────────────────────────────
      const totalDeduct = amount + SERVICE_FEE;
      if (user.balance < totalDeduct) {
        return res.status(400).json({
          success: false,
          message: `လက်ကျန်ငွေ မလုံလောက်ပါ (ထုတ်မည့်ငွေ ${amount.toLocaleString()} + ဝန်ဆောင်ခ ${SERVICE_FEE.toLocaleString()} = ${totalDeduct.toLocaleString()} Ks လိုသည်)`,
        });
      }

      // ── No duplicate pending withdrawal ──────────────────────────────────
      const hasPending = await Withdrawal.findOne({
        telegramId: user.telegramId,
        status: 'pending',
      });
      if (hasPending) {
        return res.status(409).json({
          success: false,
          message: 'ကြိုတင်တင်ထားသော ငွေထုတ်မှု ရှိနေသေးပါသည်',
        });
      }

      // ── Deduct balance ───────────────────────────────────────────────────
      deductAmount      = totalDeduct;
      const newBalance  = user.balance - totalDeduct;
      await User.findByIdAndUpdate(user._id, { $inc: { balance: -totalDeduct } });
      balanceDeducted   = true;

      // ── Create withdrawal DB record ──────────────────────────────────────
      let wd;
      try {
        wd = await Withdrawal.create({
          user:               user._id,
          telegramId:         user.telegramId,
          amount,
          fee:                SERVICE_FEE,
          netAmount:          amount - SERVICE_FEE,
          screenshotUrl:      req.file.path,
          screenshotPublicId: req.file.filename || req.file.public_id || '',
        });
      } catch (dbErr) {
        // DB failed — roll back balance immediately
        await User.findByIdAndUpdate(user._id, { $inc: { balance: deductAmount } }).catch(() => {});
        console.error('DB create withdrawal failed:', dbErr.message);
        return res.status(500).json({
          success: false,
          message: 'မှတ်တမ်းသိမ်းရာတွင် error ဖြစ်သည်။ Balance ပြန်ထည့်ပေးပြီးပါပြီ။',
        });
      }

      // ── Notify admin via Telegram (non-fatal) ────────────────────────────
      if (ADMIN_ID && bot) {
        const adminMsg =
          `💸 <b>ငွေထုတ်ယူမှု တောင်းဆိုမှု</b>\n\n` +
          `👤 ${user.displayName} (@${user.username || 'N/A'})\n` +
          `🆔 <code>${user.telegramId}</code>\n` +
          `💰 Amount: <b>${amount.toLocaleString()} Ks</b>\n` +
          `💳 Fee: ${SERVICE_FEE.toLocaleString()} Ks\n` +
          `✅ Net: <b>${(amount - SERVICE_FEE).toLocaleString()} Ks</b>\n` +
          `🕐 ${new Date().toLocaleString()}`;

        await sendTg(ADMIN_ID, adminMsg, {
          reply_markup: {
            inline_keyboard: [[
              { text: '✅ Approve', callback_data: `wd_approve_${wd._id}` },
              { text: '❌ Reject',  callback_data: `wd_reject_${wd._id}`  },
            ]],
          },
        }).catch((e) => console.warn('Admin TG notify failed:', e.message));

        await bot.telegram.sendPhoto(
          ADMIN_ID,
          { url: wd.screenshotUrl },
          { caption: `📸 ${user.displayName} — ${amount.toLocaleString()} Ks` }
        ).catch((e) => console.warn('Admin photo send failed:', e.message));
      }

      return res.status(201).json({
        success: true,
        message: 'ငွေထုတ်ယူမှု တင်ပြီးပါပြီ။ Admin မှ စစ်ဆေးပြီးနောက် Telegram မှ အကြောင်းကြားပါမည်။',
        data: {
          id:        wd._id,
          amount:    wd.amount,
          fee:       wd.fee,
          netAmount: wd.netAmount,
          status:    wd.status,
          newBalance,
        },
      });

    } catch (err) {
      console.error('Withdrawal unexpected error:', err.message);
      // Safety rollback if balance was deducted but something failed after
      if (balanceDeducted && req.user) {
        await User.findByIdAndUpdate(req.user._id, {
          $inc: { balance: deductAmount },
        }).catch((e) => console.error('CRITICAL — balance rollback failed:', e.message));
        console.warn(`Balance rollback: +${deductAmount} for ${req.user.telegramId}`);
      }
      return res.status(500).json({
        success: false,
        message: err.message || 'Server error ဖြစ်သည်',
      });
    }
  }
);

// ── Withdrawal: user's own history ────────────────────────────────────────────
app.get('/api/withdrawals/mine', requireUser, async (req, res) => {
  try {
    const wds = await Withdrawal.find({ telegramId: req.user.telegramId })
      .sort({ createdAt: -1 }).limit(20);
    res.json({ success: true, data: wds });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

// ── Withdrawal: recent approved (public leaderboard) ─────────────────────────
app.get('/api/withdrawals/recent', async (_req, res) => {
  try {
    const wds = await Withdrawal.find({ status: 'approved' })
      .sort({ updatedAt: -1 }).limit(20)
      .populate('user', 'firstName lastName username');

    const data = wds.map(w => ({
      id:     w._id,
      name:   w.user?.displayName || 'User',
      avatar: (w.user?.displayName || 'U').split(' ').map(x => x[0]).join('').slice(0, 2).toUpperCase(),
      net:    w.netAmount,
      date:   w.updatedAt.toISOString().split('T')[0],
    }));

    res.json({ success: true, data });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

// ═══════════════════════════════════════════
//  ADMIN ROUTES
// ═══════════════════════════════════════════
const adminRouter = express.Router();
adminRouter.use(requireAdmin);

adminRouter.get('/stats', async (_req, res) => {
  try {
    const [total, banned, pending, approved, rejected, balRes] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isBanned: true }),
      Withdrawal.countDocuments({ status: 'pending' }),
      Withdrawal.countDocuments({ status: 'approved' }),
      Withdrawal.countDocuments({ status: 'rejected' }),
      User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' } } }]),
    ]);
    res.json({ success: true, data: {
      total, banned,
      withdrawals: { pending, approved, rejected },
      totalBalance: balRes[0]?.total || 0,
    }});
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.get('/users', async (req, res) => {
  try {
    const { page = 1, limit = 30, search, banned } = req.query;
    const f = {};
    if (search) f.$or = [
      { firstName: new RegExp(search, 'i') },
      { username:  new RegExp(search, 'i') },
      { telegramId: search },
    ];
    if (banned !== undefined) f.isBanned = banned === 'true';
    const users = await User.find(f).sort({ createdAt: -1 }).skip((page-1)*limit).limit(parseInt(limit));
    const count = await User.countDocuments(f);
    res.json({ success: true, data: users, total: count });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.post('/users/:tid/ban', async (req, res) => {
  try {
    const { reason } = req.body;
    const u = await User.findOneAndUpdate(
      { telegramId: req.params.tid },
      { isBanned: true, banReason: reason || 'Violated terms' },
      { new: true }
    );
    if (!u) return res.status(404).json({ success: false, message: 'User not found' });
    await sendTg(u.telegramId, `🚫 <b>Account ပိတ်ထားပါသည်</b>\nအကြောင်းပြချက်: ${reason || 'Violated terms'}`);
    res.json({ success: true, data: u });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.post('/users/:tid/unban', async (req, res) => {
  try {
    const u = await User.findOneAndUpdate(
      { telegramId: req.params.tid },
      { isBanned: false, banReason: '' },
      { new: true }
    );
    if (!u) return res.status(404).json({ success: false, message: 'User not found' });
    await sendTg(u.telegramId, `✅ <b>Account ပြန်ဖွင့်ပေးပြီးပါပြီ</b>`);
    res.json({ success: true, data: u });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.patch('/users/:tid/balance', async (req, res) => {
  try {
    const { action, amount, note } = req.body;
    if (!['add','subtract'].includes(action)) {
      return res.status(400).json({ success: false, message: 'action must be add or subtract' });
    }
    const delta = action === 'add' ? Math.abs(amount) : -Math.abs(amount);
    const u = await User.findOne({ telegramId: req.params.tid });
    if (!u) return res.status(404).json({ success: false, message: 'User not found' });
    if (action === 'subtract' && u.balance < Math.abs(amount)) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    const inc = { balance: delta };
    if (action === 'add') inc.totalEarned = Math.abs(amount);
    const updated = await User.findByIdAndUpdate(u._id, { $inc: inc }, { new: true });
    const verb = action === 'add' ? 'ထည့်' : 'နုတ်';
    await sendTg(u.telegramId,
      `💰 <b>Admin မှ ${Math.abs(amount).toLocaleString()} Ks ${verb}ပေးပါပြီ</b>\n` +
      `လက်ကျန်: ${updated.balance.toLocaleString()} Ks` +
      (note ? `\nမှတ်ချက်: ${note}` : '')
    );
    res.json({ success: true, data: updated });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.patch('/users/:tid/referrals', async (req, res) => {
  try {
    const { count } = req.body;
    const bonus = count * REFERRAL_BONUS;
    const u = await User.findOneAndUpdate(
      { telegramId: req.params.tid },
      { $inc: { referrals: count, balance: bonus, totalEarned: bonus } },
      { new: true }
    );
    if (!u) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, data: u });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.get('/withdrawals', async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;
    const f = {};
    if (status) f.status = status;
    const wds = await Withdrawal.find(f)
      .sort({ createdAt: -1 })
      .skip((page-1)*limit).limit(parseInt(limit))
      .populate('user', 'firstName lastName username telegramId');
    const total = await Withdrawal.countDocuments(f);
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
    await sendTg(wd.telegramId,
      `✅ <b>ငွေထုတ်ယူမှု အတည်ပြုပြီးပါပြီ!</b>\n💰 ${wd.netAmount.toLocaleString()} Ks ကို မကြာမီ ပေးပို့ပါမည်`
    );
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
    // Refund balance
    await User.findByIdAndUpdate(wd.user._id, { $inc: { balance: wd.amount + wd.fee } });
    await sendTg(wd.telegramId,
      `❌ <b>ငွေထုတ်ယူမှု ငြင်းပယ်ပါသည်</b>\n\nအကြောင်းပြချက်: ${reason}\n\n` +
      `💰 ${(wd.amount + wd.fee).toLocaleString()} Ks ကို ပြန်ထည့်ပေးပြီးပါပြီ`
    );
    res.json({ success: true, data: wd });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

adminRouter.post('/broadcast', async (req, res) => {
  try {
    const { message: msg } = req.body;
    if (!msg) return res.status(400).json({ success: false, message: 'message required' });
    const users = await User.find({ isBanned: false }).select('telegramId');
    let sent = 0, failed = 0;
    for (const u of users) {
      const ok = await sendTg(u.telegramId, `📢 <b>ကြေညာချက်</b>\n\n${msg}`).catch(() => null);
      ok ? sent++ : failed++;
      await new Promise(r => setTimeout(r, 60));
    }
    res.json({ success: true, data: { sent, failed, total: users.length } });
  } catch { res.status(500).json({ success: false, message: 'Server error' }); }
});

app.use('/api/admin', adminRouter);

// 404
app.use((_req, res) => res.status(404).json({ success: false, message: 'Route not found' }));

// ── Global error handler (catches anything not handled above) ─────────────────
app.use((err, _req, res, _next) => {
  console.error('Global error:', err.code || '', err.message);

  // Multer errors
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ success: false, message: 'ပုံဖိုင် 10MB ထက်ကြီးနေသည်' });
  }
  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json({ success: false, message: `FormData field name မှားနေသည် — "screenshot" သုံးပါ (received: ${err.field})` });
  }

  // CORS error
  if (err.message && err.message.startsWith('CORS blocked')) {
    return res.status(403).json({ success: false, message: err.message });
  }

  // Cloudinary errors (http_code present)
  if (err.http_code) {
    return res.status(502).json({ success: false, message: `Cloudinary error ${err.http_code}: ${err.message}` });
  }

  // Mongoose validation
  if (err.name === 'ValidationError') {
    return res.status(400).json({ success: false, message: err.message });
  }

  // Default
  res.status(500).json({ success: false, message: err.message || 'Internal server error' });
});

// ═══════════════════════════════════════════
//  TELEGRAF BOT
// ═══════════════════════════════════════════
let bot = null;

function initBot() {
  if (!process.env.BOT_TOKEN) {
    console.warn('⚠️  BOT_TOKEN not set — bot disabled');
    return;
  }

  bot = new Telegraf(process.env.BOT_TOKEN);

  // In-memory pending states
  const pendingReplies    = {};  // adminId → targetUserId
  const pendingRejections = {};  // adminId → withdrawalId

  // ── /start ────────────────────────────────────────────────────────────────
  bot.start(async ctx => {
    const tgUser    = ctx.from;
    const chatId    = String(ctx.chat.id);
    const startParam = ctx.startPayload || '';

    try {
      let user = await User.findOne({ telegramId: chatId });
      if (!user) {
        const myCode = `ref_${chatId}`;
        user = await User.create({
          telegramId: chatId,
          firstName:  tgUser.first_name || '',
          lastName:   tgUser.last_name  || '',
          username:   tgUser.username   || '',
          referralCode: myCode,
        });
        if (startParam.startsWith('ref_') && startParam !== myCode) {
          const refId = startParam.replace('ref_', '');
          const referrer = await User.findOne({ telegramId: refId });
          if (referrer && !referrer.isBanned) {
            await User.findByIdAndUpdate(referrer._id, {
              $inc: { balance: REFERRAL_BONUS, totalEarned: REFERRAL_BONUS, referrals: 1 },
            });
            user.referredBy = refId;
            await user.save();
            await sendTg(refId, `🎉 <b>မိတ်ဆွေ ဝင်ရောက်ပြီ!</b>\n💰 ${REFERRAL_BONUS.toLocaleString()} Ks ထည့်ပေးပြီးပါပြီ`);
          }
        }
      } else {
        await User.findByIdAndUpdate(user._id, {
          firstName: tgUser.first_name || user.firstName,
          lastName:  tgUser.last_name  || user.lastName,
          username:  tgUser.username   || user.username,
          lastSeen:  new Date(),
        });
      }

      if (user.isBanned) {
        return ctx.reply(`🚫 Account ပိတ်ထားပါသည်\nအကြောင်း: ${user.banReason}`);
      }

      await ctx.reply(
        `👋 မင်္ဂလာပါ ${tgUser.first_name}!\n\nKBZPay Mini App သို့ ကြိုဆိုပါသည် 🎉\nမိတ်ဆွေများကို ဖိတ်ကြားပြီး ငွေရှာပါ 💰`,
        {
          reply_markup: {
            inline_keyboard: [[
              { text: '💰 App ဖွင့်မည်', web_app: { url: FRONTEND_URL } },
            ]],
          },
        }
      );
    } catch (err) {
      console.error('Bot /start error:', err.message);
    }
  });

  // ── Admin slash commands ───────────────────────────────────────────────────
  bot.command('admin', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    ctx.reply(
      `🛠 <b>Admin Commands</b>\n\n` +
      `/ban [id] [reason] — User ban\n` +
      `/unban [id] — User unban\n` +
      `/addmoney [id] [amount] — Balance ထည့်\n` +
      `/reducemoney [id] [amount] — Balance နုတ်\n` +
      `/addrefs [id] [count] — Referral တိုး\n` +
      `/userinfo [id] — User အချက်အလက်\n` +
      `/stats — App statistics`,
      { parse_mode: 'HTML' }
    );
  });

  bot.command('ban', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const parts = ctx.message.text.split(' ');
    const tid = parts[1]; const reason = parts.slice(2).join(' ') || 'Violated terms';
    if (!tid) return ctx.reply('Usage: /ban [telegramId] [reason]');
    const u = await User.findOneAndUpdate({ telegramId: tid }, { isBanned: true, banReason: reason }, { new: true }).catch(() => null);
    if (!u) return ctx.reply(`❌ User ${tid} not found`);
    await sendTg(tid, `🚫 Account ပိတ်ထားပါသည်\nအကြောင်း: ${reason}`);
    ctx.reply(`✅ Banned: ${u.displayName} (${tid})`);
  });

  bot.command('unban', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const tid = ctx.message.text.split(' ')[1];
    if (!tid) return ctx.reply('Usage: /unban [telegramId]');
    const u = await User.findOneAndUpdate({ telegramId: tid }, { isBanned: false, banReason: '' }, { new: true }).catch(() => null);
    if (!u) return ctx.reply(`❌ User ${tid} not found`);
    await sendTg(tid, `✅ Account ပြန်ဖွင့်ပေးပြီးပါပြီ`);
    ctx.reply(`✅ Unbanned: ${u.displayName}`);
  });

  bot.command('addmoney', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [, tid, amtStr] = ctx.message.text.split(' ');
    if (!tid || !amtStr) return ctx.reply('Usage: /addmoney [id] [amount]');
    const amt = parseInt(amtStr);
    const u = await User.findOneAndUpdate({ telegramId: tid }, { $inc: { balance: amt, totalEarned: amt } }, { new: true }).catch(() => null);
    if (!u) return ctx.reply('❌ Not found');
    await sendTg(tid, `💰 Admin မှ ${amt.toLocaleString()} Ks ထည့်ပေးပါပြီ\nလက်ကျန်: ${u.balance.toLocaleString()} Ks`);
    ctx.reply(`✅ Added ${amt.toLocaleString()} Ks to ${u.displayName}\nNew balance: ${u.balance.toLocaleString()} Ks`);
  });

  bot.command('reducemoney', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [, tid, amtStr] = ctx.message.text.split(' ');
    if (!tid || !amtStr) return ctx.reply('Usage: /reducemoney [id] [amount]');
    const amt = parseInt(amtStr);
    const u = await User.findOne({ telegramId: tid }).catch(() => null);
    if (!u) return ctx.reply('❌ Not found');
    if (u.balance < amt) return ctx.reply(`❌ Insufficient balance (${u.balance.toLocaleString()} Ks)`);
    await User.findByIdAndUpdate(u._id, { $inc: { balance: -amt } });
    ctx.reply(`✅ Reduced ${amt.toLocaleString()} Ks from ${u.displayName}`);
  });

  bot.command('addrefs', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [, tid, countStr] = ctx.message.text.split(' ');
    if (!tid || !countStr) return ctx.reply('Usage: /addrefs [id] [count]');
    const count = parseInt(countStr); const bonus = count * REFERRAL_BONUS;
    const u = await User.findOneAndUpdate({ telegramId: tid }, { $inc: { referrals: count, balance: bonus, totalEarned: bonus } }, { new: true }).catch(() => null);
    if (!u) return ctx.reply('❌ Not found');
    ctx.reply(`✅ Added ${count} referrals (+${bonus.toLocaleString()} Ks) to ${u.displayName}`);
  });

  bot.command('userinfo', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const tid = ctx.message.text.split(' ')[1];
    if (!tid) return ctx.reply('Usage: /userinfo [telegramId]');
    const u = await User.findOne({ telegramId: tid }).catch(() => null);
    if (!u) return ctx.reply('❌ Not found');
    ctx.reply(
      `👤 <b>User Info</b>\n` +
      `Name: ${u.displayName}\nUsername: @${u.username || 'N/A'}\nID: <code>${u.telegramId}</code>\n` +
      `Balance: ${u.balance.toLocaleString()} Ks\nReferrals: ${u.referrals}\n` +
      `Total Earned: ${u.totalEarned.toLocaleString()} Ks\nTotal Withdrawn: ${u.totalWithdrawn.toLocaleString()} Ks\n` +
      `Banned: ${u.isBanned ? '🚫 Yes' : '✅ No'}\nJoined: ${u.createdAt.toLocaleDateString()}`,
      { parse_mode: 'HTML' }
    );
  });

  bot.command('stats', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [total, banned, pending] = await Promise.all([
      User.countDocuments(), User.countDocuments({ isBanned: true }),
      Withdrawal.countDocuments({ status: 'pending' }),
    ]);
    const balRes = await User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' } } }]);
    ctx.reply(
      `📊 <b>App Stats</b>\n👥 Users: ${total}\n🚫 Banned: ${banned}\n⏳ Pending WD: ${pending}\n💰 Total Balance: ${(balRes[0]?.total || 0).toLocaleString()} Ks`,
      { parse_mode: 'HTML' }
    );
  });

  // ── Support chat: user → admin forward ────────────────────────────────────
  bot.on(message('text'), async ctx => {
    if (ctx.message.text.startsWith('/')) return;
    const chatId = String(ctx.chat.id);

    // Admin typing a reply or rejection reason
    if (chatId === ADMIN_ID) {
      // Support reply
      if (pendingReplies[ADMIN_ID]) {
        const targetId = pendingReplies[ADMIN_ID];
        delete pendingReplies[ADMIN_ID];
        await sendTg(targetId, `📩 <b>Admin ထံမှ ပြန်စာ:</b>\n\n${ctx.message.text}`);
        await SupportMsg.create({ telegramId: targetId, displayName: 'Admin', text: ctx.message.text, direction: 'admin_to_user' }).catch(() => {});
        return ctx.reply(`✅ Reply sent to user ${targetId}`);
      }
      // Withdrawal rejection reason
      if (pendingRejections[ADMIN_ID]) {
        const wdId = pendingRejections[ADMIN_ID];
        delete pendingRejections[ADMIN_ID];
        const reason = ctx.message.text;
        const wd = await Withdrawal.findById(wdId).populate('user').catch(() => null);
        if (wd && wd.status === 'pending') {
          wd.status = 'rejected'; wd.rejectionReason = reason; wd.reviewedAt = new Date();
          await wd.save();
          await User.findByIdAndUpdate(wd.user._id, { $inc: { balance: wd.amount + wd.fee } });
          await sendTg(wd.telegramId,
            `❌ <b>ငွေထုတ်ယူမှု ငြင်းပယ်ပါသည်</b>\n\nအကြောင်းပြချက်: ${reason}\n\n💰 ${(wd.amount + wd.fee).toLocaleString()} Ks ပြန်ထည့်ပေးပြီးပါပြီ`
          );
          return ctx.reply(`✅ Rejected wd #${wdId} — balance refunded`);
        }
        return ctx.reply('❌ Withdrawal not found or already processed');
      }
      return;
    }

    // Regular user support message
    const u = await User.findOne({ telegramId: chatId }).catch(() => null);
    if (!u || u.isBanned) return;

    await SupportMsg.create({ telegramId: chatId, displayName: u.displayName, text: ctx.message.text, direction: 'user_to_admin' }).catch(() => {});

    if (ADMIN_ID) {
      await sendTg(ADMIN_ID,
        `📨 <b>Support Message</b>\n👤 ${u.displayName} (@${u.username || 'N/A'})\n🆔 <code>${chatId}</code>\n\n💬 ${ctx.message.text}`,
        { reply_markup: { inline_keyboard: [[{ text: '↩️ Reply', callback_data: `reply_${chatId}` }]] } }
      );
    }
    ctx.reply('✅ မက်ဆေ့ကို Admin ထံ ပေးပို့ပြီးပါပြီ။ မကြာမီ ပြန်လည်ဖြေကြားပါမည်။');
  });

  // ── Callback queries (admin inline buttons) ───────────────────────────────
  bot.on('callback_query', async ctx => {
    const adminId = String(ctx.from.id);
    if (adminId !== ADMIN_ID) return ctx.answerCbQuery('⛔ Unauthorized');

    const data = ctx.callbackQuery.data;

    // Support reply button
    if (data.startsWith('reply_')) {
      pendingReplies[ADMIN_ID] = data.replace('reply_', '');
      await ctx.answerCbQuery('📝 Type your reply now');
      return ctx.reply(`✏️ Type your reply for user ${pendingReplies[ADMIN_ID]}:`);
    }

    // Withdrawal approve
    if (data.startsWith('wd_approve_')) {
      const wdId = data.replace('wd_approve_', '');
      const wd = await Withdrawal.findById(wdId).populate('user').catch(() => null);
      if (!wd || wd.status !== 'pending') return ctx.answerCbQuery('⚠️ Already processed');
      wd.status = 'approved'; wd.reviewedAt = new Date();
      await wd.save();
      await User.findByIdAndUpdate(wd.user._id, { $inc: { totalWithdrawn: wd.netAmount } });
      await ctx.answerCbQuery('✅ Approved!');
      await ctx.editMessageReplyMarkup({ inline_keyboard: [] }).catch(() => {});
      await sendTg(wd.telegramId, `✅ <b>ငွေထုတ်ယူမှု အတည်ပြုပြီးပါပြီ!</b>\n💰 ${wd.netAmount.toLocaleString()} Ks ကို မကြာမီ ပေးပို့ပါမည်`);
      return ctx.reply(`✅ Approved for ${wd.user?.displayName}`);
    }

    // Withdrawal reject (step 1 — ask reason)
    if (data.startsWith('wd_reject_')) {
      pendingRejections[ADMIN_ID] = data.replace('wd_reject_', '');
      await ctx.answerCbQuery('✏️ Send rejection reason');
      await ctx.editMessageReplyMarkup({ inline_keyboard: [] }).catch(() => {});
      return ctx.reply(`📝 Type rejection reason for withdrawal #${pendingRejections[ADMIN_ID]}:`);
    }

    ctx.answerCbQuery();
  });

  bot.launch({ dropPendingUpdates: true })
    .then(() => console.log('🤖 Telegraf bot started'))
    .catch(err => console.error('Bot launch error:', err.message));

  process.once('SIGINT',  () => bot.stop('SIGINT'));
  process.once('SIGTERM', () => bot.stop('SIGTERM'));
}

// ═══════════════════════════════════════════
//  STARTUP
// ═══════════════════════════════════════════
(async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
    console.log('✅ MongoDB connected');
    initBot();
    app.listen(PORT, () => {
      console.log(`🚀 Server: https://kbzpaybackend.onrender.com`);
      console.log(`🌐 Frontend: https://kbzpayfrontend.vercel.app`);
    });
  } catch (err) {
    console.error('❌ Startup failed:', err.message);
    process.exit(1);
  }
})();
