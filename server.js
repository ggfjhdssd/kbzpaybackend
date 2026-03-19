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

// ═══════════════════════════════════════════════
//  ENV CHECK
// ═══════════════════════════════════════════════
const REQUIRED_ENV = ['MONGODB_URI','BOT_TOKEN','ADMIN_CHAT_ID','CLOUDINARY_CLOUD_NAME','CLOUDINARY_API_KEY','CLOUDINARY_API_SECRET'];
REQUIRED_ENV.forEach(k => { if (!process.env[k]) console.warn(`⚠️  Missing env: ${k}`); });

const PORT            = process.env.PORT || 5000;
const ADMIN_ID        = process.env.ADMIN_CHAT_ID;
const ADMIN_SECRET    = process.env.ADMIN_SECRET    || 'changeme';
const MIN_WITHDRAW    = Number(process.env.MIN_WITHDRAW)   || 100000;
const SERVICE_FEE     = Number(process.env.SERVICE_FEE)    || 5000;
const REFERRAL_BONUS  = Number(process.env.REFERRAL_BONUS) || 5000;
const PAYMENT_PHONE   = process.env.PAYMENT_PHONE || '09702310926';
const PAYMENT_NAME    = process.env.PAYMENT_NAME  || 'Daw Mi Thaung';
const FRONTEND_URL    = process.env.FRONTEND_URL  || '*';
const BOT_USERNAME    = process.env.BOT_USERNAME  || 'YourBot';

// ═══════════════════════════════════════════════
//  CLOUDINARY
// ═══════════════════════════════════════════════
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder:          'kbzpay_withdrawals',
    allowed_formats: ['jpg','jpeg','png','webp'],
    transformation:  [{ width:1400, crop:'limit', quality:'auto:good' }],
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only images allowed'), false);
  },
});

// ═══════════════════════════════════════════════
//  MONGOOSE MODELS
// ═══════════════════════════════════════════════
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

const withdrawalSchema = new mongoose.Schema({
  user:           { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  telegramId:     { type: String, required: true, index: true },
  amount:         { type: Number, required: true },
  fee:            { type: Number, default: 5000 },
  netAmount:      { type: Number, required: true },
  screenshotUrl:  { type: String, required: true },
  screenshotPublicId: { type: String },
  status:         { type: String, enum: ['pending','approved','rejected'], default: 'pending', index: true },
  rejectionReason: { type: String, default: '' },
  adminNote:      { type: String, default: '' },
  reviewedBy:     { type: String, default: '' },
  reviewedAt:     { type: Date },
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

// ═══════════════════════════════════════════════
//  EXPRESS APP
// ═══════════════════════════════════════════════
const app = express();

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: FRONTEND_URL, methods: ['GET','POST','PUT','PATCH','DELETE'], allowedHeaders: ['Content-Type','x-telegram-id','x-admin-secret'] }));
app.use(rateLimit({ windowMs: 60*1000, max: 80, standardHeaders: true, legacyHeaders: false, message: { success:false, message:'Too many requests' } }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Middleware ────────────────────────────────────────────────────────────────
const requireUser = async (req, res, next) => {
  const tid = req.headers['x-telegram-id'];
  if (!tid) return res.status(401).json({ success:false, message:'Missing x-telegram-id' });
  const u = await User.findOne({ telegramId: tid }).catch(() => null);
  if (!u) return res.status(404).json({ success:false, message:'User not found. Please start the bot first.' });
  if (u.isBanned) return res.status(403).json({ success:false, message:`🚫 Account banned: ${u.banReason}` });
  req.user = u; next();
};

const requireAdmin = (req, res, next) => {
  const s = req.headers['x-admin-secret'];
  if (!s || s !== ADMIN_SECRET) return res.status(403).json({ success:false, message:'Forbidden' });
  next();
};

// ── Helper: send Telegram message safely ─────────────────────────────────────
const sendTg = async (chatId, text, extra = {}) => {
  if (!bot) return;
  return bot.telegram.sendMessage(chatId, text, { parse_mode:'HTML', ...extra }).catch(e => console.warn('Telegram send error:', e.message));
};

// ═══════════════════════════════════════════════
//  ROUTES
// ═══════════════════════════════════════════════

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ status:'ok', service:'KBZPay Backend', time: new Date().toISOString() }));

// ── App config (frontend fetches payment info) ────────────────────────────────
app.get('/api/config', (_req, res) => res.json({
  success: true,
  data: { paymentPhone: PAYMENT_PHONE, paymentName: PAYMENT_NAME, minWithdraw: MIN_WITHDRAW, serviceFee: SERVICE_FEE, referralBonus: REFERRAL_BONUS },
}));

// ── Users: init / login ────────────────────────────────────────────────────────
app.post('/api/users/me', async (req, res) => {
  try {
    const { telegramId, firstName, lastName, username, referralCode } = req.body;
    if (!telegramId) return res.status(400).json({ success:false, message:'telegramId required' });

    let user = await User.findOne({ telegramId });
    if (!user) {
      const myCode = `ref_${telegramId}`;
      user = await User.create({ telegramId, firstName, lastName, username, referralCode: myCode });

      // Handle referral
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
      await User.findByIdAndUpdate(user._id, {
        firstName: firstName || user.firstName,
        lastName:  lastName  || user.lastName,
        username:  username  || user.username,
        lastSeen: new Date(),
      });
      user = await User.findById(user._id);
    }

    if (user.isBanned) return res.status(403).json({ success:false, message:`🚫 Account banned: ${user.banReason}` });

    return res.json({ success:true, data: {
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
    }});
  } catch (err) {
    console.error('/api/users/me error:', err);
    res.status(500).json({ success:false, message:'Server error' });
  }
});

// ── Users: leaderboard ────────────────────────────────────────────────────────
app.get('/api/users/leaderboard', async (_req, res) => {
  try {
    const users = await User.find({ isBanned:false }).sort({ referrals:-1, totalEarned:-1 }).limit(20)
      .select('telegramId firstName lastName username referrals totalEarned');
    const data = users.map((u,i) => ({
      rank: i+1, name: u.displayName,
      avatar: u.displayName.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase(),
      referrals: u.referrals, earned: u.totalEarned,
    }));
    res.json({ success:true, data });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

// ── Withdrawals: submit ────────────────────────────────────────────────────────
app.post('/api/withdrawals', requireUser, upload.single('screenshot'), async (req, res) => {
  try {
    const user   = req.user;
    const amount = parseInt(req.body.amount);

    if (!req.file) return res.status(400).json({ success:false, message:'Screenshot လိုအပ်သည်' });
    if (isNaN(amount) || amount < MIN_WITHDRAW) return res.status(400).json({ success:false, message:`အနည်းဆုံး ${MIN_WITHDRAW.toLocaleString()} MMK ထုတ်ယူရမည်` });
    if (user.balance < amount + SERVICE_FEE) return res.status(400).json({ success:false, message:`လက်ကျန်ငွေ မလုံလောက်ပါ (ငွေ + ဝန်ဆောင်ခ ${SERVICE_FEE.toLocaleString()} Ks)` });

    const hasPending = await Withdrawal.findOne({ telegramId: user.telegramId, status:'pending' });
    if (hasPending) return res.status(409).json({ success:false, message:'ကြိုတင်တင်ထားသော ငွေထုတ်မှု ရှိနေပါသည်' });

    // Deduct balance
    await User.findByIdAndUpdate(user._id, { $inc: { balance: -(amount + SERVICE_FEE) } });

    const wd = await Withdrawal.create({
      user:               user._id,
      telegramId:         user.telegramId,
      amount, fee: SERVICE_FEE,
      netAmount:          amount - SERVICE_FEE,
      screenshotUrl:      req.file.path,
      screenshotPublicId: req.file.filename,
    });

    // Notify admin via bot
    if (ADMIN_ID) {
      const adminMsg =
        `💸 <b>ငွေထုတ်ယူမှု တောင်းဆိုမှု</b>\n\n` +
        `👤 ${user.displayName} (@${user.username||'N/A'})\n` +
        `🆔 ${user.telegramId}\n` +
        `💰 Amount: <b>${amount.toLocaleString()} Ks</b>\n` +
        `💳 Fee: ${SERVICE_FEE.toLocaleString()} Ks\n` +
        `✅ Net: <b>${(amount-SERVICE_FEE).toLocaleString()} Ks</b>\n` +
        `🕐 ${new Date().toLocaleString('my-MM')}`;

      await sendTg(ADMIN_ID, adminMsg, {
        reply_markup: { inline_keyboard: [[
          { text:'✅ Approve', callback_data:`wd_approve_${wd._id}` },
          { text:'❌ Reject',  callback_data:`wd_reject_${wd._id}`  },
        ]]},
      });

      // Send screenshot photo to admin
      await bot.telegram.sendPhoto(ADMIN_ID, { url: wd.screenshotUrl }, { caption:`📸 Screenshot — ${user.displayName}` }).catch(()=>{});
    }

    res.status(201).json({
      success:true,
      message:'ငွေထုတ်ယူမှု တင်ပြီးပါပြီ။ Admin မှ စစ်ဆေးပြီးနောက် Telegram မှ အကြောင်းကြားပါမည်။',
      data: { id:wd._id, amount:wd.amount, fee:wd.fee, netAmount:wd.netAmount, status:wd.status, newBalance: user.balance - (amount+SERVICE_FEE) },
    });
  } catch (err) {
    console.error('Withdrawal error:', err);
    res.status(500).json({ success:false, message: err.message || 'Server error' });
  }
});

// ── Withdrawals: my history ───────────────────────────────────────────────────
app.get('/api/withdrawals/mine', requireUser, async (req, res) => {
  try {
    const wds = await Withdrawal.find({ telegramId: req.user.telegramId }).sort({ createdAt:-1 }).limit(20);
    res.json({ success:true, data: wds });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

// ── Withdrawals: recent approved (public) ─────────────────────────────────────
app.get('/api/withdrawals/recent', async (_req, res) => {
  try {
    const wds = await Withdrawal.find({ status:'approved' }).sort({ updatedAt:-1 }).limit(20)
      .populate('user','firstName lastName username');
    const data = wds.map(w => ({
      id: w._id,
      name:   w.user?.displayName || 'User',
      avatar: (w.user?.displayName||'U').split(' ').map(x=>x[0]).join('').slice(0,2).toUpperCase(),
      net:    w.netAmount,
      date:   w.updatedAt.toISOString().split('T')[0],
    }));
    res.json({ success:true, data });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

// ════════════════════════════════════════════
//  ADMIN ROUTES
// ════════════════════════════════════════════
const adminRouter = express.Router();
adminRouter.use(requireAdmin);

adminRouter.get('/stats', async (_req, res) => {
  try {
    const [total, banned, pending, approved, rejected, balResult] = await Promise.all([
      User.countDocuments(), User.countDocuments({isBanned:true}),
      Withdrawal.countDocuments({status:'pending'}),
      Withdrawal.countDocuments({status:'approved'}),
      Withdrawal.countDocuments({status:'rejected'}),
      User.aggregate([{$group:{_id:null,total:{$sum:'$balance'}}}]),
    ]);
    res.json({ success:true, data:{ total, banned, withdrawals:{pending,approved,rejected}, totalBalance: balResult[0]?.total||0 } });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

adminRouter.get('/users', async (req, res) => {
  try {
    const { page=1, limit=30, search, banned } = req.query;
    const f = {};
    if (search) f.$or = [{ firstName:new RegExp(search,'i') },{ username:new RegExp(search,'i') },{ telegramId:search }];
    if (banned !== undefined) f.isBanned = banned==='true';
    const users = await User.find(f).sort({ createdAt:-1 }).skip((page-1)*limit).limit(parseInt(limit));
    const count = await User.countDocuments(f);
    res.json({ success:true, data:users, total:count });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

adminRouter.post('/users/:tid/ban', async (req, res) => {
  try {
    const { reason } = req.body;
    const u = await User.findOneAndUpdate({ telegramId:req.params.tid },{ isBanned:true, banReason:reason||'Violated terms' },{ new:true });
    if (!u) return res.status(404).json({ success:false, message:'User not found' });
    await sendTg(u.telegramId, `🚫 <b>Account ပိတ်ထားပါသည်</b>\nအကြောင်းပြချက်: ${reason||'Violated terms'}`);
    res.json({ success:true, data:u });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

adminRouter.post('/users/:tid/unban', async (req, res) => {
  try {
    const u = await User.findOneAndUpdate({ telegramId:req.params.tid },{ isBanned:false, banReason:'' },{ new:true });
    if (!u) return res.status(404).json({ success:false, message:'User not found' });
    await sendTg(u.telegramId, `✅ <b>Account ပြန်ဖွင့်ပေးပြီးပါပြီ</b>`);
    res.json({ success:true, data:u });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

adminRouter.patch('/users/:tid/balance', async (req, res) => {
  try {
    const { action, amount, note } = req.body;
    if (!['add','subtract'].includes(action)) return res.status(400).json({ success:false, message:'action: add|subtract' });
    const delta = action==='add' ? Math.abs(amount) : -Math.abs(amount);
    const u = await User.findOne({ telegramId:req.params.tid });
    if (!u) return res.status(404).json({ success:false, message:'User not found' });
    if (action==='subtract' && u.balance < Math.abs(amount)) return res.status(400).json({ success:false, message:'Insufficient balance' });
    const inc = { balance:delta };
    if (action==='add') inc.totalEarned = Math.abs(amount);
    const updated = await User.findByIdAndUpdate(u._id, { $inc:inc },{ new:true });
    const verb = action==='add' ? 'ထည့်' : 'နုတ်';
    await sendTg(u.telegramId, `💰 <b>Admin မှ ${Math.abs(amount).toLocaleString()} Ks ${verb}ပေးပါပြီ</b>\nလက်ကျန်: ${updated.balance.toLocaleString()} Ks${note?`\nမှတ်ချက်: ${note}`:''}`);
    res.json({ success:true, data:updated });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

adminRouter.patch('/users/:tid/referrals', async (req, res) => {
  try {
    const { count } = req.body;
    const bonus = count * REFERRAL_BONUS;
    const u = await User.findOneAndUpdate({ telegramId:req.params.tid },{ $inc:{ referrals:count, balance:bonus, totalEarned:bonus } },{ new:true });
    if (!u) return res.status(404).json({ success:false, message:'User not found' });
    res.json({ success:true, data:u });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

adminRouter.get('/withdrawals', async (req, res) => {
  try {
    const { status, page=1, limit=20 } = req.query;
    const f = {}; if (status) f.status = status;
    const wds = await Withdrawal.find(f).sort({ createdAt:-1 }).skip((page-1)*limit).limit(parseInt(limit))
      .populate('user','firstName lastName username telegramId');
    const total = await Withdrawal.countDocuments(f);
    res.json({ success:true, data:wds, total });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

adminRouter.post('/withdrawals/:id/approve', async (req, res) => {
  try {
    const wd = await Withdrawal.findById(req.params.id).populate('user');
    if (!wd) return res.status(404).json({ success:false, message:'Not found' });
    if (wd.status!=='pending') return res.status(409).json({ success:false, message:'Already processed' });
    wd.status='approved'; wd.reviewedAt=new Date(); wd.adminNote=req.body.note||'';
    await wd.save();
    await User.findByIdAndUpdate(wd.user._id, { $inc:{ totalWithdrawn:wd.netAmount } });
    await sendTg(wd.telegramId, `✅ <b>ငွေထုတ်ယူမှု အတည်ပြုပြီးပါပြီ!</b>\n💰 ${wd.netAmount.toLocaleString()} Ks ကို မကြာမီ ပေးပို့ပါမည်`);
    res.json({ success:true, data:wd });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

adminRouter.post('/withdrawals/:id/reject', async (req, res) => {
  try {
    const { reason } = req.body;
    if (!reason) return res.status(400).json({ success:false, message:'reason required' });
    const wd = await Withdrawal.findById(req.params.id).populate('user');
    if (!wd) return res.status(404).json({ success:false, message:'Not found' });
    if (wd.status!=='pending') return res.status(409).json({ success:false, message:'Already processed' });
    wd.status='rejected'; wd.rejectionReason=reason; wd.reviewedAt=new Date();
    await wd.save();
    // Refund
    await User.findByIdAndUpdate(wd.user._id, { $inc:{ balance: wd.amount+wd.fee } });
    await sendTg(wd.telegramId,
      `❌ <b>ငွေထုတ်ယူမှု ငြင်းပယ်ပါသည်</b>\n\nအကြောင်းပြချက်: ${reason}\n\n💰 ${(wd.amount+wd.fee).toLocaleString()} Ks ကို ပြန်ထည့်ပေးပြီးပါပြီ`
    );
    res.json({ success:true, data:wd });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

adminRouter.post('/broadcast', async (req, res) => {
  try {
    const { message: msg } = req.body;
    if (!msg) return res.status(400).json({ success:false, message:'message required' });
    const users = await User.find({ isBanned:false }).select('telegramId');
    let sent=0, failed=0;
    for (const u of users) {
      const ok = await sendTg(u.telegramId, `📢 <b>ကြေညာချက်</b>\n\n${msg}`).catch(()=>null);
      ok ? sent++ : failed++;
      await new Promise(r=>setTimeout(r,55));
    }
    res.json({ success:true, data:{ sent, failed, total:users.length } });
  } catch { res.status(500).json({ success:false, message:'Server error' }); }
});

app.use('/api/admin', adminRouter);

// 404
app.use((_req, res) => res.status(404).json({ success:false, message:'Route not found' }));
// Error handler
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ success:false, message: err.message||'Internal server error' });
});

// ═══════════════════════════════════════════════
//  TELEGRAF BOT
// ═══════════════════════════════════════════════
let bot = null;

const initBot = () => {
  if (!process.env.BOT_TOKEN) return;

  bot = new Telegraf(process.env.BOT_TOKEN);
  const pendingReplies    = {};   // adminId -> targetUserId (support reply)
  const pendingRejections = {};   // adminId -> withdrawalId (rejection reason)

  // ── /start ────────────────────────────────────────────────────────────────
  bot.start(async (ctx) => {
    const tgUser = ctx.from;
    const chatId = String(ctx.chat.id);
    const startParam = ctx.startPayload || '';

    try {
      let user = await User.findOne({ telegramId: chatId });
      if (!user) {
        const myCode = `ref_${chatId}`;
        user = await User.create({
          telegramId: chatId,
          firstName:  tgUser.first_name||'',
          lastName:   tgUser.last_name ||'',
          username:   tgUser.username  ||'',
          referralCode: myCode,
        });
        if (startParam.startsWith('ref_') && startParam !== myCode) {
          const refId = startParam.replace('ref_','');
          const referrer = await User.findOne({ telegramId: refId });
          if (referrer && !referrer.isBanned) {
            await User.findByIdAndUpdate(referrer._id, { $inc:{ balance:REFERRAL_BONUS, totalEarned:REFERRAL_BONUS, referrals:1 } });
            user.referredBy = refId; await user.save();
            await sendTg(refId, `🎉 <b>မိတ်ဆွေ ဝင်ရောက်ပြီ!</b>\n💰 ${REFERRAL_BONUS.toLocaleString()} Ks ထည့်ပေးပြီးပါပြီ`);
          }
        }
      } else {
        await User.findByIdAndUpdate(user._id,{ firstName:tgUser.first_name||user.firstName, lastName:tgUser.last_name||user.lastName, username:tgUser.username||user.username, lastSeen:new Date() });
      }
      if (user.isBanned) return ctx.reply(`🚫 Account ပိတ်ထားပါသည်\nအကြောင်း: ${user.banReason}`);

      await ctx.reply(
        `👋 မင်္ဂလာပါ ${tgUser.first_name}!\n\nKBZPay Mini App သို့ ကြိုဆိုပါသည်\nမိတ်ဆွေများကို ဖိတ်ကြားပြီး ငွေရှာပါ 💰`,
        { reply_markup:{ inline_keyboard:[[
          { text:'💰 App ဖွင့်မည်', web_app:{ url: process.env.MINI_APP_URL||FRONTEND_URL } },
        ]]}},
      );
    } catch (err) { console.error('Bot start error:', err); }
  });

  // ── Admin commands ─────────────────────────────────────────────────────────
  bot.command('admin', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    await ctx.reply(
      `🛠 <b>Admin Commands</b>\n\n` +
      `/ban [id] [reason]\n/unban [id]\n/addmoney [id] [amount]\n/reducemoney [id] [amount]\n/addrefs [id] [count]\n/userinfo [id]\n/stats`,
      { parse_mode:'HTML' }
    );
  });

  bot.command('ban', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const parts = ctx.message.text.split(' ');
    const tid = parts[1]; const reason = parts.slice(2).join(' ') || 'Violated terms';
    if (!tid) return ctx.reply('Usage: /ban [telegramId] [reason]');
    const u = await User.findOneAndUpdate({ telegramId:tid },{ isBanned:true, banReason:reason },{ new:true }).catch(()=>null);
    if (!u) return ctx.reply(`❌ User ${tid} not found`);
    await sendTg(tid, `🚫 Account ပိတ်ထားပါသည်\nအကြောင်း: ${reason}`);
    ctx.reply(`✅ Banned: ${u.displayName}`);
  });

  bot.command('unban', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const tid = ctx.message.text.split(' ')[1];
    if (!tid) return ctx.reply('Usage: /unban [telegramId]');
    const u = await User.findOneAndUpdate({ telegramId:tid },{ isBanned:false, banReason:'' },{ new:true }).catch(()=>null);
    if (!u) return ctx.reply(`❌ User ${tid} not found`);
    await sendTg(tid, `✅ Account ပြန်ဖွင့်ပေးပြီးပါပြီ`);
    ctx.reply(`✅ Unbanned: ${u.displayName}`);
  });

  bot.command('addmoney', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [,tid,amtStr] = ctx.message.text.split(' ');
    if (!tid||!amtStr) return ctx.reply('Usage: /addmoney [id] [amount]');
    const amt = parseInt(amtStr);
    const u = await User.findOneAndUpdate({ telegramId:tid },{ $inc:{ balance:amt, totalEarned:amt } },{ new:true }).catch(()=>null);
    if (!u) return ctx.reply(`❌ Not found`);
    await sendTg(tid, `💰 Admin မှ ${amt.toLocaleString()} Ks ထည့်ပေးပါပြီ\nလက်ကျန်: ${u.balance.toLocaleString()} Ks`);
    ctx.reply(`✅ Added ${amt.toLocaleString()} Ks to ${u.displayName}\nNew balance: ${u.balance.toLocaleString()} Ks`);
  });

  bot.command('reducemoney', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [,tid,amtStr] = ctx.message.text.split(' ');
    if (!tid||!amtStr) return ctx.reply('Usage: /reducemoney [id] [amount]');
    const amt = parseInt(amtStr);
    const u = await User.findOne({ telegramId:tid }).catch(()=>null);
    if (!u) return ctx.reply(`❌ Not found`);
    if (u.balance < amt) return ctx.reply(`❌ Insufficient balance (${u.balance.toLocaleString()} Ks)`);
    await User.findByIdAndUpdate(u._id,{ $inc:{ balance:-amt } });
    ctx.reply(`✅ Reduced ${amt.toLocaleString()} Ks from ${u.displayName}`);
  });

  bot.command('addrefs', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [,tid,countStr] = ctx.message.text.split(' ');
    if (!tid||!countStr) return ctx.reply('Usage: /addrefs [id] [count]');
    const count = parseInt(countStr); const bonus = count * REFERRAL_BONUS;
    const u = await User.findOneAndUpdate({ telegramId:tid },{ $inc:{ referrals:count, balance:bonus, totalEarned:bonus } },{ new:true }).catch(()=>null);
    if (!u) return ctx.reply(`❌ Not found`);
    ctx.reply(`✅ Added ${count} refs (+${bonus.toLocaleString()} Ks) to ${u.displayName}`);
  });

  bot.command('userinfo', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const tid = ctx.message.text.split(' ')[1];
    if (!tid) return ctx.reply('Usage: /userinfo [telegramId]');
    const u = await User.findOne({ telegramId:tid }).catch(()=>null);
    if (!u) return ctx.reply(`❌ Not found`);
    ctx.reply(
      `👤 <b>User Info</b>\nName: ${u.displayName}\nUsername: @${u.username||'N/A'}\nID: ${u.telegramId}\n` +
      `Balance: ${u.balance.toLocaleString()} Ks\nReferrals: ${u.referrals}\nTotal Earned: ${u.totalEarned.toLocaleString()} Ks\n` +
      `Total Withdrawn: ${u.totalWithdrawn.toLocaleString()} Ks\nBanned: ${u.isBanned?'🚫 Yes':'✅ No'}\nJoined: ${u.createdAt.toLocaleDateString()}`,
      { parse_mode:'HTML' }
    );
  });

  bot.command('stats', async ctx => {
    if (String(ctx.chat.id) !== ADMIN_ID) return;
    const [total,banned,pending] = await Promise.all([
      User.countDocuments(), User.countDocuments({isBanned:true}),
      Withdrawal.countDocuments({status:'pending'}),
    ]);
    const balRes = await User.aggregate([{$group:{_id:null,total:{$sum:'$balance'}}}]);
    ctx.reply(
      `📊 <b>App Stats</b>\n\n👥 Total Users: ${total}\n🚫 Banned: ${banned}\n⏳ Pending Withdrawals: ${pending}\n💰 Total Balance: ${(balRes[0]?.total||0).toLocaleString()} Ks`,
      { parse_mode:'HTML' }
    );
  });

  // ── Support: user messages forwarded to admin ──────────────────────────────
  bot.on(message('text'), async ctx => {
    const chatId = String(ctx.chat.id);
    if (ctx.message.text.startsWith('/')) return;

    // Admin is replying to a pending reply or rejection
    if (chatId === ADMIN_ID) {
      // Support reply pending?
      if (pendingReplies[ADMIN_ID]) {
        const targetId = pendingReplies[ADMIN_ID];
        delete pendingReplies[ADMIN_ID];
        await sendTg(targetId, `📩 <b>Admin ထံမှ ပြန်စာ:</b>\n\n${ctx.message.text}`);
        await SupportMsg.create({ telegramId:targetId, displayName:'Admin', text:ctx.message.text, direction:'admin_to_user' }).catch(()=>{});
        return ctx.reply(`✅ Reply sent to ${targetId}`);
      }
      // Rejection reason pending?
      if (pendingRejections[ADMIN_ID]) {
        const wdId = pendingRejections[ADMIN_ID];
        delete pendingRejections[ADMIN_ID];
        const reason = ctx.message.text;
        const wd = await Withdrawal.findById(wdId).populate('user').catch(()=>null);
        if (wd && wd.status==='pending') {
          wd.status='rejected'; wd.rejectionReason=reason; wd.reviewedAt=new Date(); await wd.save();
          await User.findByIdAndUpdate(wd.user._id,{ $inc:{ balance:wd.amount+wd.fee } });
          await sendTg(wd.telegramId, `❌ <b>ငွေထုတ်ယူမှု ငြင်းပယ်ပါသည်</b>\n\nအကြောင်းပြချက်: ${reason}\n\n💰 ${(wd.amount+wd.fee).toLocaleString()} Ks ပြန်ထည့်ပေးပြီးပါပြီ`);
          return ctx.reply(`✅ Rejected & refunded for ${wd.telegramId}`);
        }
        return ctx.reply('❌ Withdrawal not found or already processed');
      }
      return; // Admin messages not forwarded
    }

    // Regular user message → forward to admin
    const u = await User.findOne({ telegramId:chatId }).catch(()=>null);
    if (!u || u.isBanned) return;

    await SupportMsg.create({ telegramId:chatId, displayName:u.displayName, text:ctx.message.text, direction:'user_to_admin' }).catch(()=>{});

    if (ADMIN_ID) {
      await sendTg(ADMIN_ID,
        `📨 <b>Support Message</b>\n👤 ${u.displayName} (@${u.username||'N/A'})\n🆔 <code>${chatId}</code>\n\n💬 ${ctx.message.text}`,
        { reply_markup:{ inline_keyboard:[[{ text:'↩️ Reply', callback_data:`reply_${chatId}` }]] }},
      );
    }
    await ctx.reply('✅ မက်ဆေ့ကို Admin ထံ ပေးပို့ပြီးပါပြီ။ မကြာမီ ပြန်လည်ဖြေကြားပါမည်။');
  });

  // ── Callback queries ───────────────────────────────────────────────────────
  bot.on('callback_query', async ctx => {
    const adminId = String(ctx.from.id);
    if (adminId !== ADMIN_ID) return ctx.answerCbQuery('⛔ Unauthorized');
    const data = ctx.callbackQuery.data;

    // Support reply
    if (data.startsWith('reply_')) {
      pendingReplies[ADMIN_ID] = data.replace('reply_','');
      await ctx.answerCbQuery('📝 Type your reply now');
      return ctx.reply(`✏️ Now send your reply to user ${pendingReplies[ADMIN_ID]}:`);
    }

    // Withdrawal approve
    if (data.startsWith('wd_approve_')) {
      const wdId = data.replace('wd_approve_','');
      const wd = await Withdrawal.findById(wdId).populate('user').catch(()=>null);
      if (!wd || wd.status!=='pending') return ctx.answerCbQuery('⚠️ Already processed');
      wd.status='approved'; wd.reviewedAt=new Date(); await wd.save();
      await User.findByIdAndUpdate(wd.user._id,{ $inc:{ totalWithdrawn:wd.netAmount } });
      await ctx.answerCbQuery('✅ Approved!');
      await ctx.editMessageReplyMarkup({ inline_keyboard:[] }).catch(()=>{});
      await sendTg(wd.telegramId, `✅ <b>ငွေထုတ်ယူမှု အတည်ပြုပြီးပါပြီ!</b>\n💰 ${wd.netAmount.toLocaleString()} Ks ကို မကြာမီ ပေးပို့ပါမည်`);
      return ctx.reply(`✅ Approved withdrawal for ${wd.user.displayName}`);
    }

    // Withdrawal reject (step 1)
    if (data.startsWith('wd_reject_')) {
      pendingRejections[ADMIN_ID] = data.replace('wd_reject_','');
      await ctx.answerCbQuery('✏️ Send rejection reason');
      await ctx.editMessageReplyMarkup({ inline_keyboard:[] }).catch(()=>{});
      return ctx.reply(`📝 Please type the rejection reason for withdrawal ${pendingRejections[ADMIN_ID]}:`);
    }

    ctx.answerCbQuery();
  });

  bot.launch({ dropPendingUpdates:true })
    .then(() => console.log('🤖 Telegraf bot started'))
    .catch(err => console.error('Bot launch error:', err));

  // Graceful stop
  process.once('SIGINT',  () => bot.stop('SIGINT'));
  process.once('SIGTERM', () => bot.stop('SIGTERM'));
};

// ═══════════════════════════════════════════════
//  STARTUP
// ═══════════════════════════════════════════════
(async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS:10000 });
    console.log('✅ MongoDB connected');
    initBot();
    app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
  } catch (err) {
    console.error('❌ Startup failed:', err);
    process.exit(1);
  }
})();
