// import express from 'express';
// import mongoose from 'mongoose';
// import bcrypt from 'bcryptjs';
// import jwt from 'jsonwebtoken';
// import Joi from 'joi';
// import nodemailer from 'nodemailer';
// import winston from 'winston';
// import 'winston-mongodb';
// import { randomBytes } from 'crypto';
// import dotenv from 'dotenv';

// dotenv.config();

// const app = express();
// app.use(express.json());

// // MongoDB ulanishi
// mongoose.connect(process.env.MONGO_URI)
//   .then(() => console.log('MongoDB ulandi'))
//   .catch(err => console.error('MongoDB ulanish xatosi:', err));

// // Winston Logger sozlamalari
// const logger = winston.createLogger({
//   level: 'info',
//   format: winston.format.combine(
//     winston.format.timestamp(),
//     winston.format.json()
//   ),
//   transports: [
//     new winston.transports.File({ filename: 'combined.log', level: 'info' }),
//     new winston.transports.MongoDB({ db: process.env.MONGO_URI, collection: 'logs_all', level: 'info' }),
//     new winston.transports.File({ filename: 'warn.log', level: 'warn' }),
//     new winston.transports.MongoDB({ db: process.env.MONGO_URI, collection: 'logs_warn', level: 'warn' }),
//     new winston.transports.File({ filename: 'error.log', level: 'error' }),
//     new winston.transports.MongoDB({ db: process.env.MONGO_URI, collection: 'logs_error', level: 'error' })
//   ]
// });

// // Modellar
// const userSchema = new mongoose.Schema({
//   username: { type: String, required: true, unique: true },
//   email: { type: String, required: true, unique: true },
//   password: { type: String, required: true },
//   role: { type: String, enum: ['user', 'admin'], default: 'user' },
//   isVerified: { type: Boolean, default: false },
//   verificationToken: String,
//   resetToken: String,
//   resetTokenExpiry: Date,
//   refreshToken: String
// });
// const User = mongoose.model('User', userSchema);

// const categorySchema = new mongoose.Schema({
//   name: { type: String, required: true },
//   createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
// });
// const Category = mongoose.model('Category', categorySchema);

// const machineSchema = new mongoose.Schema({
//   name: { type: String, required: true },
//   category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
//   createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
// });
// const Machine = mongoose.model('Machine', machineSchema);

// // Nodemailer sozlamasi
// const transporter = nodemailer.createTransport({
//   service: 'gmail',
//   auth: {
//     user: process.env.EMAIL_USER,
//     pass: process.env.EMAIL_PASS
//   }
// });

// // JWT funksiyalari
// const generateAccessToken = (user) => jwt.sign({ id: user._id, role: user.role }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
// const generateRefreshToken = (user) => jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

// // Token qora ro'yxati
// const tokenBlacklist = new Set();

// // Autentifikatsiya middleware
// const authMiddleware = (req, res, next) => {
//   const token = req.headers.authorization?.split(' ')[1];
//   if (!token) return res.status(401).json({ message: 'Token taqdim etilmadi' });
//   if (tokenBlacklist.has(token)) return res.status(401).json({ message: 'Token yaroqsiz' });

//   try {
//     const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
//     req.user = decoded;
//     next();
//   } catch (err) {
//     logger.error(`Yaroqsiz token: ${err.message}`);
//     res.status(401).json({ message: 'Yaroqsiz token' });
//   }
// };

// // Admin middleware
// const adminMiddleware = (req, res, next) => {
//   if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin ruxsati talab qilinadi' });
//   next();
// };

// // Joi sxemalari
// const registerSchema = Joi.object({
//   username: Joi.string().min(3).max(30).required(),
//   email: Joi.string().email().required(),
//   password: Joi.string().min(6).required().pattern(new RegExp('^[a-zA-Z0-9]{6,30}$'))
// });

// const loginSchema = Joi.object({
//   email: Joi.string().email().required(),
//   password: Joi.string().required()
// });

// const forgotSchema = Joi.object({
//   email: Joi.string().email().required()
// });

// const resetSchema = Joi.object({
//   token: Joi.string().required(),
//   password: Joi.string().min(6).required().pattern(new RegExp('^[a-zA-Z0-9]{6,30}$'))
// });

// const changePasswordSchema = Joi.object({
//   oldPassword: Joi.string().required(),
//   newPassword: Joi.string().min(6).required().pattern(new RegExp('^[a-zA-Z0-9]{6,30}$'))
// });

// const categorySchemaJoi = Joi.object({
//   name: Joi.string().min(3).max(50).required()
// });

// const machineSchemaJoi = Joi.object({
//   name: Joi.string().min(3).max(50).required(),
//   category: Joi.string().required()
// });

// // Validatsiya middleware
// const validate = (schema) => (req, res, next) => {
//   const { error } = schema.validate(req.body);
//   if (error) {
//     logger.warn(`Validatsiya xatosi: ${error.details[0].message}`);
//     return res.status(400).json({ message: error.details[0].message });
//   }
//   next();
// };

// // Yo'nalishlar (Routes)

// // Ro'yxatdan o'tish
// app.post('/register', validate(registerSchema), async (req, res, next) => {
//   try {
//     const { username, email, password } = req.body;
//     const existingUser = await User.findOne({ email });
//     if (existingUser) return res.status(400).json({ message: 'Foydalanuvchi mavjud' });

//     const hashedPassword = await bcrypt.hash(password, 10);
//     const verificationToken = randomBytes(32).toString('hex');
//     const user = new User({ username, email, password: hashedPassword, verificationToken });
//     await user.save();

//     const verifyUrl = `${process.env.BASE_URL}/verify/${verificationToken}`;
//     await transporter.sendMail({
//       to: email,
//       subject: 'Emailni tasdiqlash',
//       html: `Tasdiqlash uchun <a href="${verifyUrl}">bu yerga</a> bosing.`
//     });

//     logger.info(`Foydalanuvchi ro'yxatdan o'tdi: ${email}`);
//     res.status(201).json({ message: 'Royxatdan otildi. Emailingizni tasdiqlang.' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Email tasdiqlash
// app.get('/verify/:token', async (req, res, next) => {
//   try {
//     const user = await User.findOne({ verificationToken: req.params.token });
//     if (!user) return res.status(400).json({ message: 'Notogri token' });

//     user.isVerified = true;
//     user.verificationToken = undefined;
//     await user.save();

//     logger.info(`Foydalanuvchi tasdiqlandi: ${user.email}`);
//     res.json({ message: 'Email tasdiqlandi' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Tizimga kirish
// app.post('/login', validate(loginSchema), async (req, res, next) => {
//   try {
//     const { email, password } = req.body;
//     const user = await User.findOne({ email });
//     if (!user || !user.isVerified) return res.status(400).json({ message: 'Notogri malumotlar yoki tasdiqlanmagan' });

//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) return res.status(400).json({ message: 'Notogri malumotlar' });

//     const accessToken = generateAccessToken(user);
//     const refreshToken = generateRefreshToken(user);
//     user.refreshToken = refreshToken;
//     await user.save();

//     logger.info(`Foydalanuvchi tizimga kirdi: ${email}`);
//     res.json({ accessToken, refreshToken });
//   } catch (err) {
//     next(err);
//   }
// });

// // Token yangilash
// app.post('/refresh', async (req, res, next) => {
//   const { refreshToken } = req.body;
//   if (!refreshToken) return res.status(401).json({ message: 'Yangilash tokeni yoq' });

//   try {
//     const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
//     const user = await User.findById(decoded.id);
//     if (!user || user.refreshToken !== refreshToken) return res.status(401).json({ message: 'Notogri yangilash tokeni' });

//     const accessToken = generateAccessToken(user);
//     logger.info(`Token yangilandi: ${user.email}`);
//     res.json({ accessToken });
//   } catch (err) {
//     next(err);
//   }
// });

// // Chiqish
// app.post('/logout', authMiddleware, async (req, res, next) => {
//   try {
//     const token = req.headers.authorization.split(' ')[1];
//     tokenBlacklist.add(token);

//     const user = await User.findById(req.user.id);
//     user.refreshToken = undefined;
//     await user.save();

//     logger.info(`Foydalanuvchi chiqdi: ${user.email}`);
//     res.json({ message: 'Tizimdan chiqildi' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Parolni unutganlar uchun
// app.post('/forgot-password', validate(forgotSchema), async (req, res, next) => {
//   try {
//     const { email } = req.body;
//     const user = await User.findOne({ email });
//     if (!user) return res.status(400).json({ message: 'Foydalanuvchi topilmadi' });

//     const resetToken = randomBytes(32).toString('hex');
//     user.resetToken = resetToken;
//     user.resetTokenExpiry = Date.now() + 3600000; // 1 soat
//     await user.save();

//     const resetUrl = `${process.env.BASE_URL}/reset-password/${resetToken}`;
//     await transporter.sendMail({
//       to: email,
//       subject: 'Parolni tiklash',
//       html: `Parolni tiklash uchun <a href="${resetUrl}">bu yerga</a> bosing.`
//     });

//     logger.info(`Parol tiklash so'rovi: ${email}`);
//     res.json({ message: 'Tiklash havolasi yuborildi' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Parolni tiklash
// app.post('/reset-password/:token', validate(resetSchema), async (req, res, next) => {
//   try {
//     const { token } = req.params;
//     const { password } = req.body;
//     const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
//     if (!user) return res.status(400).json({ message: 'Notogri yoki muddati otgan token' });

//     user.password = await bcrypt.hash(password, 10);
//     user.resetToken = undefined;
//     user.resetTokenExpiry = undefined;
//     await user.save();

//     logger.info(`Parol tiklandi: ${user.email}`);
//     res.json({ message: 'Parol tiklandi' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Parolni o'zgartirish
// app.post('/change-password', authMiddleware, validate(changePasswordSchema), async (req, res, next) => {
//   try {
//     const { oldPassword, newPassword } = req.body;
//     const user = await User.findById(req.user.id);
//     const isMatch = await bcrypt.compare(oldPassword, user.password);
//     if (!isMatch) return res.status(400).json({ message: 'Eski parol notogri' });

//     user.password = await bcrypt.hash(newPassword, 10);
//     await user.save();

//     logger.info(`Parol o'zgartirildi: ${user.email}`);
//     res.json({ message: 'Parol ozgartirildi' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Profil
// app.get('/profile', authMiddleware, async (req, res, next) => {
//   try {
//     const user = await User.findById(req.user.id).select('-password -verificationToken -resetToken -resetTokenExpiry -refreshToken');
//     let adminData = {};
//     if (req.user.role === 'admin') {
//       const categories = await Category.find({ createdBy: req.user.id });
//       const machines = await Machine.find({ createdBy: req.user.id }).populate('category');
//       adminData = { categories, machines };
//     }

//     logger.info(`Profil ko'rildi: ${user.email}`);
//     res.json({ user, ...adminData });
//   } catch (err) {
//     next(err);
//   }
// });

// // Kategoriyalar CRUD
// app.get('/categories', authMiddleware, async (req, res, next) => {
//   try {
//     const categories = await Category.find();
//     res.json(categories);
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/categories', authMiddleware, adminMiddleware, validate(categorySchemaJoi), async (req, res, next) => {
//   try {
//     const category = new Category({ ...req.body, createdBy: req.user.id });
//     await category.save();
//     logger.info(`Kategoriya qo'shildi: ${req.user.id}`);
//     res.status(201).json(category);
//   } catch (err) {
//     next(err);
//   }
// });

// app.put('/categories/:id', authMiddleware, adminMiddleware, validate(categorySchemaJoi), async (req, res, next) => {
//   try {
//     const category = await Category.findByIdAndUpdate(req.params.id, req.body, { new: true });
//     if (!category) return res.status(404).json({ message: 'Kategoriya topilmadi' });
//     logger.info(`Kategoriya o'zgartirildi: ${req.user.id}`);
//     res.json(category);
//   } catch (err) {
//     next(err);
//   }
// });

// app.delete('/categories/:id', authMiddleware, adminMiddleware, async (req, res, next) => {
//   try {
//     const category = await Category.findByIdAndDelete(req.params.id);
//     if (!category) return res.status(404).json({ message: 'Kategoriya topilmadi' });
//     logger.info(`Kategoriya o'chirildi: ${req.user.id}`);
//     res.json({ message: 'O\'chirildi' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Mashinalar CRUD
// app.get('/machines', authMiddleware, async (req, res, next) => {
//   try {
//     const machines = await Machine.find().populate('category');
//     res.json(machines);
//   } catch (err) {
//     next(err);
//   }
// });

// app.post('/machines', authMiddleware, adminMiddleware, validate(machineSchemaJoi), async (req, res, next) => {
//   try {
//     const machine = new Machine({ ...req.body, createdBy: req.user.id });
//     await machine.save();
//     logger.info(`Mashina qo'shildi: ${req.user.id}`);
//     res.status(201).json(machine);
//   } catch (err) {
//     next(err);
//   }
// });

// app.put('/machines/:id', authMiddleware, adminMiddleware, validate(machineSchemaJoi), async (req, res, next) => {
//   try {
//     const machine = await Machine.findByIdAndUpdate(req.params.id, req.body, { new: true });
//     if (!machine) return res.status(404).json({ message: 'Mashina topilmadi' });
//     logger.info(`Mashina o'zgartirildi: ${req.user.id}`);
//     res.json(machine);
//   } catch (err) {
//     next(err);
//   }
// });

// app.delete('/machines/:id', authMiddleware, adminMiddleware, async (req, res, next) => {
//   try {
//     const machine = await Machine.findByIdAndDelete(req.params.id);
//     if (!machine) return res.status(404).json({ message: 'Mashina topilmadi' });
//     logger.info(`Mashina o'chirildi: ${req.user.id}`);
//     res.json({ message: 'O\'chirildi' });
//   } catch (err) {
//     next(err);
//   }
// });

// // Global xato ishlov beruvchi
// app.use((err, req, res, next) => {
//   logger.error(`Xato: ${err.message} | Stack: ${err.stack}`);
//   res.status(500).json({ message: 'Server xatosi', error: err.message });
// });

// app.listen(process.env.PORT, () => {
//   console.log(`Server ${process.env.PORT} portda ishlamoqda`);
// });
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Joi from 'joi';
import nodemailer from 'nodemailer';
import winston from 'winston';
import 'winston-mongodb';
import { randomBytes } from 'crypto';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Form ma'lumotlari uchun
app.set('view engine', 'ejs'); // EJS templating engine
app.set('views', path.join(__dirname, 'views')); // EJS fayllari joylashuvi
app.use(express.static(path.join(__dirname, 'public'))); // Statik fayllar (CSS, JS)

// MongoDB ulanishi
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB ulandi'))
  .catch(err => console.error('MongoDB ulanish xatosi:', err));

// Winston Logger sozlamalari
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'combined.log', level: 'info' }),
    new winston.transports.MongoDB({ db: process.env.MONGO_URI, collection: 'logs_all', level: 'info' }),
    new winston.transports.File({ filename: 'warn.log', level: 'warn' }),
    new winston.transports.MongoDB({ db: process.env.MONGO_URI, collection: 'logs_warn', level: 'warn' }),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.MongoDB({ db: process.env.MONGO_URI, collection: 'logs_error', level: 'error' })
  ]
});

// Modellar
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  resetToken: String,
  resetTokenExpiry: Date,
  refreshToken: String
});
const User = mongoose.model('User', userSchema);

const categorySchema = new mongoose.Schema({
  name: { type: String, required: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});
const Category = mongoose.model('Category', categorySchema);

const machineSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});
const Machine = mongoose.model('Machine', machineSchema);

// Nodemailer sozlamasi
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// JWT funksiyalari
const generateAccessToken = (user) => jwt.sign({ id: user._id, role: user.role }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
const generateRefreshToken = (user) => jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

// Token qora ro'yxati
const tokenBlacklist = new Set();

// Autentifikatsiya middleware
const authMiddleware = async (req, res, next) => {
  const token = req.cookies.accessToken || req.headers.authorization?.split(' ')[1];
  if (!token) return res.redirect('/login');

  if (tokenBlacklist.has(token)) return res.redirect('/login');

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    logger.error(`Yaroqsiz token: ${err.message}`);
    res.redirect('/login');
  }
};

// Admin middleware
const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') return res.render('error', { message: 'Admin ruxsati talab qilinadi' });
  next();
};

// Joi sxemalari
const registerSchema = Joi.object({
  username: Joi.string().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required().pattern(new RegExp('^[a-zA-Z0-9]{6,30}$'))
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

const forgotSchema = Joi.object({
  email: Joi.string().email().required()
});

const resetSchema = Joi.object({
  password: Joi.string().min(6).required().pattern(new RegExp('^[a-zA-Z0-9]{6,30}$'))
});

const changePasswordSchema = Joi.object({
  oldPassword: Joi.string().required(),
  newPassword: Joi.string().min(6).required().pattern(new RegExp('^[a-zA-Z0-9]{6,30}$'))
});

const categorySchemaJoi = Joi.object({
  name: Joi.string().min(3).max(50).required()
});

const machineSchemaJoi = Joi.object({
  name: Joi.string().min(3).max(50).required(),
  category: Joi.string().required()
});

// Validatsiya middleware
const validate = (schema) => (req, res, next) => {
  const { error } = schema.validate(req.body);
  if (error) {
    logger.warn(`Validatsiya xatosi: ${error.details[0].message}`);
    return res.render('error', { message: error.details[0].message });
  }
  next();
};

// Yo'nalishlar (Routes)

// Ro'yxatdan o'tish
app.get('/register', (req, res) => res.render('register', { error: null, success: null }));
app.post('/register', validate(registerSchema), async (req, res, next) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.render('register', { error: 'Foydalanuvchi mavjud', success: null });

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = randomBytes(32).toString('hex');
    const user = new User({ username, email, password: hashedPassword, verificationToken });
    await user.save();

    const verifyUrl = `${process.env.BASE_URL}/verify/${verificationToken}`;
    await transporter.sendMail({
      to: email,
      subject: 'Emailni tasdiqlash',
      html: `Tasdiqlash uchun <a href="${verifyUrl}">bu yerga</a> bosing.`
    });

    logger.info(`Foydalanuvchi ro'yxatdan o'tdi: ${email}`);
    res.render('register', { error: null, success: 'Ro\'yxatdan o\'tdingiz. Emailingizni tasdiqlang.' });
  } catch (err) {
    next(err);
  }
});

// Email tasdiqlash
app.get('/verify/:token', async (req, res, next) => {
  try {
    const user = await User.findOne({ verificationToken: req.params.token });
    if (!user) return res.render('error', { message: 'Noto\'g\'ri token' });

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    logger.info(`Foydalanuvchi tasdiqlandi: ${user.email}`);
    res.render('error', { message: 'Email tasdiqlandi. Tizimga kiring.' });
  } catch (err) {
    next(err);
  }
});

// Tizimga kirish
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', validate(loginSchema), async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !user.isVerified) return res.render('login', { error: 'Noto\'g\'ri ma\'lumotlar yoki tasdiqlanmagan' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.render('login', { error: 'Noto\'g\'ri ma\'lumotlar' });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    user.refreshToken = refreshToken;
    await user.save();

    res.cookie('accessToken', accessToken, { httpOnly: true });
    res.cookie('refreshToken', refreshToken, { httpOnly: true });

    logger.info(`Foydalanuvchi tizimga kirdi: ${email}`);
    res.redirect('/profile');
  } catch (err) {
    next(err);
  }
});

// Token yangilash
app.post('/refresh', async (req, res, next) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken) return res.redirect('/login');

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || user.refreshToken !== refreshToken) return res.redirect('/login');

    const accessToken = generateAccessToken(user);
    res.cookie('accessToken', accessToken, { httpOnly: true });
    logger.info(`Token yangilandi: ${user.email}`);
    res.redirect(req.get('referer') || '/profile');
  } catch (err) {
    next(err);
  }
});

// Chiqish
app.post('/logout', authMiddleware, async (req, res, next) => {
  try {
    const token = req.cookies.accessToken;
    tokenBlacklist.add(token);

    const user = await User.findById(req.user.id);
    user.refreshToken = undefined;
    await user.save();

    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    logger.info(`Foydalanuvchi chiqdi: ${user.email}`);
    res.redirect('/login');
  } catch (err) {
    next(err);
  }
});

// Parolni unutganlar uchun
app.get('/forgot-password', (req, res) => res.render('forgot-password', { error: null, success: null }));
app.post('/forgot-password', validate(forgotSchema), async (req, res, next) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.render('forgot-password', { error: 'Foydalanuvchi topilmadi', success: null });

    const resetToken = randomBytes(32).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000; // 1 soat
    await user.save();

    const resetUrl = `${process.env.BASE_URL}/reset-password/${resetToken}`;
    await transporter.sendMail({
      to: email,
      subject: 'Parolni tiklash',
      html: `Parolni tiklash uchun <a href="${resetUrl}">bu yerga</a> bosing.`
    });

    logger.info(`Parol tiklash so'rovi: ${email}`);
    res.render('forgot-password', { error: null, success: 'Tiklash havolasi emailingizga yuborildi.' });
  } catch (err) {
    next(err);
  }
});

// Parolni tiklash
app.get('/reset-password/:token', (req, res) => res.render('reset-password', { token: req.params.token, error: null, success: null }));
app.post('/reset-password/:token', validate(resetSchema), async (req, res, next) => {
  try {
    const { token } = req.params;
    const { password } = req.body;
    const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
    if (!user) return res.render('reset-password', { token, error: 'Noto\'g\'ri yoki muddati o\'tgan token', success: null });

    user.password = await bcrypt.hash(password, 10);
    user.resetToken = undefined;
    user

.resetTokenExpiry = undefined;
    await user.save();

    logger.info(`Parol tiklandi: ${user.email}`);
    res.render('reset-password', { token, error: null, success: 'Parol tiklandi. Tizimga kiring.' });
  } catch (err) {
    next(err);
  }
});

// Parolni o'zgartirish
app.post('/change-password', authMiddleware, validate(changePasswordSchema), async (req, res, next) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user = await User.findById(req.user.id);
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return res.render('profile', { user, error: 'Eski parol noto\'g\'ri', success: null });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    logger.info(`Parol o'zgartirildi: ${user.email}`);
    res.render('profile', { user, error: null, success: 'Parol o\'zgartirildi' });
  } catch (err) {
    next(err);
  }
});

// Profil
app.get('/profile', authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select('-password -verificationToken -resetToken -resetTokenExpiry -refreshToken');
    let adminData = {};
    if (req.user.role === 'admin') {
      const categories = await Category.find({ createdBy: req.user.id });
      const machines = await Machine.find({ createdBy: req.user.id }).populate('category');
      adminData = { categories, machines };
    }

    logger.info(`Profil ko'rildi: ${user.email}`);
    res.render('profile', { user, ...adminData, error: null, success: null });
  } catch (err) {
    next(err);
  }
});

// Kategoriyalar CRUD
app.get('/categories', authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    const categories = await Category.find();
    res.render('categories', { categories, isAdmin: user.role === 'admin', error: null });
  } catch (err) {
    next(err);
  }
});

app.post('/categories', authMiddleware, adminMiddleware, validate(categorySchemaJoi), async (req, res, next) => {
  try {
    const category = new Category({ ...req.body, createdBy: req.user.id });
    await category.save();
    logger.info(`Kategoriya qo'shildi: ${req.user.id}`);
    res.redirect('/categories');
  } catch (err) {
    next(err);
  }
});

app.post('/categories/:id/edit', authMiddleware, adminMiddleware, validate(categorySchemaJoi), async (req, res, next) => {
  try {
    const category = await Category.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!category) return res.render('categories', { categories: await Category.find(), isAdmin: true, error: 'Kategoriya topilmadi' });
    logger.info(`Kategoriya o'zgartirildi: ${req.user.id}`);
    res.redirect('/categories');
  } catch (err) {
    next(err);
  }
});

app.post('/categories/:id/delete', authMiddleware, adminMiddleware, async (req, res, next) => {
  try {
    const category = await Category.findByIdAndDelete(req.params.id);
    if (!category) return res.render('categories', { categories: await Category.find(), isAdmin: true, error: 'Kategoriya topilmadi' });
    logger.info(`Kategoriya o'chirildi: ${req.user.id}`);
    res.redirect('/categories');
  } catch (err) {
    next(err);
  }
});

// Mashinalar CRUD
app.get('/machines', authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    const categories = await Category.find();
    const machines = await Machine.find().populate('category');
    res.render('machines', { machines, categories, isAdmin: user.role === 'admin', error: null });
  } catch (err) {
    next(err);
  }
});

app.post('/machines', authMiddleware, adminMiddleware, validate(machineSchemaJoi), async (req, res, next) => {
  try {
    const machine = new Machine({ ...req.body, createdBy: req.user.id });
    await machine.save();
    logger.info(`Mashina qo'shildi: ${req.user.id}`);
    res.redirect('/machines');
  } catch (err) {
    next(err);
  }
});

app.post('/machines/:id/edit', authMiddleware, adminMiddleware, validate(machineSchemaJoi), async (req, res, next) => {
  try {
    const machine = await Machine.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!machine) return res.render('machines', { machines: await Machine.find().populate('category'), categories: await Category.find(), isAdmin: true, error: 'Mashina topilmadi' });
    logger.info(`Mashina o'zgartirildi: ${req.user.id}`);
    res.redirect('/machines');
  } catch (err) {
    next(err);
  }
});

app.post('/machines/:id/delete', authMiddleware, adminMiddleware, async (req, res, next) => {
  try {
    const machine = await Machine.findByIdAndDelete(req.params.id);
    if (!machine) return res.render('machines', { machines: await Machine.find().populate('category'), categories: await Category.find(), isAdmin: true, error: 'Mashina topilmadi' });
    logger.info(`Mashina o'chirildi: ${req.user.id}`);
    res.redirect('/machines');
  } catch (err) {
    next(err);
  }
});

// Global xato ishlov beruvchi
app.use((err, req, res, next) => {
  logger.error(`Xato: ${err.message} | Stack: ${err.stack}`);
  res.render('error', { message: 'Server xatosi: ' + err.message });
});

app.listen(process.env.PORT, () => {
  console.log(`Server ${process.env.PORT} portda ishlamoqda`);
});