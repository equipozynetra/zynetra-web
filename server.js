require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración Email
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

async function sendOTPEmail(email, code, name) {
    const htmlContent = `
    <div style="background-color:#020617; color:#fff; padding:40px; font-family:sans-serif; text-align:center;">
        <h1 style="letter-spacing:3px; color:#fff;">ZYNETRA</h1>
        <div style="background:#1e293b; padding:20px; border-radius:10px; margin:30px auto; max-width:400px; border:1px solid #334155;">
            <h2 style="color:#6366f1; letter-spacing:5px; font-size:32px; margin:0;">${code}</h2>
        </div>
        <p>Hola ${name}, usa este código para verificar tu cuenta. Expira en 15 min.</p>
        <p style="color:#64748b; font-size:12px;">Si no fuiste tú, ignora este mensaje.</p>
    </div>`;
    
    try {
        await transporter.sendMail({ from: '"Zynetra Security"', to: email, subject: '🔐 Código de Verificación', html: htmlContent });
        console.log(`✅ Email enviado a ${email}`);
    } catch (e) {
        console.error("❌ FALLO ENVÍO EMAIL:", e.message);
        console.log(`🔑 CÓDIGO DE EMERGENCIA (Para Logs): [ ${code} ]`);
    }
}

// Limpieza automática
cron.schedule('* * * * *', () => {
    db.run(`DELETE FROM users WHERE is_verified = 0 AND otp_expires < ?`, [Date.now()], (err) => {
        if(!err && this.changes > 0) console.log("🧹 Limpieza completada.");
    });
});

// Configuración App
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.set('trust proxy', 1); 

// Rutas Estáticas (Solución CSS)
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));
app.use('/css', express.static(path.join(publicPath, 'css')));
app.use('/js', express.static(path.join(publicPath, 'js')));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'zynetra_secret', resave: false, saveUninitialized: false,
    cookie: { httpOnly: true, secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 100 });

// API Session
app.get('/api/session-status', (req, res) => {
    if (req.session.userId) {
        const isOwner = (req.session.email || '').toLowerCase() === 'equipozynetra@gmail.com';
        res.json({ loggedIn: true, name: req.session.userName, isOwner });
    } else {
        res.json({ loggedIn: false });
    }
});

// Rutas Vistas
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
app.get('/servicios', (req, res) => res.sendFile(path.join(publicPath, 'services.html')));
app.get('/desafios', (req, res) => res.sendFile(path.join(publicPath, 'challenges.html')));
app.get('/nosotros', (req, res) => res.sendFile(path.join(publicPath, 'about.html')));
app.get('/login', (req, res) => req.session.userId ? res.redirect('/dashboard') : res.sendFile(path.join(publicPath, 'auth.html')));
app.get('/verify-otp', (req, res) => res.sendFile(path.join(publicPath, 'verify.html')));
app.get('/loading', (req, res) => req.session.userId ? res.sendFile(path.join(publicPath, 'loading.html')) : res.redirect('/login'));
app.get('/dashboard', (req, res) => req.session.userId ? res.sendFile(path.join(publicPath, 'dashboard.html')) : res.redirect('/login'));
app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/'); });

// Registro (CORREGIDO PARA EVITAR BLOQUEO)
app.post('/register', authLimiter, [body('email').isEmail().normalizeEmail()], async (req, res) => {
    const { name, email, password, phone, company, role } = req.body;
    const cleanEmail = email.trim().toLowerCase();
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 15*60*1000;
    const hashed = await bcrypt.hash(password, 10);

    db.run(`INSERT INTO users (name, email, password, phone, company, role, is_verified, otp_code, otp_expires) VALUES (?,?,?,?,?,?,0,?,?)`, 
    [name, cleanEmail, hashed, phone, company, role, otp, expires], 
    async function(err) {
        if(err) {
            console.error("Error DB:", err.message);
            return res.redirect('/login?error=email_exists');
        }
        
        // Intentamos enviar email, pero NO bloqueamos si falla
        // El usuario será redirigido siempre.
        try {
            await sendOTPEmail(cleanEmail, otp, name);
        } catch (e) {
            console.error("Fallo crítico en email:", e);
        }
        
        res.redirect(`/verify-otp?email=${encodeURIComponent(cleanEmail)}`);
    });
});

// Verificación OTP
app.post('/verify-code', (req, res) => {
    const { email, otp } = req.body;
    const cleanEmail = email.trim().toLowerCase();
    
    db.get(`SELECT * FROM users WHERE email = ?`, [cleanEmail], (err, user) => {
        if(user && user.otp_code === otp && user.otp_expires > Date.now()) {
            db.run(`UPDATE users SET is_verified=1, otp_code=NULL WHERE id=?`, [user.id], () => {
                req.session.userId = user.id;
                req.session.userName = user.name;
                req.session.email = user.email;
                res.redirect('/loading');
            });
        } else {
            res.redirect(`/verify-otp?email=${cleanEmail}&error=invalid_code`);
        }
    });
});

// Login
app.post('/login', authLimiter, async (req, res) => {
    const { email, password, remember } = req.body;
    const cleanEmail = email.trim().toLowerCase();
    db.get(`SELECT * FROM users WHERE email = ?`, [cleanEmail], async (err, user) => {
        if(user && await bcrypt.compare(password, user.password)) {
            if(user.is_verified === 0) return res.redirect('/login?error=not_verified');
            if(remember === 'on') req.session.cookie.maxAge = 30*24*60*60*1000;
            req.session.userId = user.id;
            req.session.userName = user.name;
            req.session.email = user.email;
            res.redirect('/loading');
        } else {
            res.redirect('/login?error=invalid_credentials');
        }
    });
});

app.use((req, res) => res.status(404).sendFile(path.join(publicPath, '404.html')));
app.listen(PORT, () => console.log(`🚀 Corriendo en ${PORT}`));