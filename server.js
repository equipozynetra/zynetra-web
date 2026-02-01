require('dotenv').config(); // Cargar variables de entorno
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

// --- CONFIGURACIÓN EMAIL (GMAIL REAL) ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, // Lee del archivo .env o Render
        pass: process.env.EMAIL_PASS  // Lee del archivo .env o Render
    }
});

// Función para enviar HTML bonito
async function sendOTPEmail(email, code, name) {
    const htmlContent = `
    <!DOCTYPE html>
    <html>
    <body style="margin:0; padding:0; background-color:#020617; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
        <table width="100%" border="0" cellspacing="0" cellpadding="0">
            <tr>
                <td align="center" style="padding: 40px 0;">
                    <table width="600" border="0" cellspacing="0" cellpadding="0" style="background-color:#0f172a; border-radius:16px; overflow:hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5); border: 1px solid #1e293b;">
                        <!-- Header -->
                        <tr>
                            <td align="center" style="padding: 30px; background-color:#1e293b;">
                                <h1 style="color:#ffffff; margin:0; font-size:24px; letter-spacing: 2px;">ZYNETRA</h1>
                            </td>
                        </tr>
                        <!-- Body -->
                        <tr>
                            <td style="padding: 40px 30px; color:#cbd5e1; text-align:center;">
                                <h2 style="color:#6366f1; margin-top:0;">Verificación de Seguridad</h2>
                                <p style="font-size:16px; line-height:1.6;">Hola <strong>${name}</strong>,</p>
                                <p style="font-size:16px; line-height:1.6;">Gracias por confiar en Zynetra. Para activar tu cuenta corporativa y acceder al panel, introduce el siguiente código:</p>
                                
                                <div style="background: linear-gradient(135deg, #6366f1, #8b5cf6); padding: 2px; border-radius: 12px; display: inline-block; margin: 30px 0;">
                                    <div style="background-color:#020617; padding: 15px 40px; border-radius: 10px;">
                                        <span style="font-size: 36px; font-weight: 800; color: #ffffff; letter-spacing: 8px;">${code}</span>
                                    </div>
                                </div>

                                <p style="font-size:14px; color:#94a3b8;">Este código expirará en <strong>15 minutos</strong>.</p>
                            </td>
                        </tr>
                        <!-- Footer -->
                        <tr>
                            <td style="padding: 20px; background-color:#020617; text-align:center; font-size:12px; color:#64748b; border-top: 1px solid #1e293b;">
                                <p>&copy; 2023 Zynetra Digital Solutions. Todos los derechos reservados.</p>
                                <p>Si no solicitaste este acceso, por favor ignora este correo.</p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    `;

    try {
        await transporter.sendMail({
            from: '"Zynetra Security" <no-reply@zynetra.com>',
            to: email,
            subject: '🔐 Código de Acceso Zynetra',
            html: htmlContent
        });
        console.log(`✅ Email enviado correctamente a ${email}`);
    } catch (error) {
        console.error(`❌ Error enviando email:`, error);
        // Fallback para desarrollo: Imprimir en consola si falla el email
        console.log(`🔑 CÓDIGO DE RESPALDO (Consola): ${code}`);
    }
}

// --- CRON JOB: Limpieza de cuentas no verificadas ---
cron.schedule('* * * * *', () => {
    const now = Date.now();
    db.run(`DELETE FROM users WHERE is_verified = 0 AND otp_expires < ?`, [now], function(err) {
        if (!err && this.changes > 0) console.log(`🧹 Cuentas expiradas eliminadas: ${this.changes}`);
    });
});

// --- SEGURIDAD ---
app.use(helmet({ contentSecurityPolicy: false }));
app.set('trust proxy', 1); // Importante para Render/Heroku (HTTPS)

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 100 });

app.use(session({
    secret: 'zynetra_secure_session',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// --- API SESSION ---
app.get('/api/session-status', (req, res) => {
    if (req.session.userId) {
        const userEmail = req.session.email ? req.session.email.trim().toLowerCase() : '';
        const isOwner = userEmail === 'equipozynetra@gmail.com';
        res.json({ loggedIn: true, name: req.session.userName, isOwner: isOwner });
    } else {
        res.json({ loggedIn: false });
    }
});

// --- RUTAS VISTAS ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/servicios', (req, res) => res.sendFile(path.join(__dirname, 'public', 'services.html')));
app.get('/desafios', (req, res) => res.sendFile(path.join(__dirname, 'public', 'challenges.html')));
app.get('/nosotros', (req, res) => res.sendFile(path.join(__dirname, 'public', 'about.html')));

app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard');
    res.sendFile(path.join(__dirname, 'public', 'auth.html'));
});

app.get('/verify-otp', (req, res) => res.sendFile(path.join(__dirname, 'public', 'verify.html')));

app.get('/loading', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    res.sendFile(path.join(__dirname, 'public', 'loading.html'));
});

app.get('/dashboard', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// --- LOGICA REGISTRO ---
app.post('/register', authLimiter, [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.redirect('/login?error=validation_error');

    const { name, email, password, phone, company, role } = req.body;
    const cleanEmail = email.trim().toLowerCase();
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + (15 * 60 * 1000);
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO users (name, email, password, phone, company, role, is_verified, otp_code, otp_expires) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`;
    
    db.run(sql, [name, cleanEmail, hashedPassword, phone, company, role, otp, expires], async function(err) {
        if (err) return res.redirect('/login?error=email_exists');
        
        // Enviar email real
        await sendOTPEmail(cleanEmail, otp, name);
        res.redirect(`/verify-otp?email=${encodeURIComponent(cleanEmail)}`);
    });
});

// --- LOGICA VERIFICACIÓN ---
app.post('/verify-code', async (req, res) => {
    const { email, otp } = req.body;
    const cleanEmail = email.trim().toLowerCase();
    const now = Date.now();

    db.get(`SELECT * FROM users WHERE email = ?`, [cleanEmail], (err, user) => {
        if (err || !user) return res.redirect('/verify-otp?error=invalid_user');

        if (user.otp_code === otp && user.otp_expires > now) {
            db.run(`UPDATE users SET is_verified = 1, otp_code = NULL WHERE id = ?`, [user.id], (err) => {
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

// --- LOGICA LOGIN ---
app.post('/login', authLimiter, async (req, res) => {
    const { email, password, remember } = req.body;
    const cleanEmail = email.trim().toLowerCase();

    db.get(`SELECT * FROM users WHERE email = ?`, [cleanEmail], async (err, user) => {
        if (err || !user) return res.redirect('/login?error=invalid_credentials');
        
        if (await bcrypt.compare(password, user.password)) {
            if (user.is_verified === 0) return res.redirect('/login?error=not_verified');

            if (remember === 'on') req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
            else req.session.cookie.expires = false;

            req.session.userId = user.id;
            req.session.userName = user.name;
            req.session.email = user.email;
            
            res.redirect('/loading');
        } else {
            res.redirect('/login?error=invalid_credentials');
        }
    });
});

app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'public', '404.html')));

app.listen(PORT, () => console.log(`🚀 Zynetra Server: http://localhost:${PORT}`));