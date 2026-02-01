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

// --- CONFIGURACIÓN EMAIL (NODEMAILER) ---
// Para usar Gmail real, cambia esto por tus credenciales y usa "App Password" de Google
const transporter = nodemailer.createTransport({
    service: 'gmail', // O tu proveedor SMTP
    auth: {
        user: 'tu_correo@gmail.com', // PON TU CORREO REAL AQUÍ
        pass: 'tu_contraseña_app'    // PON TU CONTRASEÑA DE APP AQUÍ
    }
});

// Función auxiliar para enviar email HTML
async function sendOTPEmail(email, code) {
    const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #0f172a; color: #fff; padding: 40px; border-radius: 10px;">
        <h2 style="color: #6366f1; text-align: center;">Bienvenido a Zynetra</h2>
        <p>Estás a un paso de activar tu cuenta corporativa.</p>
        <div style="background-color: #1e293b; padding: 20px; text-align: center; border-radius: 8px; margin: 30px 0;">
            <span style="font-size: 32px; letter-spacing: 5px; font-weight: bold; color: #fff;">${code}</span>
        </div>
        <p>Este código caducará en <strong>15 minutos</strong>.</p>
        <p style="font-size: 12px; color: #94a3b8; text-align: center; margin-top: 30px;">Si no has solicitado este código, ignora este mensaje.</p>
    </div>
    `;

    try {
        await transporter.sendMail({
            from: '"Zynetra Security" <security@zynetra.com>',
            to: email,
            subject: '🔐 Tu Código de Verificación Zynetra',
            html: htmlContent
        });
        console.log(`📧 Email enviado a ${email}`);
    } catch (error) {
        console.log(`⚠️ No se pudo enviar el email (probablemente falta config SMTP).`);
        console.log(`🔑 TU CÓDIGO OTP ES: [ ${code} ] (Cópialo de aquí)`);
    }
}

// --- CRON JOB: LIMPIEZA AUTOMÁTICA ---
// Se ejecuta cada minuto para borrar cuentas no verificadas expiradas
cron.schedule('* * * * *', () => {
    const now = Date.now();
    db.run(`DELETE FROM users WHERE is_verified = 0 AND otp_expires < ?`, [now], function(err) {
        if (!err && this.changes > 0) {
            console.log(`🧹 Limpieza: ${this.changes} cuentas no verificadas eliminadas.`);
        }
    });
});

// --- SEGURIDAD Y MIDDLEWARES ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: 'zynetra_super_secure_key',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false, maxAge: 24 * 60 * 60 * 1000 } // Default 24h
}));

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 100 });

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

// --- RUTAS DE VISTAS ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/servicios', (req, res) => res.sendFile(path.join(__dirname, 'public', 'services.html')));
app.get('/desafios', (req, res) => res.sendFile(path.join(__dirname, 'public', 'challenges.html')));
app.get('/nosotros', (req, res) => res.sendFile(path.join(__dirname, 'public', 'about.html')));

app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard');
    res.sendFile(path.join(__dirname, 'public', 'auth.html'));
});

// Nueva ruta: Verificación OTP
app.get('/verify-otp', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'verify.html'));
});

// Nueva ruta: Pantalla de Carga
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

// --- LÓGICA REGISTRO (CON OTP) ---
app.post('/register', authLimiter, [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.redirect('/login?error=validation_error');

    const { name, email, password, phone, company, role } = req.body;
    const cleanEmail = email.trim().toLowerCase();
    
    // Generar OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + (15 * 60 * 1000); // 15 minutos

    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO users (name, email, password, phone, company, role, is_verified, otp_code, otp_expires) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`;
    
    db.run(sql, [name, cleanEmail, hashedPassword, phone, company, role, otp, expires], async function(err) {
        if (err) return res.redirect('/login?error=email_exists');
        
        // Enviar Email
        await sendOTPEmail(cleanEmail, otp);

        // Redirigir a página de verificación (pasamos email por query para identificar)
        res.redirect(`/verify-otp?email=${encodeURIComponent(cleanEmail)}`);
    });
});

// --- LÓGICA VERIFICACIÓN OTP ---
app.post('/verify-code', async (req, res) => {
    const { email, otp } = req.body;
    const cleanEmail = email.trim().toLowerCase();
    const now = Date.now();

    db.get(`SELECT * FROM users WHERE email = ?`, [cleanEmail], (err, user) => {
        if (err || !user) return res.redirect('/verify-otp?error=invalid_user');

        if (user.otp_code === otp && user.otp_expires > now) {
            // Código correcto y no expirado
            db.run(`UPDATE users SET is_verified = 1, otp_code = NULL WHERE id = ?`, [user.id], (err) => {
                if(err) console.error(err);
                
                // Iniciar sesión
                req.session.userId = user.id;
                req.session.userName = user.name;
                req.session.email = user.email;
                
                // Redirigir a la pantalla de carga (Loading)
                res.redirect('/loading');
            });
        } else {
            // Código incorrecto o expirado
            res.redirect(`/verify-otp?email=${cleanEmail}&error=invalid_code`);
        }
    });
});

// --- LÓGICA LOGIN (CON REMEMBER ME) ---
app.post('/login', authLimiter, async (req, res) => {
    const { email, password, remember } = req.body;
    const cleanEmail = email.trim().toLowerCase();

    db.get(`SELECT * FROM users WHERE email = ?`, [cleanEmail], async (err, user) => {
        if (err || !user) return res.redirect('/login?error=invalid_credentials');
        
        if (await bcrypt.compare(password, user.password)) {
            // Verificar si la cuenta está validada (El dueño is_verified=1 por defecto)
            if (user.is_verified === 0) {
                // Si existe pero no verificada, podría estar expirada o pendiente.
                // Por simplicidad, si intenta loguear y no está verificado, le pedimos verificar si no expiró
                // O le decimos que debe registrarse de nuevo si el cron la borró.
                return res.redirect('/login?error=not_verified');
            }

            // Gestionar "Recordarme"
            if (remember === 'on') {
                // 30 días
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
            } else {
                // Sesión de navegador (se borra al cerrar)
                req.session.cookie.expires = false;
            }

            req.session.userId = user.id;
            req.session.userName = user.name;
            req.session.email = user.email;
            
            res.redirect('/loading'); // Ir a loading también en login
        } else {
            res.redirect('/login?error=invalid_credentials');
        }
    });
});

app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'public', '404.html')));

app.listen(PORT, () => {
    console.log(`🚀 Zynetra Secure Server en http://localhost:${PORT}`);
});