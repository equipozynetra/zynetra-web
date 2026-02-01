const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

const dbPath = path.resolve(__dirname, 'zynetra.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('❌ Error DB:', err.message);
    else console.log('💾 Base de datos conectada.');
});

db.serialize(() => {
    // 1. Tabla Usuarios (Con campos de seguridad y verificación)
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        phone TEXT,
        company TEXT,
        role TEXT,
        is_verified INTEGER DEFAULT 0,
        otp_code TEXT,
        otp_expires INTEGER
    )`);

    // 2. Crear Cuenta DUEÑO (Seed)
    const ownerEmail = 'equipozynetra@gmail.com';
    const ownerPass = 'Betico_44';
    
    db.get("SELECT * FROM users WHERE email = ?", [ownerEmail], async (err, row) => {
        if (!row) {
            console.log("👑 Creando cuenta de Dueño...");
            const hashedPassword = await bcrypt.hash(ownerPass, 10);
            
            // El dueño nace verificado (is_verified = 1)
            db.run(`INSERT INTO users (name, email, password, phone, company, role, is_verified) VALUES (?, ?, ?, ?, ?, ?, 1)`, 
            ['Zombie4x4', ownerEmail, hashedPassword, '+34 000 000 000', 'Zynetra HQ', 'CEO & Founder'], 
            (err) => {
                if (err) console.error(err.message);
                else console.log("✅ Cuenta de Dueño creada y lista.");
            });
        }
    });
});

module.exports = db;