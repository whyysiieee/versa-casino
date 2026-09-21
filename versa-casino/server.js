const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'versa_super_secret_key_2026';

// Мидлвары
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Инициализация базы данных SQLite
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error('Ошибка подключения к БД:', err);
    else console.log('База данных SQLite успешно подключена');
});

// Создание таблиц
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            balance REAL DEFAULT 1000.0,
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
});

// Мидлвар авторизации
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Требуется авторизация' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Недействительный токен' });
        req.user = user;
        next();
    });
};

// Мидлвар проверки прав админа
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Доступ разрешен только администраторам' });
    }
    next();
};

// ---------------- API ЭНДПОИНТЫ ----------------

// 1. Регистрация
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });

    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Проверка: сделаем первого зарегистрированного пользователя админом
    db.get('SELECT COUNT(*) as count FROM users', [], (err, row) => {
        const role = row.count === 0 ? 'admin' : 'user';

        db.run(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            [username.trim(), hashedPassword, role],
            function (err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'Имя пользователя уже занято' });
                    }
                    return res.status(500).json({ error: 'Ошибка БД' });
                }
                res.json({ message: 'Регистрация успешна! Теперь войдите.', role });
            }
        );
    });
});

// 2. Вход
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username.trim()], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Пользователь не найден' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Неверный пароль' });

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                balance: user.balance,
                role: user.role
            }
        });
    });
});

// 3. Получение профиля и баланса
app.get('/api/user/profile', authenticateToken, (req, res) => {
    db.get('SELECT id, username, balance, role FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Пользователь не найден' });
        res.json(user);
    });
});

// 4. Обновление баланса после игры
app.post('/api/user/update-balance', authenticateToken, (req, res) => {
    const { amount } = req.body; // delta (например +100 или -50)
    if (typeof amount !== 'number') return res.status(400).json({ error: 'Неверная сумма' });

    db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Ошибка' });

        const newBalance = user.balance + amount;
        if (newBalance < 0) return res.status(400).json({ error: 'Недостаточно средств на балансе' });

        db.run('UPDATE users SET balance = ? WHERE id = ?', [newBalance, req.user.id], (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка обновления' });
            res.json({ balance: newBalance });
        });
    });
});

// 5. АДМИН-ПАНЕЛЬ: Поиск всех игроков
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    db.all('SELECT id, username, balance, role, created_at FROM users', [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Ошибка БД' });
        res.json(rows);
    });
});

// 6. АДМИН-ПАНЕЛЬ: Выдача / списание монет
app.post('/api/admin/give-coins', authenticateToken, requireAdmin, (req, res) => {
    const { targetUsername, amount } = req.body;
    
    if (!targetUsername || typeof amount !== 'number') {
        return res.status(400).json({ error: 'Укажите ник и сумму' });
    }

    db.get('SELECT balance FROM users WHERE username = ?', [targetUsername], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Пользователь не найден' });

        const newBalance = Math.max(0, user.balance + amount);
        db.run('UPDATE users SET balance = ? WHERE username = ?', [newBalance, targetUsername], (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка записи' });
            res.json({ success: true, targetUsername, newBalance });
        });
    });
});

// Главный маршрут (возвращает HTML)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Сервер VERSA CASINO запущен на порту ${PORT}`);
});

// ... ваш основной код сервера ...

app.use(express.static('public'));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Добавьте эту строку в самый конец файла server.js:
module.exports = app;
