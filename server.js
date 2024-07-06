const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

const users = [];
const allowedUsernames = ['King', 'Jin', 'Yin']; // 允许注册的用户名列表

app.use(bodyParser.json());

app.post('/register', (req, res) => {
    const { username, email, password } = req.body;

    // 验证用户名是否在允许注册的列表中
    if (!allowedUsernames.includes(username)) {
        return res.json({ success: false, message: 'Invalid username' });
    }

    // 检查用户名是否已被注册
    if (users.find(user => user.username === username)) {
        return res.json({ success: false, message: 'Username already registered' });
    }

    const hashedPassword = bcrypt.hashSync(password, 8);
    users.push({ username, email, password: hashedPassword });
    res.json({ success: true });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ email: user.email }, 'your_jwt_secret', { expiresIn: '1h' });
        res.json({ success: true, token });
    } else {
        res.json({ success: false, message: 'Invalid email or password' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
