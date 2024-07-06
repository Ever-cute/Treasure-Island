const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const users = [];
const allowedUsernames = ['King', 'Jin', 'Yin']; // 允许注册的用户名列表
const secretKey = 'your_jwt_secret'; // 用于JWT签名的密钥

app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files from "public" directory

// 配置Multer
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// 用户注册
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;

    if (!allowedUsernames.includes(username)) {
        return res.json({ success: false, message: 'Invalid username' });
    }

    if (users.find(user => user.username === username)) {
        return res.json({ success: false, message: 'Username already registered' });
    }

    const hashedPassword = bcrypt.hashSync(password, 8);
    users.push({ username, email, password: hashedPassword });
    res.json({ success: true, message: 'Registration successful' });
});

// 用户登录
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);

    if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ email: user.email }, secretKey, { expiresIn: '1h' });
        res.json({ success: true, token });
    } else {
        res.json({ success: false, message: 'Invalid email or password' });
    }
});

// 保护中间件
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization').replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access denied' });
    }

    try {
        const verified = jwt.verify(token, secretKey);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ success: false, message: 'Invalid token' });
    }
};

// 上传照片
app.post('/upload', authenticateToken, upload.single('photo'), (req, res) => {
    res.json({ success: true, message: 'Photo uploaded successfully', file: req.file });
});


app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

