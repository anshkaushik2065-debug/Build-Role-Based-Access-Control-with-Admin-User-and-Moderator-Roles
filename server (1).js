const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

const JWT_SECRET = 'mysecretkey123';

// Sample users with roles
const users = [
  { username: 'admin', password: 'admin123', role: 'Admin' },
  { username: 'mod', password: 'mod123', role: 'Moderator' },
  { username: 'user', password: 'user123', role: 'User' }
];

// Login route - issues JWT with role
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const foundUser = users.find(
    (u) => u.username === username && u.password === password
  );
  if (!foundUser) return res.status(401).json({ message: 'Invalid credentials' });

  const token = jwt.sign(
    { username: foundUser.username, role: foundUser.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ message: `Welcome ${foundUser.username}!`, role: foundUser.role, token });
});

// Middleware to verify JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(403).json({ message: 'Token missing' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(403).json({ message: 'Token missing or malformed' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
}

// Middleware to authorize specific roles
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        message: `Access denied: ${req.user.role} does not have permission`
      });
    }
    next();
  };
}

// Admin-only route
app.get('/admin/dashboard', verifyToken, authorizeRoles('Admin'), (req, res) => {
  res.json({ message: `Welcome to Admin Dashboard, ${req.user.username}` });
});

// Moderator or Admin route
app.get('/moderator/manage', verifyToken, authorizeRoles('Moderator', 'Admin'), (req, res) => {
  res.json({ message: `Moderator panel accessed by ${req.user.username}` });
});

// User, Moderator, or Admin route
app.get('/user/profile', verifyToken, authorizeRoles('User', 'Moderator', 'Admin'), (req, res) => {
  res.json({ message: `Hello ${req.user.username}, this is your profile.` });
});

// Public route
app.get('/', (req, res) => {
  res.send('Welcome! Use POST /login to get a JWT token.');
});

const PORT = 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));