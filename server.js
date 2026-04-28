const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SECRET = 'mysecretkey123';

let users = [];

// SIGNUP
app.post('/signup', async (req, res) => {
  const { name, password } = req.body;

  if (!name || !password) {
    return res.status(400).json({ error: 'Name and password required' });
  }

  const hashed = await bcrypt.hash(password, 10);
  const user = { id: users.length + 1, name, password: hashed };
  users.push(user);

  res.status(201).json({ message: 'Account created!' });
});

// LOGIN
app.post('/login', async (req, res) => {
  const { name, password } = req.body;

  const user = users.find(u => u.name === name);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ error: 'Wrong password' });
  }

  const token = jwt.sign({ id: user.id, name: user.name }, SECRET);
  res.json({ token });
});

// PROTECTED ROUTE
app.get('/profile', (req, res) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    res.json({ message: 'Welcome ' + decoded.name });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});