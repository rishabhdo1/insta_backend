// controllers/authController.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/database.js');

// Secret key for JWT (in a real application, store it securely)
const JWT_SECRET = process.env.JWT_SECRET;

exports.register = async (req, res) => {
  const { username, password, email } = req.body;
  try {
    const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length > 0) {
      return res.status(400).send({ message: 'User already exists' });
    }

    const hashedPassword = bcrypt.hashSync(password, 8);
    await db.query('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', [username, hashedPassword, email]);
    res.status(201).send({ message: 'User registered successfully!' });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
};

exports.login = async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(404).send({ message: 'User not found' });
    }

    const user = rows[0];
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).send({ message: 'Invalid Password' });
    }

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: 86400 });
    res.status(200).send({ message: 'Login successful', accessToken: token });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
};
