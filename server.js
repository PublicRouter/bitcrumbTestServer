const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
// process incoming request bodies before your handlers
app.use(bodyParser.json());

// Sample database (replace with real DB in production)
const users = {};

// Hashing function
function hashPassword(password, salt) {
  return crypto
    .pbkdf2Sync(password, salt, 1000, 64, 'sha512')
    .toString('hex');
}

// Handshake endpoint
app.post('/handshake', (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  const salt = crypto.randomBytes(16).toString('hex');
  const hashedPassword = hashPassword(password, salt);

  // Save user to "database"
  users[email] = { firstName, lastName, email, salt, hashedPassword };
  console.log("list of mock database users: ", users);

  res.json({ message: 'Account created', email });
});

// Validation (Authentication) endpoint
app.post('/validate', (req, res) => {
  const { email, password } = req.body;
  const user = users[email];

  if (!user) {
    return res.status(401).json({ message: 'User not found' });
  }

  const hashedPassword = hashPassword(password, user.salt);

  if (hashedPassword === user.hashedPassword) {
    res.json({ message: 'Authentication successful' });
  } else {
    res.status(401).json({ message: 'Authentication failed' });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
