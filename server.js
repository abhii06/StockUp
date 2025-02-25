// require('dotenv').config(); // Load environment variables

// const express = require('express');
// const mysql = require('mysql2');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');
// const cors = require('cors');
// const dbConfig = require('./db.config'); // Your db config file

// const app = express();
// app.use(express.json());
// app.use(cors());

// // Create MySQL connection using the configuration file
// const db = mysql.createConnection({
//   host: dbConfig.HOST,
//   user: dbConfig.USER,
//   password: dbConfig.PASSWORD,
//   database: dbConfig.DB,
// });

// // Connect to MySQL
// db.connect((err) => {
//   if (err) throw err;
//   console.log('Connected to the MySQL database');
// });



// // Register route (Sign Up)
// app.post('/api/signup', (req, res) => {
//   const { username, email, password } = req.body;

//   // Hash password before storing it
//   bcrypt.hash(password, 10, (err, hashedPassword) => {
//     if (err) return res.status(500).send('Error hashing password');

//     // Insert new user into the database
//     const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
//     db.query(query, [username, email, hashedPassword], (err, result) => {
//       if (err) return res.status(500).send('Error registering user');
//       res.status(200).send('User registered successfully');
//     });
//   });
// });

// // Login route
// app.post('/api/login', (req, res) => {
//   const { email, password } = req.body;

//   // Check if user exists
//   const query = 'SELECT * FROM users WHERE email = ?';
//   db.query(query, [email], (err, result) => {
//     if (err) return res.status(500).send('Error checking user');
//     if (result.length === 0) return res.status(400).send('User not found');

//     // Compare password with hashed password in database
//     bcrypt.compare(password, result[0].password, (err, isMatch) => {
//       if (err) return res.status(500).send('Error comparing passwords');
//       if (!isMatch) return res.status(400).send('Invalid credentials');

//       // Generate JWT token
//       const token = jwt.sign({ userId: result[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
//       res.status(200).json({ message: 'Login successful', token });
//     });
//   });
// });

// // Server listening
// const PORT = process.env.PORT || 5000;
// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));






require('dotenv').config(); // Load environment variables
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const redis = require('redis');

const dbConfig = require('./db.config'); // Your db config file

const app = express();
app.use(express.json());
// app.use(cors({ origin: 'http://localhost:5174' }));
app.use(cors({
  origin: 'http://localhost:5174', // Allow only this origin
  credentials: true, // Allow cookies (if needed)
}));

// Redis client for token blacklist
const redisClient = redis.createClient();
redisClient.on('error', (err) => console.log('Redis error: ', err));

// MySQL connection setup
const db = mysql.createConnection({
  host: dbConfig.HOST,
  user: dbConfig.USER,
  password: dbConfig.PASSWORD,
  database: dbConfig.DB,
});

// Connect to MySQL
db.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL database');
});

// Register route (Sign Up)
app.post('/api/signup', (req, res) => {
  const { username, email, password } = req.body;

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).send('Error hashing password');

    const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    db.query(query, [username, email, hashedPassword], (err, result) => {
      if (err) return res.status(500).send('Error registering user');
      res.status(200).send('User registered successfully');
    });
  });
});

// Login route
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, result) => {
    if (err) return res.status(500).send('Error checking user');
    if (result.length === 0) return res.status(400).send('User not found');

    bcrypt.compare(password, result[0].password, (err, isMatch) => {
      if (err) return res.status(500).send('Error comparing passwords');
      if (!isMatch) return res.status(400).send('Invalid credentials');

      const token = jwt.sign({ userId: result[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.status(200).json({ message: 'Login successful', token });
    });
  });
});

// Middleware to check JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Bearer token
  if (!token) return res.status(403).send('Token is required');

  // Check if the token is blacklisted in Redis
  redisClient.get(token, (err, reply) => {
    if (reply === 'blacklisted') {
      return res.status(401).send('Token is invalidated');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) return res.status(403).send('Token is invalid or expired');
      req.userId = decoded.userId;
      next();
    });
  });
};

// Logout route (optional blacklist)
app.post('/api/logout', (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Bearer token
  if (!token) return res.status(400).send('No token provided');

  // Blacklist the token in Redis
  redisClient.setex(token, 3600, 'blacklisted', (err, reply) => { // Token expires in 1 hour
    if (err) return res.status(500).send('Error blacklisting token');
    res.status(200).send('User logged out successfully');
  });
});

// Server listening
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
