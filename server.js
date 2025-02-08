const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const mysql = require("mysql2");
const session = require("express-session")
require("dotenv").config();

const app = express();
const port = 3000;


app.use(session({
  secret: 'mySecretKey',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect(err => {
  if (err) throw err;
  console.log("Connected to the database.");
});


app.use(bodyParser.urlencoded({ extended: true }));


//GET Handling

// Serve the login form
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

// serve signup form
app.get("/signup", (req, res) => {
  res.sendFile(__dirname + "/public/signup.html");
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});


//POST Handling

// Handle login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const query = "SELECT * FROM Users WHERE Username = ?";
  db.query(query, [username], async (err, results) => {
    if (err) throw err;

    if (results.length === 0) {
      return res.status(401).send("User not found.");
    }

    const user = results[0];

    // Compare the password with the stored hash
    const match = await bcrypt.compare(password, user.PasswordHash);

    if (match) {
      res.send("Login successful!");
    } else {
      res.status(401).send("Invalid credentials.");
    }
  });
});

app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if username already exists
    const checkQuery = "SELECT * FROM Users WHERE Username = ?";
    db.query(checkQuery, [username], async (err, results) => {
      if (err) throw err;

      if (results.length > 0) {
        return res.status(400).send("Username already exists.");
      }

      // Hash the password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // Insert new user into database
      const insertQuery = "INSERT INTO Users (Username, PasswordHash) VALUES (?, ?)";
      db.query(insertQuery, [username, hashedPassword], (err) => {
        if (err) throw err;
        res.send("Signup successful! You can now login.");
      });
    });
  } catch (error) {
    res.status(500).send("Error creating user.");
  }
});


app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});