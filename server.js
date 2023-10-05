const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
const axios = require("axios");
const mysql = require("mysql2");

// Create a MySQL database connection
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "login",
});

connection.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    return;
  }
  console.log("Connected to MySQL database");
});

const app = express();
const port = process.env.PORT || 3000;

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: "$2a$10$VDDcWAlaGYNG2Yu4fA9qs.Zj1zr02F2gUtEcwbO84JD0neRaaPAH2",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Passport initialization
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      // Fetch user from the database based on username
      const [rows] = await connection.execute(
        "SELECT * FROM users WHERE username = ?",
        [username]
      );

      if (rows.length === 0) {
        return done(null, false, { message: "Incorrect username" });
      }

      const user = rows[0];

      // Compare the hashed password
      if (await bcrypt.compare(password, user.password)) {
        return done(null, user);
      } else {
        return done(null, false, { message: "Incorrect password" });
      }
    } catch (error) {
      return done(error);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    // Fetch user from the database based on id
    const [rows] = await connection.execute("SELECT * FROM users WHERE id = ?", [
      id,
    ]);

    if (rows.length === 0) {
      return done(new Error("User not found"));
    }

    const user = rows[0];
    return done(null, user);
  } catch (error) {
    return done(error);
  }
});

// Authentication middleware
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Unauthorized" });
}

// Routes
app.post("/api/users/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the user into the database
    await connection.execute(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashedPassword]
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/users/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Login failed" });
    }

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    req.logIn(user, (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Login failed" });
      }

      res.status(200).json({ message: "Login successful" });
    });
  })(req, res, next);
});

app.get("/api/users/me", ensureAuthenticated, (req, res) => {
  res.status(200).json({ user: req.user.username });
});

app.get("/api/random-joke", async (req, res) => {
  try {
    const response = await axios.get(
      "https://api.chucknorris.io/jokes/random"
    );
    const joke = response.data.value;
    res.status(200).json({ joke });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch a random joke" });
  }
});

app.delete("/api/users/logout", (req, res) => {
  req.logout();
  res.status(200).json({ message: "Logout successful" });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
