const path = require("path");
const express = require("express");
const morgan = require("morgan");
const db = require("./secure-db");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const app = express();
const PORT = 4000;

// --- Middleware ---

app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

app.use(
  session({
    secret: "This is my secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
    },
  }),
);

// --- Basic Routes ---

app.get("/", (req, res) => {
  res.send(`
    <h1>Secure Web App</h1>
    <p>This is the <strong>hardened</strong> version with proper security controls.</p>
    <ul>
      <li><a href="/login">Login (secure)</a></li>
    </ul>
  `);
});

app.get("/login", (req, res) => {
  res.send(`
    <h2>Secure Login</h2>
    <form method="POST" action="/login">
      <label>Username: <input name="username" /></label><br/>
      <label>Password: <input type="password" name="password" /></label><br/>
      <button type="submit">Login</button>
    </form>
  `);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (err) return res.status(500).send("Server error");
      if (!user) return res.status(401).send("Invalid credentials");

      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).send("Invalid credentials");

      req.session.userId = user.id;
      req.session.username = user.username;

      return res.redirect("/dashboard");
    },
  );
});

app.get("/dashboard", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).send("Not logged in");
  }

  res.send(`
    <h2>Dashboard</h2>
    <p>Welcome, ${req.session.username}</p>
    <p>You are logged in via session.</p>
  `);
});

app.listen(PORT, () => {
  console.log(`Secure app listening on http://localhost:${PORT}`);
});
