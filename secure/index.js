function escapeHTML(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const path = require("path");
const express = require("express");
const morgan = require("morgan");
const db = require("./secure-db");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const csurf = require("csurf");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 4000;
const csrfProtection = csurf();

// --- Middleware ---

app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    },
  }),
);

app.use(helmet());
app.use(csrfProtection);

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  next();
}

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: "Too many login attempts. Try again later.",
});

// --- Basic Routes ---

app.get("/", (req, res) => {
  res.send(`
    <h1>Secure Web App</h1>
    <p>This is the <strong>hardened</strong> version with proper security controls.</p>
    <ul>
      <li><a href="/login">Login (secure)</a></li>
      <li><a href="/comments">Comments (XSS target)</a></li>
    </ul>
  `);
});

app.get("/login", (req, res) => {
  res.send(`
    <h2>Secure Login</h2>
    <form method="POST" action="/login">
     <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
      <label>Username: <input name="username" /></label><br/>
      <label>Password: <input type="password" name="password" /></label><br/>
      <button type="submit">Login</button>
    </form>
  `);
});

app.post("/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Missing username or password");
  }

  if (username.length > 50 || password > 100) {
    return res.status(400).send("Invalid input length");
  }

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

app.get("/comments", (req, res) => {
  db.all("SELECT content FROM comments", (err, rows) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).send("Internal Server Error");
    }

    const comments = rows
      .map(row => `<li>${escapeHTML(row.content)}</li>`)
      .join("");

    res.send(`
      <h2>Secure Comments</h2>

      <form method="POST" action="/comments">
        <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
        <input name="content" placeholder="Enter comment" />
        <button type="submit">Post</button>
      </form>

      <h3>All Comments:</h3>
      <ul>
        ${comments}
      </ul>
    `);
  });
});

app.post("/comments", (req, res) => {
  const { content } = req.body;

  if (!content || content.length > 500) {
    return res.status(400).send("Invalid comment");
  }

  db.run("INSERT INTO comments (content) VALUES (?)", [content], err => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).send("Internal Server Error");
    }

    res.redirect("/comments");
  });
});

app.get("/dashboard", requireLogin, (req, res) => {
  res.send(`
    <h2>Dashboard</h2>
    <p>Welcome, ${req.session.username}</p>
    <a href="/logout">Logout</a>
  `);
});

app.get("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send("Logut failed");
    return res.redirect("/login");
  });
});

app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).send("Invalid CSRF token");
  }
  next(err);
});

app.listen(PORT, () => {
  console.log(`Secure app listening on http://localhost:${PORT}`);
});
