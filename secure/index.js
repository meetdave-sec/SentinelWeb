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

const styles = `
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      max-width: 600px;
      margin: 40px auto;
      padding: 0 20px;
      background: #121212;
      color: #f1f1f1;
      line-height: 1.6;
    }
    h1, h2, h3 {
      color: #4ecdc4;
    }
    a {
      color: #ffb347;
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
    form {
      background: #1f1f1f;
      padding: 20px;
      border-radius: 8px;
      margin: 20px 0;
    }
    label {
      display: block;
      margin-bottom: 10px;
    }
    input {
      width: 100%;
      padding: 8px;
      margin-top: 4px;
      border: 1px solid #333;
      border-radius: 4px;
      background: #222;
      color: #f1f1f1;
    }
    input:focus {
      outline: none;
      border-color: #4ecdc4;
    }
    button {
      background: #4ecdc4;
      color: #000;
      border: none;
      padding: 10px 20px;
      border-radius: 4px;
      cursor: pointer;
      font-weight: 600;
      margin-top: 8px;
    }
    button:hover {
      background: #3bb3aa;
    }
    ul {
      padding-left: 20px;
    }
    li {
      margin-bottom: 8px;
    }
    .nav {
      margin-top: 20px;
    }
  </style>
`;

const layout = content => `
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Secure Web App</title>
      ${styles}
    </head>
    <body>${content}</body>
  </html>
`;

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

// --- Helpers ---
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  next();
}

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: "Too many login attempts. Try again later.",
});

// --- Routes ---

app.get("/", (req, res) => {
  res.send(
    layout(`
      <h1>Secure Web App</h1>
      <p>This is the <strong>hardened</strong> version with proper security controls.</p>
      <ul>
        <li><a href="/login">Login (secure)</a></li>
        <li><a href="/comments">Comments (sanitized)</a></li>
      </ul>
    `),
  );
});

app.get("/login", (req, res) => {
  res.send(
    layout(`
      <h2>Secure Login</h2>
      <form method="POST" action="/login">
       <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
        <label>Username:<input name="username" /></label>
        <label>Password:<input type="password" name="password" /></label>
        <button type="submit">Login</button>
      </form>
      <p class="nav"><a href="/">← Home</a></p>
    `),
  );
});

app.post("/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).send(layout(`
  <h2>Login Failed</h2>
  <p>Missing username or password</p>
  <p><a href="/login">← Try again</a></p>
  `));
  if (username.length > 50 || password.length > 100)
    return res.status(400).send("Invalid input length");

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

      res.redirect("/dashboard");
    },
  );
});

app.get("/comments", (req, res) => {
  db.all("SELECT content FROM comments", (err, rows) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).send(layout("<p>Internal Server Error</p>"));
    }

    const comments = rows
      .map(row => `<li>${escapeHTML(row.content)}</li>`)
      .join("");

    res.send(
      layout(`
        <h2>Secure Comments</h2>
        <form method="POST" action="/comments">
          <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
          <input name="content" placeholder="Enter comment" />
          <button type="submit">Post</button>
        </form>
        <h3>All Comments:</h3>
        <ul>${comments || "<li><em>No comments yet.</em></li>"}</ul>
        <p class="nav"><a href="/">← Home</a></p>
      `),
    );
  });
});

app.post("/comments", (req, res) => {
  const { content } = req.body;
  if (!content || content.length > 500)
    return res.status(400).send("Invalid comment");

  db.run("INSERT INTO comments (content) VALUES (?)", [content], err => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).send("Internal Server Error");
    }
    res.redirect("/comments");
  });
});

app.get("/dashboard", requireLogin, (req, res) => {
  res.send(
    layout(`
      <h2>Dashboard</h2>
      <p>Welcome, <strong>${escapeHTML(req.session.username)}</strong></p>
      <p><a href="/logout">Logout</a></p>
      <p class="nav"><a href="/">← Home</a></p>
    `),
  );
});

app.get("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send("Logout failed");
    res.redirect("/login");
  });
});

// --- Error Handling ---
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).send("Invalid CSRF token");
  }
  next(err);
});

app.listen(PORT, () => {
  console.log(`Secure app listening on http://localhost:${PORT}`);
});
