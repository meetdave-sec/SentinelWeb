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

/* ---------------- STYLES ---------------- */

const styles = `
<style>
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto;
    max-width: 650px;
    margin: 40px auto;
    padding: 0 20px;
    background: #121212;
    color: #f1f1f1;
  }
  h1,h2,h3 { color:#4ecdc4; }
  a { color:#ffb347; text-decoration:none; }
  a:hover { text-decoration:underline; }
  form, .card {
    background:#1f1f1f;
    padding:20px;
    border-radius:8px;
    margin:20px 0;
  }
  input {
    width:100%;
    padding:8px;
    margin-top:4px;
    border:1px solid #333;
    background:#222;
    color:#fff;
  }
  button {
    margin-top:10px;
    padding:10px;
    background:#4ecdc4;
    border:none;
    cursor:pointer;
  }
  ul { padding-left:20px; }
  .nav { margin-top:20px; }
</style>
`;

const layout = content => `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Secure App</title>
${styles}
</head>
<body>
${content}
</body>
</html>
`;

/* ---------------- MIDDLEWARE ---------------- */

app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
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
});

/* ---------------- ROUTES ---------------- */

app.get("/", (req, res) => {
  res.send(
    layout(`
      <h1>Secure Web App</h1>
      <ul>
        <li><a href="/login">Login</a></li>
        <li><a href="/comments">Comments</a></li>
      </ul>
    `),
  );
});

app.get("/login", (req, res) => {
  res.send(
    layout(`
      <h2>Login</h2>
      <form method="POST">
        <input type="hidden" name="_csrf" value="${req.csrfToken()}"/>
        <label>Username<input name="username"/></label>
        <label>Password<input type="password" name="password"/></label>
        <button>Login</button>
      </form>
    `),
  );
});

app.post("/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (!user) return res.send("Invalid credentials");

      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.send("Invalid credentials");

      req.session.userId = user.id;
      req.session.username = user.username;

      res.redirect("/dashboard");
    },
  );
});

app.get("/dashboard", requireLogin, (req, res) => {
  res.send(
    layout(`
      <h2>Dashboard</h2>
      <p>Welcome ${escapeHTML(req.session.username)}</p>

      <ul>
        <li><a href="/profile/${req.session.userId}">View My Profile</a></li>
        <li><a href="/comments">Comments</a></li>
      </ul>

      <a href="/logout">Logout</a>
    `),
  );
});

app.get("/profile/:id", requireLogin, (req, res) => {
  const id = parseInt(req.params.id);

  // 🔒 IDOR protection
  if (id !== req.session.userId) {
    return res.status(403).send(
      layout(`
        <h2>403 Forbidden</h2>
        <p>You cannot access this profile.</p>
      `),
    );
  }

  db.get(
    "SELECT id, username, role, email FROM users WHERE id = ?",
    [id],
    (err, user) => {
      res.send(
        layout(`
          <h2>My Profile</h2>
          <div class="card">
            <p>ID: ${user.id}</p>
            <p>Username: ${escapeHTML(user.username)}</p>
            <p>Email: ${escapeHTML(user.email)}</p>
          </div>
        `),
      );
    },
  );
});

app.get("/comments", (req, res) => {
  db.all("SELECT content FROM comments", (err, rows) => {
    const list = rows.map(r => `<li>${escapeHTML(r.content)}</li>`).join("");

    res.send(
      layout(`
        <h2>Comments</h2>

        <form method="POST">
          <input type="hidden" name="_csrf" value="${req.csrfToken()}"/>
          <input name="content"/>
          <button>Post</button>
        </form>

        <ul>${list}</ul>
      `),
    );
  });
});

app.post("/comments", (req, res) => {
  const { content } = req.body;

  db.run("INSERT INTO comments (content) VALUES (?)", [content], () => {
    res.redirect("/comments");
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).send("Invalid CSRF token");
  }
});

app.listen(PORT, () => {
  console.log("Secure app running on port", PORT);
});
