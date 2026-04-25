const path = require("path");
const express = require("express");
const morgan = require("morgan");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const PORT = 3000;

const db = new sqlite3.Database("./vuln-app.db");

// --- MIDDLEWARE ---

app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// -- BASIC ROUTES ---

app.get("/", (req, res) => {
  res.send(`
    <h1>Vulnerable Web App</h1>
    <p>This is the <strong>intentionally insecure</strong> version.</p>
    <ul>
      <li><a href="/login">Login page</a></li>
      <li><a href="/comments">Comments (XSS target)</a></li>
    </ul>
  `);
});

app.get("/login", (req, res) => {
  res.send(`
    <h2>Login</h2>
    <form method="POST" action="/login">
      <label>Username: <input name="username" /></label><br/>
      <label>Password: <input type="password" name="password" /></label><br/>
      <button type="submit">Login</button>
    </form>
  `);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const sql = `
    SELECT id, username, role
    FROM users
    WHERE username = '${username}' AND password = '${password}';
  `;

  console.log("[VULN QUERY]", sql.trim());

  db.get(sql, (err, row) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).send("Internal Server Error");
    }

    if (!row) {
      return res.send("<p>Login failed. Invalid username or password.</p>");
    }

    res.send(`
      <h2>Welcome, ${row.username}</h2>
      <p>Role: ${row.role}</p>
      <p>(This login is <strong>vulnerable to SQL injection</strong>.)</p>
    `);
  });
});

app.listen(PORT, () => console.log("Server running on port 3000."));
