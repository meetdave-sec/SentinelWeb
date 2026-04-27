const path = require("path");
const express = require("express");
const morgan = require("morgan");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const PORT = 3000;

const db = new sqlite3.Database("./vuln-app.db");

const styles = `
  <style>
    * {
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      max-width: 600px;
      margin: 40px auto;
      padding: 0 20px;
      background: #1a1a2e;
      color: #eaeaea;
      line-height: 1.6;
    }
    h1, h2, h3 {
      color: #ff6b6b;
    }
    a {
      color: #4ecdc4;
    }
    a:hover {
      color: #45b7aa;
    }
    ul {
      padding-left: 20px;
    }
    li {
      margin: 8px 0;
    }
    form {
      background: #16213e;
      padding: 20px;
      border-radius: 8px;
      margin: 20px 0;
    }
    label {
      display: block;
      margin-bottom: 12px;
    }
    input {
      padding: 8px 12px;
      border: 1px solid #4a4a6a;
      border-radius: 4px;
      background: #0f0f23;
      color: #eaeaea;
      margin-top: 4px;
    }
    input:focus {
      outline: none;
      border-color: #4ecdc4;
    }
    button {
      background: #ff6b6b;
      color: white;
      border: none;
      padding: 10px 20px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    }
    button:hover {
      background: #ee5a5a;
    }
    .warning {
      background: #2d1f1f;
      border-left: 4px solid #ff6b6b;
      padding: 12px;
      margin: 16px 0;
      border-radius: 0 4px 4px 0;
    }
    .comment-list {
      background: #16213e;
      padding: 16px;
      border-radius: 8px;
    }
    .comment-list li {
      padding: 8px 0;
      border-bottom: 1px solid #2a2a4a;
    }
    .comment-list li:last-child {
      border-bottom: none;
    }
  </style>
`;

const layout = content => `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable Web App</title>
    ${styles}
  </head>
  <body>
    ${content}
  </body>
  </html>
`;

// --- MIDDLEWARE ---

app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// --- BASIC ROUTES ---

app.get("/", (req, res) => {
  res.send(
    layout(`
    <h1>Vulnerable Web App</h1>
    <p>This is the <strong>intentionally insecure</strong> version.</p>
    <ul>
      <li><a href="/login">Login page</a></li>
      <li><a href="/comments">Comments (XSS target)</a></li>
    </ul>
  `),
  );
});

app.get("/login", (req, res) => {
  res.send(
    layout(`
    <h2>Login</h2>
    <form method="POST" action="/login">
      <label>Username: <input name="username" /></label>
      <label>Password: <input type="password" name="password" /></label>
      <button type="submit">Login</button>
    </form>
    <p><a href="/">← Back to Home</a></p>
  `),
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const sql = `
    SELECT id, username, role
    FROM users
    WHERE username = '${username}' AND password = '${password}'
  `;

  console.log("[VULN QUERY]", sql.trim());

  db.get(sql, (err, row) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).send(layout("<p>Internal Server Error</p>"));
    }

    if (!row) {
      return res.send(
        layout(`
        <h2>Login Failed</h2>
        <p>Invalid username or password.</p>
        <p><a href="/login">← Try again</a></p>
      `),
      );
    }

    res.send(
      layout(`
      <h2>Welcome, ${row.username}</h2>
      <p><strong>Role:</strong> ${row.role}</p>
      <div class="warning">
        <strong>⚠️ Security Note:</strong> This login is vulnerable to SQL injection.
      </div>
      <p><a href="/">← Back to Home</a></p>
    `),
    );
  });
});

app.get("/comments", (req, res) => {
  db.all("SELECT content FROM comments", (err, rows) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).send(layout("<p>Internal Server Error</p>"));
    }

    const comments = rows.map(row => `<li>${row.content}</li>`).join("");

    res.send(
      layout(`
      <h2>Comments</h2>

      <form method="POST" action="/comments">
        <input name="content" placeholder="Enter comment" style="width: 100%; margin-bottom: 12px;" />
        <button type="submit">Post Comment</button>
      </form>

      <h3>All Comments:</h3>
      <ul class="comment-list">
        ${comments || "<li><em>No comments yet.</em></li>"}
      </ul>

      <p><a href="/">← Back to Home</a></p>
    `),
    );
  });
});

app.post("/comments", (req, res) => {
  const { content } = req.body;

  const sql = `INSERT INTO comments (content) VALUES ('${content}')`;

  console.log("[VULN COMMENT QUERY]", sql);

  db.run("INSERT INTO comments (content) VALUES (?)", [content], err => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).send("Internal Server Error");
    }

    res.redirect("/comments");
  });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}.`));
