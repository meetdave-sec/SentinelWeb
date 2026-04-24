const express = require("express");
const morgan = require("morgan");
const path = require("path");

const app = express();
const PORT = 3000;

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

app.listen(PORT, () => console.log("Server running on port 3000."));
