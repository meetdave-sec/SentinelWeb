const express = require("express");
const morgan = require("morgan");
const path = require("path");

const app = express();
const PORT = 4000; 

// --- Middleware ---

app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

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
  const { username } = req.body;
  res.send(`<p>Secure app received login for user: ${username}</p>`);
});


app.listen(PORT, () => {
  console.log(`Secure app listening on http://localhost:${PORT}`);
});
