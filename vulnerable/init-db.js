const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./vuln-app.db");

db.serialize(() => {
  console.log("[*] Resetting database...");

  db.run("DROP TABLE IF EXISTS users");
  db.run("DROP TABLE IF EXISTS comments");

  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,        -- INSECURE: plain-text password
      role TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT
    )
    `);

  console.log("[*] Created users table.");
  console.log("[*] Created comments table.");

  const insert = db.prepare(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
  );

  insert.run("admin", "admin123", "admin"); // Intentionally weak
  insert.run("alice", "password1", "user");
  insert.run("bob", "qwerty123", "user");

  insert.finalize();

  console.log("[*] Inserted sample users.");
});

db.close(() => {
  console.log("[*] Database initialization complete.");
});
