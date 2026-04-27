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
      role TEXT NOT NULL,
      email TEXT NOT NULL
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
    "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
  );

  insert.run("admin", "admin123", "admin", "admin@test.com");
  insert.run("alice", "password1", "user", "alice@test.com");
  insert.run("bob", "qwerty123", "user", "bob@test.com");


  insert.finalize();

  console.log("[*] Inserted sample users.");
});

db.close(() => {
  console.log("[*] Database initialization complete.");
});
