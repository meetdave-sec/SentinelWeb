const bcrypt = require("bcryptjs");
const db = require("./secure-db");

async function seed() {
  const users = [
    { username: "admin", password: "admin123", role: "admin", email: "admin@test.com" },
    { username: "alice", password: "password1", role: "user", email: "alice@test.com" },
    { username: "bob", password: "qwerty123", role: "user", email: "bob@test.com" }
  ];

  for (const user of users) {
    const password_hash = await bcrypt.hash(user.password, 12);

    db.run(
      `INSERT OR IGNORE INTO users (username, password_hash, role, email)
       VALUES (?, ?, ?, ?)`,
      [user.username, password_hash, user.role, user.email],
      (err) => {
        if (err) {
          console.error("Insert error:", err.message);
        } else {
          console.log("User seeded:", user.username);
        }
      }
    );
  }
 
  setTimeout(() => db.close(), 500);
}

seed();