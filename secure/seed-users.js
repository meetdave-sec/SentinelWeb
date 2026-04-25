const bcrypt = require("bcryptjs");
const db = require("./secure-db");

async function seed() {
  const username = "admin";
  const password = "admin123";
  const role = "admin";

  const password_hash = await bcrypt.hasqsh(password, 12);

  db.run(
    `INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
    [username, password_hash, role],
    function (err) {
      if (err) {
        console.error("Insert error:", err.message);
      } else {
        console.log("User seeded (or already exists):", username);
      }

      db.close();
    }
  );
}

seed();
