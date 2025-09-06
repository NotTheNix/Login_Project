const express = require("express");
const fs = require("fs").promises;
const path = require("path");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3000;

// files live next to server.js
const ROOT = __dirname;
const USERS_FILE = path.join(ROOT, "users.txt");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(ROOT)); // serves main.html, login.html, register.html

// make sure users.txt exists
async function ensureUsersFile() {
  try { await fs.access(USERS_FILE); }
  catch { await fs.writeFile(USERS_FILE, "", "utf8"); }
}

// load map: email -> { name, hash }
async function loadUsers() {
  await ensureUsersFile();
  const text = await fs.readFile(USERS_FILE, "utf8");
  const map = new Map();
  for (const line of text.split("\n")) {
    const row = line.trim();
    if (!row) continue;
    const [email, name, hash] = row.split(",");
    if (email && hash) map.set(email.toLowerCase(), { name, hash });
  }
  return map;
}

async function appendUser(email, name, hash) {
  const safe = String(name).replace(/,/g, " ");
  await fs.appendFile(USERS_FILE, `${email.toLowerCase()},${safe},${hash}\n`, "utf8");
}

// serve main as homepage too
app.get("/", (_req, res) => {
  res.sendFile(path.join(ROOT, "main.html"));
});

app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ ok:false, msg:"Name, email, password required." });
    }
    const users = await loadUsers();
    const key = email.toLowerCase();
    if (users.has(key)) {
      return res.status(409).json({ ok:false, msg:"Email already registered." });
    }
    const hash = await bcrypt.hash(password, 10);
    await appendUser(email, name, hash);
    return res.json({ ok:true, msg:"Registered successfully." });
  } catch (e) {
    console.error("REGISTER ERROR:", e);
    return res.status(500).json({ ok:false, msg:"Server error." });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ ok:false, msg:"Email and password required." });
    }
    const users = await loadUsers();
    const entry = users.get(email.toLowerCase());
    if (!entry) return res.status(401).json({ ok:false, msg:"Wrong credentials: email not found." });

    const ok = await bcrypt.compare(password, entry.hash);
    if (!ok) return res.status(401).json({ ok:false, msg:"Wrong credentials: incorrect password." });
    return res.json({ ok:true, msg:"Login successful", name: entry.name });
  } catch (e) {
    console.error("LOGIN ERROR:", e);
    return res.status(500).json({ ok:false, msg:"Server error." });
  }
});

app.listen(PORT, () => {
  console.log(`Running at http://localhost:${PORT}`);
});