const initSqlJs = require("sql.js");
const fs = require("fs");
const crypto = require("crypto");

const DB_PATH = "./enclave.db";
let db = null;

async function getDb() {
  if (db) return db;
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }

  // Ajout de owner_id pour isoler les comptes
  db.run(`
    CREATE TABLE IF NOT EXISTS contacts (
      id TEXT PRIMARY KEY, 
      owner_id TEXT NOT NULL, 
      name TEXT NOT NULL, 
      device_id TEXT NOT NULL, 
      shared_secret TEXT
    );
    CREATE TABLE IF NOT EXISTS keys (id TEXT PRIMARY KEY, contact_id TEXT NOT NULL, key_blob BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'free');
    CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, key_id TEXT, contact_id TEXT, action TEXT NOT NULL, detail TEXT, timestamp INTEGER DEFAULT (strftime('%s','now')));
    CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  `);

  db.run("INSERT OR IGNORE INTO config (key,value) VALUES (?,?)", ["device_id", "enclave-" + crypto.randomBytes(4).toString("hex")]);
  db.run("INSERT OR IGNORE INTO config (key,value) VALUES (?,?)", ["version", "2.0.0-pqc"]);
  
  save();
  return db;
}

function save() {
  if (!db) return;
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

module.exports = { getDb, save };