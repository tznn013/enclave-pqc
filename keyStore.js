const crypto = require("crypto");
const { getDb, save } = require("./db");
const KEY_SIZE = 256;

// ─── HELPERS ─────────────────────────────────────────────────────
// Toutes les requêtes avec variables utilisent db.prepare() + bind
// pour éliminer toute possibilité d'injection SQL.

async function generateKeyPool(contactId, count = 50) {
  const db = await getDb();
  const ids = [];
  for (let i = 0; i < count; i++) {
    const id = "key-" + crypto.randomBytes(8).toString("hex");
    const keyBlob = crypto.randomBytes(KEY_SIZE);
    db.run("INSERT INTO keys (id,contact_id,key_blob,status) VALUES (?,?,?,'free')", [id, contactId, keyBlob]);
    db.run("INSERT INTO audit_log (key_id,contact_id,action,detail) VALUES (?,?,'GENERATED',?)", [id, contactId, `Batch ${i+1}/${count}`]);
    ids.push(id);
  }
  save();
  return ids;
}

// FIX: Remplacé db.exec() avec interpolation par db.prepare() + bind
async function consumeKey(contactId) {
  const db = await getDb();

  while (true) {
    const stmt = db.prepare("SELECT id, key_blob FROM keys WHERE contact_id=? AND status='free' LIMIT 1");
    const res = stmt.getAsObject({ 1: contactId });
    stmt.free();
    if (!res.id) return null;

    const { id, key_blob: keyBlob } = res;
    db.run("UPDATE keys SET status='used' WHERE id=? AND status='free'", [id]);
    const changes = typeof db.getRowsModified === 'function' ? db.getRowsModified() : null;
    if (changes && changes > 0) {
      db.run("INSERT INTO audit_log (key_id,contact_id,action,detail) VALUES (?,?,'USED','Signed - awaiting verification')", [id, contactId]);
      save();
      return { id, keyBlob: Buffer.from(keyBlob) };
    }

    // Possible race: key was consumed by concurrent request. Retry.
    continue;
  }
}

// FIX: Remplacé db.exec() avec interpolation par db.prepare() + bind
async function findAndConsumeKey(keyId, contactId) {
  const db = await getDb();
  const stmt = db.prepare("SELECT id, key_blob FROM keys WHERE id=? AND contact_id=? AND status='used'");
  const res = stmt.getAsObject({ 1: keyId, 2: contactId });
  stmt.free();
  if (!res.id) return null;

  const { id, key_blob: keyBlob } = res;
  db.run("DELETE FROM keys WHERE id=?", [id]);
  db.run("INSERT INTO audit_log (key_id,contact_id,action,detail) VALUES (?,?,'DESTROYED','Verified - PFS guaranteed')", [id, contactId]);
  save();
  return { id, keyBlob: Buffer.from(keyBlob) };
}

async function countAllFreeKeys() {
  const db = await getDb();
  const res = db.exec("SELECT COUNT(*) FROM keys WHERE status='free'");
  return res.length ? res[0].values[0][0] : 0;
}

async function countFreeKeysForContact(contactId) {
  const db = await getDb();
  const res = db.exec("SELECT COUNT(*) FROM keys WHERE contact_id=? AND status='free'", [contactId]);
  return res.length ? res[0].values[0][0] : 0;
}

// FIX: limit est un entier, on le cast pour éviter toute injection
async function getAuditLog(limit = 50) {
  const db = await getDb();
  const safeLimit = Math.max(1, Math.min(500, parseInt(limit) || 50));
  const res = db.exec(
    `SELECT a.timestamp, a.action, a.key_id, c.name, a.detail
     FROM audit_log a
     LEFT JOIN contacts c ON a.contact_id=c.id
     ORDER BY a.timestamp DESC
     LIMIT ${safeLimit}`
  );
  if (!res.length) return [];
  return res[0].values.map(([timestamp, action, key_id, contact_name, detail]) => ({
    timestamp, action, key_id, contact_name, detail
  }));
}

// FIX: on ajoute owner_id dans le SELECT pour que le filtre dans server.js fonctionne
async function getContacts() {
  const db = await getDb();
  const res = db.exec(
    `SELECT c.id, c.owner_id, c.name, c.device_id, c.shared_secret, COUNT(k.id) as free_keys
     FROM contacts c
     LEFT JOIN keys k ON k.contact_id=c.id AND k.status='free'
     GROUP BY c.id`
  );
  if (!res.length) return [];
  return res[0].values.map(([id, owner_id, name, device_id, shared_secret, free_keys]) => ({
    id, owner_id, name, device_id, shared_secret, free_keys
  }));
}

async function setSharedSecret(contactId, secret) {
  const db = await getDb();
  db.run("UPDATE contacts SET shared_secret=? WHERE id=?", [secret, contactId]);
  save();
}

// FIX: Remplacé db.exec() avec interpolation par db.prepare() + bind
async function getSharedSecret(contactId) {
  const db = await getDb();
  const stmt = db.prepare("SELECT shared_secret FROM contacts WHERE id=?");
  const res = stmt.getAsObject({ 1: contactId });
  stmt.free();
  if (!res.shared_secret) return null;
  return res.shared_secret;
}

async function getDeviceId() {
  const db = await getDb();
  const res = db.exec("SELECT value FROM config WHERE key='device_id'");
  return res.length ? res[0].values[0][0] : "unknown";
}

module.exports = {
  generateKeyPool, consumeKey, findAndConsumeKey,
  countAllFreeKeys, countFreeKeysForContact, getAuditLog, getContacts, getDeviceId,
  setSharedSecret, getSharedSecret
};