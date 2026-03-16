const crypto = require("crypto");
const { getDb, save } = require("./db");
const KEY_SIZE = 256;

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

async function consumeKey(contactId) {
  const db = await getDb();
  const res = db.exec(`SELECT id, key_blob FROM keys WHERE contact_id='${contactId}' AND status='free' LIMIT 1`);
  if (!res.length || !res[0].values.length) return null;
  const [id, keyBlob] = res[0].values[0];
  // On marque 'used' mais on ne détruit pas encore — destruction après vérification
  db.run("UPDATE keys SET status='used' WHERE id=?", [id]);
  db.run("INSERT INTO audit_log (key_id,contact_id,action,detail) VALUES (?,?,'USED','Signed - awaiting verification')", [id, contactId]);
  save();
  return { id, keyBlob: Buffer.from(keyBlob) };
}

async function findAndConsumeKey(keyId, contactId) {
  const db = await getDb();
  const res = db.exec(`SELECT id, key_blob FROM keys WHERE id='${keyId}' AND contact_id='${contactId}' AND status='used'`);
  if (!res.length || !res[0].values.length) return null;
  const [id, keyBlob] = res[0].values[0];
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

async function getAuditLog(limit = 50) {
  const db = await getDb();
  const res = db.exec(`SELECT a.timestamp, a.action, a.key_id, c.name, a.detail FROM audit_log a LEFT JOIN contacts c ON a.contact_id=c.id ORDER BY a.timestamp DESC LIMIT ${limit}`);
  if (!res.length) return [];
  return res[0].values.map(([timestamp, action, key_id, contact_name, detail]) => ({ timestamp, action, key_id, contact_name, detail }));
}

async function getContacts() {
  const db = await getDb();
  const res = db.exec(`SELECT c.id, c.name, c.device_id, COUNT(k.id) as free_keys FROM contacts c LEFT JOIN keys k ON k.contact_id=c.id AND k.status='free' GROUP BY c.id`);
  if (!res.length) return [];
  return res[0].values.map(([id, name, device_id, free_keys]) => ({ id, name, device_id, free_keys }));
}

async function setSharedSecret(contactId, secret) {
  const db = await getDb();
  db.run("UPDATE contacts SET shared_secret=? WHERE id=?", [secret, contactId]);
  save();
}

async function getSharedSecret(contactId) {
  const db = await getDb();
  const res = db.exec(`SELECT shared_secret FROM contacts WHERE id='${contactId}'`);
  if (!res.length || !res[0].values[0][0]) return null;
  return res[0].values[0][0];
}

async function getDeviceId() {
  const db = await getDb();
  const res = db.exec("SELECT value FROM config WHERE key='device_id'");
  return res.length ? res[0].values[0][0] : "unknown";
}

module.exports = {
  generateKeyPool, consumeKey, findAndConsumeKey,
  countAllFreeKeys, getAuditLog, getContacts, getDeviceId,
  setSharedSecret, getSharedSecret
};