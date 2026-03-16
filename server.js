require("dotenv").config();
const crypto  = require("crypto");
const express = require("express");
const path    = require("path");
const QRCode  = require("qrcode");
const helmet  = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const jwt     = require("jsonwebtoken");
const bcrypt  = require("bcryptjs");

const { sign, verify, decryptPayload } = require("./crypto");
const { generateKeyPool, consumeKey, findAndConsumeKey, countAllFreeKeys, getAuditLog, getContacts, getDeviceId, setSharedSecret, getSharedSecret } = require("./keyStore");
const { depositMessage, retrieveMessage, deleteMessage, depositFile, retrieveFile, deleteFile } = require("./nextcloud");

// Variables requises
["JWT_SECRET","NEXTCLOUD_USER","NEXTCLOUD_PASS","NEXTCLOUD_URL"].forEach(v => {
  if (!process.env[v]) { console.error(`Manquant: ${v}`); process.exit(1); }
});
const JWT_SECRET = process.env.JWT_SECRET;

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'","'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'","'unsafe-inline'","https://fonts.googleapis.com"],
      fontSrc: ["'self'","https://fonts.gstatic.com"],
      imgSrc: ["'self'","data:"],
    }
  }
}));

const mkLimit = (max) => rateLimit({ windowMs: 15*60*1000, max, standardHeaders: true, legacyHeaders: false, message: { error: "Trop de requêtes." } });
const authLimiter      = mkLimit(10);
const sensitiveLimiter = mkLimit(30);
const defaultLimiter   = mkLimit(200);

app.use(defaultLimiter);
app.use(cookieParser());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Helpers
const escapeHtml = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#x27;");
const isValidEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);

// Auth
function authRequired(req, res, next) {
  const token = req.cookies?.enclave_token;
  if (!token) return res.status(401).json({ error: "Non authentifié" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.clearCookie("enclave_token"); return res.status(401).json({ error: "Session expirée" }); }
}

function issueToken(res, user) {
  const payload = { id: user.id, email: user.email, name: user.name };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "24h" });
  res.cookie("enclave_token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", maxAge: 86400000 });
  return payload;
}

// POST /auth/register
app.post("/auth/register", authLimiter, async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "Tous les champs sont requis." });
  if (String(name).trim().length < 2) return res.status(400).json({ error: "Nom trop court." });
  if (!isValidEmail(email)) return res.status(400).json({ error: "Email invalide." });
  if (String(password).length < 8) return res.status(400).json({ error: "Mot de passe trop court (8 caractères min)." });
  try {
    const db = await require("./db").getDb();
    const stmt = db.prepare("SELECT id FROM users WHERE email=?");
    const ex = stmt.getAsObject({ 1: email.toLowerCase() });
    stmt.free();
    if (ex.id) return res.status(409).json({ error: "Cet email est déjà utilisé." });
    const id = "user-" + crypto.randomBytes(8).toString("hex");
    const device_id = "dev-" + crypto.randomBytes(4).toString("hex");
    const hash = await bcrypt.hash(password, 12);
    db.run("INSERT INTO users (id,email,password_hash,name,device_id) VALUES (?,?,?,?,?)", [id, email.toLowerCase(), hash, name.trim(), device_id]);
    require("./db").save();
    const user = { id, email: email.toLowerCase(), name: name.trim(), device_id };
    res.status(201).json({ user: issueToken(res, user) });
  } catch(e) { res.status(500).json({ error: "Erreur serveur." }); }
});

// POST /auth/login
app.post("/auth/login", authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis." });
  try {
    const db = await require("./db").getDb();
    const stmt = db.prepare("SELECT id,email,password_hash,name,device_id FROM users WHERE email=?");
    const user = stmt.getAsObject({ 1: email.toLowerCase() });
    stmt.free();
    const fake = "$2a$12$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const valid = await bcrypt.compare(password, user.password_hash || fake);
    if (!user.id || !valid) return res.status(401).json({ error: "Email ou mot de passe incorrect." });
    res.json({ user: issueToken(res, user) });
  } catch(e) { res.status(500).json({ error: "Erreur serveur." }); }
});

// POST /auth/logout
app.post("/auth/logout", (req, res) => {
  res.clearCookie("enclave_token");
  res.json({ success: true });
});

// GET /auth/me
app.get("/auth/me", authRequired, async (req, res) => {
  try {
    const db = await require("./db").getDb();
    const stmt = db.prepare("SELECT id,email,name,device_id FROM users WHERE id=?");
    const user = stmt.getAsObject({ 1: req.user.id });
    stmt.free();
    if (!user.id) return res.status(404).json({ error: "Introuvable." });
    res.json(user);
  } catch(e) { res.status(500).json({ error: "Erreur serveur." }); }
});

// GET /users/search
app.get("/users/search", authRequired, async (req, res) => {
  const q = (req.query.q || "").trim();
  if (q.length < 2) return res.status(400).json({ error: "2 caractères minimum." });
  try {
    const db = await require("./db").getDb();
    const stmt = db.prepare("SELECT id,name,device_id FROM users WHERE (name LIKE ? OR email LIKE ?) AND id != ? LIMIT 20");
    const results = [];
    const p = `%${q}%`;
    stmt.bind({ 1: p, 2: p, 3: req.user.id });
    while (stmt.step()) results.push(stmt.getAsObject());
    stmt.free();
    const enriched = await Promise.all(results.map(async u => {
      const s = db.prepare("SELECT id,status FROM pact_requests WHERE (from_user_id=? AND to_user_id=?) OR (from_user_id=? AND to_user_id=?) ORDER BY created_at DESC LIMIT 1");
      const ex = s.getAsObject({ 1: req.user.id, 2: u.id, 3: u.id, 4: req.user.id });
      s.free();
      return { ...u, pact_status: ex.status || null, pact_request_id: ex.id || null };
    }));
    res.json(enriched);
  } catch(e) { res.status(500).json({ error: "Erreur serveur." }); }
});

// POST /pact/request
app.post("/pact/request", sensitiveLimiter, authRequired, async (req, res) => {
  const { to_user_id } = req.body;
  if (!to_user_id) return res.status(400).json({ error: "to_user_id requis." });
  if (to_user_id === req.user.id) return res.status(400).json({ error: "Vous ne pouvez pas vous envoyer un pacte." });
  try {
    const db = await require("./db").getDb();
    const us = db.prepare("SELECT id FROM users WHERE id=?");
    const target = us.getAsObject({ 1: to_user_id });
    us.free();
    if (!target.id) return res.status(404).json({ error: "Utilisateur introuvable." });
    const ps = db.prepare("SELECT id,status FROM pact_requests WHERE (from_user_id=? AND to_user_id=?) OR (from_user_id=? AND to_user_id=?) ORDER BY created_at DESC LIMIT 1");
    const ex = ps.getAsObject({ 1: req.user.id, 2: to_user_id, 3: to_user_id, 4: req.user.id });
    ps.free();
    if (ex.status === 'accepted') return res.status(409).json({ error: "Pacte déjà actif." });
    if (ex.status === 'pending') return res.status(409).json({ error: "Demande déjà en attente." });
    const id = "req-" + crypto.randomBytes(8).toString("hex");
    db.run("INSERT INTO pact_requests (id,from_user_id,to_user_id) VALUES (?,?,?)", [id, req.user.id, to_user_id]);
    require("./db").save();
    res.status(201).json({ success: true });
  } catch(e) { res.status(500).json({ error: "Erreur serveur." }); }
});

// GET /pact/pending
app.get("/pact/pending", authRequired, async (req, res) => {
  try {
    const db = await require("./db").getDb();
    const stmt = db.prepare("SELECT pr.id,pr.from_user_id,pr.created_at,u.name as from_name FROM pact_requests pr JOIN users u ON u.id=pr.from_user_id WHERE pr.to_user_id=? AND pr.status='pending' ORDER BY pr.created_at DESC");
    const rows = [];
    stmt.bind({ 1: req.user.id });
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    res.json(rows);
  } catch(e) { res.status(500).json({ error: "Erreur serveur." }); }
});

// POST /pact/accept/:id
app.post("/pact/accept/:id", sensitiveLimiter, authRequired, async (req, res) => {
  try {
    const db = await require("./db").getDb();
    const rs = db.prepare("SELECT id,from_user_id,to_user_id,status FROM pact_requests WHERE id=? AND to_user_id=?");
    const req2 = rs.getAsObject({ 1: req.params.id, 2: req.user.id });
    rs.free();
    if (!req2.id) return res.status(404).json({ error: "Demande introuvable." });
    if (req2.status !== 'pending') return res.status(400).json({ error: "Demande non en attente." });

    const u1s = db.prepare("SELECT id,name,device_id FROM users WHERE id=?");
    const uFrom = u1s.getAsObject({ 1: req2.from_user_id }); u1s.free();
    const u2s = db.prepare("SELECT id,name,device_id FROM users WHERE id=?");
    const uTo = u2s.getAsObject({ 1: req2.to_user_id }); u2s.free();

    const pairSecret = crypto.randomBytes(32).toString("hex");
    const cid1 = `contact-${uFrom.id}-${uTo.id}`;
    const cid2 = `contact-${uTo.id}-${uFrom.id}`;

    db.run("INSERT OR REPLACE INTO contacts (id,owner_id,name,device_id,shared_secret) VALUES (?,?,?,?,?)", [cid1, uFrom.id, uTo.name, uTo.device_id, pairSecret]);
    db.run("INSERT OR REPLACE INTO contacts (id,owner_id,name,device_id,shared_secret) VALUES (?,?,?,?,?)", [cid2, uTo.id, uFrom.name, uFrom.device_id, pairSecret]);
    db.run("UPDATE pact_requests SET status='accepted' WHERE id=?", [req.params.id]);
    require("./db").save();

    await generateKeyPool(cid1, 100);
    await generateKeyPool(cid2, 100);

    res.json({ success: true, message: "Canal chiffré établi — 200 clés générées." });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /pact/reject/:id
app.post("/pact/reject/:id", authRequired, async (req, res) => {
  try {
    const db = await require("./db").getDb();
    const s = db.prepare("SELECT id FROM pact_requests WHERE id=? AND to_user_id=? AND status='pending'");
    const r = s.getAsObject({ 1: req.params.id, 2: req.user.id }); s.free();
    if (!r.id) return res.status(404).json({ error: "Introuvable." });
    db.run("UPDATE pact_requests SET status='rejected' WHERE id=?", [req.params.id]);
    require("./db").save();
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: "Erreur serveur." }); }
});

// GET /status
app.get("/status", authRequired, async (req, res) => {
  const domain = process.env.RAILWAY_PUBLIC_DOMAIN;
  res.json({ running: true, device_id: await getDeviceId(), keys_available: await countAllFreeKeys(), version: "3.0.0", public_url: domain ? `https://${domain}` : null });
});

// GET /contacts
app.get("/contacts", authRequired, async (req, res) => {
  try {
    const all = await getContacts();
    res.json(all.filter(c => c.owner_id === req.user.id));
  } catch(e) { res.json([]); }
});

// GET /audit
app.get("/audit", authRequired, async (req, res) => {
  const adminKey = process.env.ADMIN_KEY;
  if (adminKey && req.headers["x-admin-key"] !== adminKey) return res.status(401).json({ error: "Non autorisé." });
  res.json(await getAuditLog(parseInt(req.query.limit) || 50));
});

// POST /send
app.post("/send", sensitiveLimiter, authRequired, async (req, res) => {
  const { subject, body, contact_id, file_data, file_name } = req.body;
  if (!subject || !body || !contact_id) return res.status(400).json({ error: "Champs manquants." });
  try {
    const db = await require("./db").getDb();
    const cs = db.prepare("SELECT id FROM contacts WHERE id=? AND owner_id=?");
    const ct = cs.getAsObject({ 1: contact_id, 2: req.user.id }); cs.free();
    if (!ct.id) return res.status(403).json({ error: "Contact non autorisé." });
  } catch(e) { return res.status(500).json({ error: "Erreur vérification." }); }

  const pairSecret = await getSharedSecret(contact_id);
  if (!pairSecret) return res.status(400).json({ error: "Aucun secret." });
  const keyData = await consumeKey(contact_id);
  if (!keyData) return res.status(400).json({ error: "Plus de clés disponibles." });

  try {
    let finalBody = body, fileUploaded = false;
    if (file_data && file_name) {
      await depositFile(keyData.id, Buffer.from(file_data, "base64"), file_name);
      finalBody += `\n\n[PJ: ${file_name}]`;
      fileUploaded = true;
    }
    const result = sign(subject, finalBody, pairSecret, keyData.keyBlob);
    const payload = { v: 3, key_id: keyData.id, device_id: await getDeviceId(), from_user_id: req.user.id, encrypted_subject: result.encrypted_subject, subject_len: result.subject_len, encrypted_body: result.encrypted_body, body_len: result.body_len, ciphertext_b64: result.ciphertext_b64, file_name: fileUploaded ? file_name : null, sent_at: Date.now() };
    await depositMessage(keyData.id, payload);
    res.json({ success: true, key_id: keyData.id, file_uploaded: fileUploaded, message: "Message chiffré & déposé." });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /receive
app.post("/receive", sensitiveLimiter, authRequired, async (req, res) => {
  const { key_id, contact_id } = req.body;
  if (!key_id || !contact_id) return res.status(400).json({ error: "Champs manquants." });
  try {
    const db = await require("./db").getDb();
    const cs = db.prepare("SELECT id FROM contacts WHERE id=? AND owner_id=?");
    const ct = cs.getAsObject({ 1: contact_id, 2: req.user.id }); cs.free();
    if (!ct.id) return res.status(403).json({ error: "Contact non autorisé." });
  } catch(e) { return res.status(500).json({ error: "Erreur vérification." }); }

  try {
    const payload = await retrieveMessage(key_id);
    if (!payload) return res.status(404).json({ error: "Message introuvable." });
    const pairSecret = await getSharedSecret(contact_id);
    const keyData = await findAndConsumeKey(key_id, contact_id);
    if (!keyData) return res.status(400).json({ error: "Clé déjà détruite." });
    const { subject, body } = decryptPayload(payload, keyData.keyBlob);
    const ok = verify(subject, body, pairSecret, keyData.keyBlob, payload.ciphertext_b64);
    if (!ok) {
      await deleteMessage(key_id);
      if (payload.file_name) await deleteFile(key_id, payload.file_name).catch(() => {});
      return res.status(400).json({ error: "Signature invalide — message rejeté." });
    }
    let fileData = null;
    if (payload.file_name) {
      const fb = await retrieveFile(key_id, payload.file_name);
      if (fb) { fileData = fb.toString("base64"); await deleteFile(key_id, payload.file_name); }
    }
    await deleteMessage(key_id);
    res.json({ valid: true, subject, body, file_name: payload.file_name, file_data: fileData, sent_at: payload.sent_at, pfs: "Clé détruite + message supprimé." });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /qrcode/:contact_id
app.get("/qrcode/:contact_id", authRequired, async (req, res) => {
  try {
    const secret = await getSharedSecret(req.params.contact_id);
    if (!secret) return res.status(400).json({ error: "Aucun secret." });
    const domain = process.env.RAILWAY_PUBLIC_DOMAIN || "localhost:8080";
    const url = `https://${domain}/import-pact?contact_id=${encodeURIComponent(req.params.contact_id)}&secret=${encodeURIComponent(secret)}&from=${encodeURIComponent(await getDeviceId())}`;
    res.json({ qr: await QRCode.toDataURL(url, { width: 300 }), url });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Pages publiques
app.get("/import-pact", async (req, res) => {
  const { contact_id, secret, from } = req.query;
  const sf = escapeHtml(from || "inconnu");
  const sc = JSON.stringify(contact_id || "");
  const ss = JSON.stringify(secret || "");
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Enclave</title><style>body{background:#060910;color:#e2eeff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;}.card{background:#0b0f1a;border:1px solid #1c2840;border-radius:16px;padding:28px;max-width:400px;width:100%;text-align:center;}h1{color:#00e5ff;}button{background:#00e5ff;color:#000;border:none;border-radius:10px;padding:14px;font-weight:700;cursor:pointer;width:100%;margin-top:16px;}</style></head><body><div class="card"><h1>🔐 ENCLAVE PQC</h1><p>Pacte de <strong>${sf}</strong></p><button onclick="importPact()">Accepter le Pacte</button><div id="ok" style="display:none;color:#00e676;margin-top:15px;">✅ Pacte établi !</div></div><script>async function importPact(){const r=await fetch('/accept-pact',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({contact_id:${sc},secret:${ss}})});const d=await r.json();if(d.success)document.getElementById('ok').style.display='block';}</script></body></html>`);
});

app.post("/accept-pact", async (req, res) => {
  const { contact_id, secret } = req.body;
  if (!contact_id || !secret) return res.status(400).json({ error: "Champs manquants." });
  await setSharedSecret(contact_id, secret);
  res.json({ success: true });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🔐 Enclave PQC-OTP v3.0 — Multi-utilisateur`);
  console.log(`   → Port : ${PORT}\n`);
});