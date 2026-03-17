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
const { generateKeyPool, generatePairedKeyPool, consumeKey, findAndConsumeKey, findAndConsumeKeyByPair, countAllFreeKeys, countFreeKeysForContact, getAuditLog, getContacts, getDeviceId, setSharedSecret, getSharedSecret } = require("./keyStore");
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
const authLimiter      = mkLimit(50);   // 50 tentatives / 15min (assez strict sans bloquer les tests)
const sensitiveLimiter = mkLimit(100);
const defaultLimiter   = mkLimit(500);

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
  res.cookie("enclave_token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", maxAge: 86400000 });
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
    const _r1 = db.exec("SELECT id FROM users WHERE email=?", [email.toLowerCase()]);
    const ex = _r1.length ? { id: _r1[0].values[0][0] } : {};
    if (ex.id) return res.status(409).json({ error: "Cet email est déjà utilisé." });
    const id = "user-" + crypto.randomBytes(8).toString("hex");
    const device_id = "dev-" + crypto.randomBytes(4).toString("hex");
    const hash = await bcrypt.hash(password, 12);
    db.run("INSERT INTO users (id,email,password_hash,name,device_id) VALUES (?,?,?,?,?)", [id, email.toLowerCase(), hash, name.trim(), device_id]);
    require("./db").save();
    console.log('User registered:', email.toLowerCase(), id);
    const user = { id, email: email.toLowerCase(), name: name.trim(), device_id };
    res.status(201).json({ user: issueToken(res, user) });
  } catch(e) { console.error('Error:', e.message); res.status(500).json({ error: e.message }); }
});

// POST /auth/login
app.post("/auth/login", authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis." });
  try {
    const db = await require("./db").getDb();
    const _r2 = db.exec("SELECT id,email,password_hash,name,device_id FROM users WHERE email=?", [email.toLowerCase()]);
    const user = _r2.length ? { id:_r2[0].values[0][0], email:_r2[0].values[0][1], password_hash:_r2[0].values[0][2], name:_r2[0].values[0][3], device_id:_r2[0].values[0][4] } : {};
    if (!user.id) return res.status(401).json({ error: "Email ou mot de passe incorrect." });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Email ou mot de passe incorrect." });
    res.json({ user: issueToken(res, user) });
  } catch(e) { console.error('Error:', e.message); res.status(500).json({ error: e.message }); }
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
    const _r3 = db.exec("SELECT id,email,name,device_id FROM users WHERE id=?", [req.user.id]);
    const user = _r3.length ? { id:_r3[0].values[0][0], email:_r3[0].values[0][1], name:_r3[0].values[0][2], device_id:_r3[0].values[0][3] } : {};
    if (!user.id) return res.status(404).json({ error: "Introuvable." });
    res.json(user);
  } catch(e) { console.error('Error:', e.message); res.status(500).json({ error: e.message }); }
});

// GET /users/search
app.get("/users/search", authRequired, async (req, res) => {
  const q = (req.query.q || "").trim();
  if (q.length < 2) return res.status(400).json({ error: "2 caractères minimum." });
  try {
    const db = await require("./db").getDb();
    const p = `%${q}%`;
    console.log('Search query:', q, 'by user:', req.user.id);
    const raw = db.exec(
      "SELECT id,name,device_id FROM users WHERE (name LIKE ? OR email LIKE ?) AND id != ? LIMIT 20",
      [p, p, req.user.id]
    );
    const results = raw.length ? raw[0].values.map(([id,name,device_id]) => ({ id, name, device_id })) : [];

    const enriched = await Promise.all(results.map(async u => {
      const r2 = db.exec(
        "SELECT id,status FROM pact_requests WHERE (from_user_id=? AND to_user_id=?) OR (from_user_id=? AND to_user_id=?) ORDER BY created_at DESC LIMIT 1",
        [req.user.id, u.id, u.id, req.user.id]
      );
      const ex = r2.length ? { id: r2[0].values[0][0], status: r2[0].values[0][1] } : {};
      return { ...u, pact_status: ex.status || null, pact_request_id: ex.id || null };
    }));
    res.json(enriched);
  } catch(e) {
    console.error("Search error:", e.message);
    res.status(500).json({ error: "Erreur serveur : " + e.message });
  }
});

// POST /pact/request
app.post("/pact/request", sensitiveLimiter, authRequired, async (req, res) => {
  const { to_user_id } = req.body;
  if (!to_user_id) return res.status(400).json({ error: "to_user_id requis." });
  if (to_user_id === req.user.id) return res.status(400).json({ error: "Vous ne pouvez pas vous envoyer un pacte." });
  try {
    const db = await require("./db").getDb();
    const _r4 = db.exec("SELECT id FROM users WHERE id=?", [to_user_id]);
    const target = _r4.length ? { id: _r4[0].values[0][0] } : {};
    if (!target.id) return res.status(404).json({ error: "Utilisateur introuvable." });
    const _r5 = db.exec("SELECT id,status FROM pact_requests WHERE (from_user_id=? AND to_user_id=?) OR (from_user_id=? AND to_user_id=?) ORDER BY created_at DESC LIMIT 1", [req.user.id, to_user_id, to_user_id, req.user.id]);
    const ex = _r5.length ? { id:_r5[0].values[0][0], status:_r5[0].values[0][1] } : {};
    if (ex.status === 'accepted') return res.status(409).json({ error: "Pacte déjà actif." });
    if (ex.status === 'pending') return res.status(409).json({ error: "Demande déjà en attente." });
    const id = "req-" + crypto.randomBytes(8).toString("hex");
    db.run("INSERT INTO pact_requests (id,from_user_id,to_user_id) VALUES (?,?,?)", [id, req.user.id, to_user_id]);
    require("./db").save();
    res.status(201).json({ success: true });
  } catch(e) { console.error('Error:', e.message); res.status(500).json({ error: e.message }); }
});

// GET /pact/pending
app.get("/pact/pending", authRequired, async (req, res) => {
  try {
    const db = await require("./db").getDb();
    const raw = db.exec(
      "SELECT pr.id,pr.from_user_id,pr.created_at,u.name as from_name FROM pact_requests pr JOIN users u ON u.id=pr.from_user_id WHERE pr.to_user_id=? AND pr.status='pending' ORDER BY pr.created_at DESC",
      [req.user.id]
    );
    const rows = raw.length ? raw[0].values.map(([id,from_user_id,created_at,from_name]) => ({ id, from_user_id, created_at, from_name })) : [];
    res.json(rows);
  } catch(e) { console.error('Error:', e.message); res.status(500).json({ error: e.message }); }
});

// POST /pact/accept/:id
app.post("/pact/accept/:id", sensitiveLimiter, authRequired, async (req, res) => {
  try {
    const db = await require("./db").getDb();
    const _r6 = db.exec("SELECT id,from_user_id,to_user_id,status FROM pact_requests WHERE id=? AND to_user_id=?", [req.params.id, req.user.id]);
    const req2 = _r6.length ? { id:_r6[0].values[0][0], from_user_id:_r6[0].values[0][1], to_user_id:_r6[0].values[0][2], status:_r6[0].values[0][3] } : {};
    if (!req2.id) return res.status(404).json({ error: "Demande introuvable." });
    if (req2.status !== 'pending') return res.status(400).json({ error: "Demande non en attente." });

    const _r7 = db.exec("SELECT id,name,device_id FROM users WHERE id=?", [req2.from_user_id]);
    const uFrom = _r7.length ? { id:_r7[0].values[0][0], name:_r7[0].values[0][1], device_id:_r7[0].values[0][2] } : {};
    const _r8 = db.exec("SELECT id,name,device_id FROM users WHERE id=?", [req2.to_user_id]);
    const uTo = _r8.length ? { id:_r8[0].values[0][0], name:_r8[0].values[0][1], device_id:_r8[0].values[0][2] } : {};

    const pairSecret = crypto.randomBytes(32).toString("hex");
    const cid1 = `contact-${uFrom.id}-${uTo.id}`;
    const cid2 = `contact-${uTo.id}-${uFrom.id}`;

    db.run("INSERT OR REPLACE INTO contacts (id,owner_id,name,device_id,shared_secret) VALUES (?,?,?,?,?)", [cid1, uFrom.id, uTo.name, uTo.device_id, pairSecret]);
    db.run("INSERT OR REPLACE INTO contacts (id,owner_id,name,device_id,shared_secret) VALUES (?,?,?,?,?)", [cid2, uTo.id, uFrom.name, uFrom.device_id, pairSecret]);
    db.run("UPDATE pact_requests SET status='accepted' WHERE id=?", [req.params.id]);
    require("./db").save();

    await generatePairedKeyPool(cid1, cid2, 100);

    res.json({ success: true, message: "Canal chiffré établi — 200 clés (100 paires) générées." });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /pact/reject/:id
app.post("/pact/reject/:id", authRequired, async (req, res) => {
  try {
    const db = await require("./db").getDb();
    const _r9 = db.exec("SELECT id FROM pact_requests WHERE id=? AND to_user_id=? AND status='pending'", [req.params.id, req.user.id]);
    const r = _r9.length ? { id: _r9[0].values[0][0] } : {};
    if (!r.id) return res.status(404).json({ error: "Introuvable." });
    db.run("UPDATE pact_requests SET status='rejected' WHERE id=?", [req.params.id]);
    require("./db").save();
    res.json({ success: true });
  } catch(e) { console.error('Error:', e.message); res.status(500).json({ error: e.message }); }
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
    const filtered = all
      .filter(c => c.owner_id === req.user.id)
      .map(c => ({ ...c, has_secret: !!c.shared_secret }));
    res.json(filtered);
  } catch(e) { res.json([]); }
});

// GET /inbox : liste des IDs de messages disponibles pour cet utilisateur
app.get("/inbox", authRequired, async (req, res) => {
  try {
    const db = await require("./db").getDb();
    const query = `SELECT k.id AS key_id, c.id AS contact_id, c.name AS contact_name
                   FROM keys k
                   JOIN contacts c ON k.contact_id = c.id
                   WHERE c.owner_id = ? AND k.status = 'used'`;
    const rows = db.exec(query, [req.user.id]);
    const items = rows.length ? rows[0].values.map(([key_id, contact_id, contact_name]) => ({ key_id, contact_id, contact_name })) : [];
    res.json(items);
  } catch (e) {
    console.error("inbox error:", e.message);
    res.status(500).json({ error: "Erreur serveur." });
  }
});

// GET /audit
app.get("/audit", authRequired, async (req, res) => {
  const adminKey = process.env.ADMIN_KEY;
  if (adminKey && req.headers["x-admin-key"] !== adminKey) return res.status(401).json({ error: "Non autorisé." });
  res.json(await getAuditLog(parseInt(req.query.limit) || 50));
});

// POST /send
app.post("/send", sensitiveLimiter, authRequired, async (req, res) => {
  console.log('DEBUG /send called', { user: req.user?.id, subject: req.body?.subject, contact_id: req.body?.contact_id });
  const { subject, body, contact_id, file_data, file_name } = req.body;
  if (!subject || !body || !contact_id) return res.status(400).json({ error: "Champs manquants." });

  let ct = {};
  try {
    const db = await require("./db").getDb();
    const _ra = db.exec("SELECT id,shared_secret FROM contacts WHERE id=? AND owner_id=?", [contact_id, req.user.id]);
    ct = _ra.length ? { id: _ra[0].values[0][0], shared_secret: _ra[0].values[0][1] } : {};
    if (!ct.id) return res.status(403).json({ error: "Contact non autorisé." });
    if (!ct.shared_secret) return res.status(400).json({ error: "Aucun secret - le pacte n'a pas encore été accepté ou a été réinitialisé." });
  } catch(e) { return res.status(500).json({ error: "Erreur vérification." }); }

  // Utiliser le shared_secret déjà validé côté contact pour éviter incohérence
  const pairSecret = ct.shared_secret || await getSharedSecret(contact_id);
  if (!pairSecret) return res.status(400).json({ error: "Aucun secret - objet partagé manquant." });

  const parts = (contact_id || "").split("-");
  const partnerContactId = parts.length === 3 ? `contact-${parts[2]}-${parts[1]}` : null;
  if (!partnerContactId) return res.status(400).json({ error: "Format contact_id invalide." });

  let keyData = await consumeKey(contact_id);
  if (!keyData) {
    const freeKeys = await countFreeKeysForContact(contact_id);
    console.warn(`No free keys for contact ${contact_id} (${freeKeys} found) - generating paired batch`);
    await generatePairedKeyPool(contact_id, partnerContactId, 100);
    keyData = await consumeKey(contact_id);
    if (!keyData) {
      return res.status(500).json({ error: "Plus de clés disponibles même après rechargement. Contactez l'administrateur." });
    }
  }

  try {
    let finalBody = body, fileUploaded = false;
    if (file_data && file_name) {
      await depositFile(keyData.id, Buffer.from(file_data, "base64"), file_name);
      finalBody += `\n\n[PJ: ${file_name}]`;
      fileUploaded = true;
    }
    const result = sign(subject, finalBody, pairSecret, keyData.keyBlob);
    const payload = { v: 3, key_id: keyData.id, pair_id: keyData.pairId, device_id: await getDeviceId(), from_user_id: req.user.id, encrypted_subject: result.encrypted_subject, subject_len: result.subject_len, encrypted_body: result.encrypted_body, body_len: result.body_len, ciphertext_b64: result.ciphertext_b64, file_name: fileUploaded ? file_name : null, sent_at: Date.now() };
    await depositMessage(keyData.id, payload);
    res.json({ success: true, key_id: keyData.id, pair_id: keyData.pairId, file_uploaded: fileUploaded, message: "Message chiffré & déposé." });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /receive
app.post("/receive", sensitiveLimiter, authRequired, async (req, res) => {
  const { key_id, contact_id } = req.body;
  if (!key_id || !contact_id) return res.status(400).json({ error: "Champs manquants." });
  try {
    const db = await require("./db").getDb();
    const _rb = db.exec("SELECT id FROM contacts WHERE id=? AND owner_id=?", [contact_id, req.user.id]);
    const ct = _rb.length ? { id: _rb[0].values[0][0] } : {};
    if (!ct.id) return res.status(403).json({ error: "Contact non autorisé." });
  } catch(e) { return res.status(500).json({ error: "Erreur vérification." }); }

  try {
    const payload = await retrieveMessage(key_id);
    if (!payload) return res.status(404).json({ error: "Message introuvable." });
    const pairSecret = await getSharedSecret(contact_id);

    let keyData = null;
    if (payload.pair_id) {
      keyData = await findAndConsumeKeyByPair(contact_id, payload.pair_id);
    }

    if (!keyData) {
      // Backwards compatibility (ancienne version sans pair_id)
      keyData = await findAndConsumeKey(key_id, contact_id);
    }

    if (!keyData) return res.status(400).json({ error: "Clé déjà détruite ou non disponible." });
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
  } catch(e) { console.error('qrcode error:', e.message); res.status(500).json({ error: e.message }); }
});

// Pages publiques
app.get("/import-pact", async (req, res) => {
  const { contact_id, secret, from } = req.query;
  const sf = escapeHtml(from || "inconnu");
  const sc = JSON.stringify(contact_id || "");
  const ss = JSON.stringify(secret || "");
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Enclave</title><style>body{background:#060910;color:#e2eeff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;}.card{background:#0b0f1a;border:1px solid #1c2840;border-radius:16px;padding:28px;max-width:400px;width:100%;text-align:center;}h1{color:#00e5ff;}button{background:#00e5ff;color:#000;border:none;border-radius:10px;padding:14px;font-weight:700;cursor:pointer;width:100%;margin-top:16px;}</style></head><body><div class="card"><h1>🔐 ENCLAVE PQC</h1><p>Pacte de <strong>${sf}</strong></p><button onclick="importPact()">Accepter le Pacte</button><div id="ok" style="display:none;color:#00e676;margin-top:15px;">✅ Pacte établi !</div></div><script>async function importPact(){const r=await fetch('/accept-pact',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({contact_id:${sc},secret:${ss}})});const d=await r.json();if(d.success)document.getElementById('ok').style.display='block';}</script></body></html>`);
});

app.post("/accept-pact", authRequired, async (req, res) => {
  const { contact_id, secret } = req.body;
  if (!contact_id || !secret) return res.status(400).json({ error: "Champs manquants." });

  try {
    const db = await require("./db").getDb();
    const raw = db.exec("SELECT shared_secret FROM contacts WHERE id=?", [contact_id]);
    const contact = raw.length ? { shared_secret: raw[0].values[0][0] } : {};
    if (!contact.shared_secret && raw.length === 0) {
      return res.status(404).json({ error: "Contact inexistant." });
    }
    if (contact.shared_secret && contact.shared_secret !== secret) {
      return res.status(409).json({ error: "Secret incohérent ou déjà établi." });
    }

    await setSharedSecret(contact_id, secret);
    res.json({ success: true, message: "Secret partagé établi." });
  } catch (e) {
    console.error("accept-pact error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get("/debug/reset-contacts", authRequired, async (req, res) => {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey || req.headers["x-admin-key"] !== adminKey) return res.status(401).json({ error: "Non autorisé." });

  const db = await require("./db").getDb();
  db.run("DELETE FROM contacts");
  db.run("DELETE FROM pact_requests");
  db.run("DELETE FROM keys");
  require("./db").save();
  res.json({ success: true });
});
const PORT = process.env.PORT || 8080;
// Initialise la DB au démarrage pour créer les tables avant la première requête
require("./db").getDb().then(() => {
  console.log("✅ Base de données initialisée");
}).catch(e => {
  console.error("❌ Erreur init DB:", e.message);
  process.exit(1);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🔐 Enclave PQC-OTP v3.0 — Multi-utilisateur`);
  console.log(`   → Port : ${PORT}\n`);
});