require("dotenv").config();
const crypto = require("crypto");
const express = require("express");
const path = require("path");
const QRCode = require("qrcode");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");

const { sign, verify, decryptPayload } = require("./crypto");
const { generateKeyPool, consumeKey, findAndConsumeKey,
        countAllFreeKeys, getAuditLog, getContacts, getDeviceId,
        setSharedSecret, getSharedSecret } = require("./keyStore");

const app = express();

// ─── OWNER_ID ────────────────────────────────────────────────────
// FIX: Lève une erreur au démarrage si la variable n'est pas définie
// plutôt que d'utiliser silencieusement un fallback partagé "admin-esiee".
if (!process.env.NEXTCLOUD_USER) {
  console.error("❌ NEXTCLOUD_USER non défini dans .env — arrêt.");
  process.exit(1);
}
const OWNER_ID = process.env.NEXTCLOUD_USER;

// ─── SÉCURITÉ HTTP ───────────────────────────────────────────────
// FIX: Headers de sécurité (CSP, HSTS, X-Frame-Options, X-Content-Type-Options…)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
    }
  }
}));

// ─── RATE LIMITING ───────────────────────────────────────────────
// FIX: Empêche l'épuisement du pool de clés et le brute-force sur contact_id.
const defaultLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Trop de requêtes, réessayez dans 15 minutes." }
});

const sensitiveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Trop de requêtes, réessayez dans 15 minutes." }
});

app.use(defaultLimiter);

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// ─── HELPER : échapper les caractères HTML ───────────────────────
// FIX: Utilisé pour toutes les variables injectées dans du HTML généré (anti-XSS).
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

// ─── STATUS ──────────────────────────────────────────────────────
app.get("/status", async (req, res) => {
  const domain = process.env.RAILWAY_PUBLIC_DOMAIN;
  const public_url = domain ? `https://${domain}` : null;
  res.json({
    running: true,
    owner: OWNER_ID,
    device_id: await getDeviceId(),
    keys_available: await countAllFreeKeys(),
    version: "2.0.0-pqc",
    pqc_resistant: true,
    confidentiality: "OTP-XOR end-to-end",
    public_url  // null en local, URL Railway en prod
  });
});

// ─── CONTACTS (FILTRÉS) ──────────────────────────────────────────
app.get("/contacts", async (req, res) => {
  try {
    const all = await getContacts();
    const mine = all.filter(c => c.owner_id === OWNER_ID);
    res.json(mine);
  } catch (e) {
    res.json([]);
  }
});

// ─── AUDIT ───────────────────────────────────────────────────────
// FIX: Protégé par une clé admin (header x-admin-key).
// Définir ADMIN_KEY dans .env pour activer la protection.
app.get("/audit", async (req, res) => {
  const adminKey = process.env.ADMIN_KEY;
  if (adminKey && req.headers["x-admin-key"] !== adminKey) {
    return res.status(401).json({ error: "Non autorisé." });
  }
  res.json(await getAuditLog(parseInt(req.query.limit) || 50));
});

// ─── LE PACTE ────────────────────────────────────────────────────
app.post("/generate", sensitiveLimiter, async (req, res) => {
  const { contact_id, count = 50 } = req.body;
  if (!contact_id) return res.status(400).json({ error: "contact_id requis" });
  try {
    const pairSecret = crypto.randomBytes(32).toString("hex");
    await setSharedSecret(contact_id, pairSecret);
    const ids = await generateKeyPool(contact_id, count);
    res.json({
      success: true,
      generated: ids.length,
      pair_secret: pairSecret,
      message: `${ids.length} clés OTP générées. Secret de paire établi.`
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── SEND PACT EMAIL ─────────────────────────────────────────────
// Envoie le QR de pacte directement par email — le QR ne s'affiche
// jamais à l'écran, seul le destinataire légitime peut scanner.
app.post("/send-pact-email", sensitiveLimiter, async (req, res) => {
  const { to, from_name, meet_url } = req.body;
  if (!to || !from_name || !meet_url) {
    return res.status(400).json({ error: "to, from_name et meet_url requis" });
  }

  // Vérification basique de l'email
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
    return res.status(400).json({ error: "Email destinataire invalide" });
  }

  try {
    // Génère le QR en PNG base64
    const qrBuffer = await QRCode.toBuffer(meet_url, { width: 300, margin: 2 });

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT) || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    await transporter.sendMail({
      from: `"Enclave PQC" <${process.env.SMTP_USER}>`,
      to,
      subject: `🔐 Pacte de chiffrement — ${from_name}`,
      text: `${from_name} vous invite à établir un canal chiffré OTP via Enclave PQC.\n\nScannez le QR code en pièce jointe pour accepter le pacte.\n\nCe lien est unique et à usage unique.`,
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:auto;background:#0b0f1a;color:#e2eeff;padding:32px;border-radius:16px;">
          <h2 style="color:#00e5ff;margin-bottom:8px;">🔐 Enclave PQC</h2>
          <p style="color:#8ba3c7;margin-bottom:24px;">Canal chiffré One-Time Pad</p>
          <p><strong>${from_name}</strong> vous invite à établir un canal de communication chiffré.</p>
          <p style="margin:16px 0;color:#8ba3c7;">Scannez le QR code ci-dessous pour accepter le pacte. Ce lien est <strong>unique et secret</strong> — ne le partagez pas.</p>
          <div style="text-align:center;margin:24px 0;">
            <img src="cid:pact-qr" alt="QR Code Pacte" style="border-radius:12px;width:220px;height:220px;">
          </div>
          <p style="font-size:12px;color:#3d5470;margin-top:24px;">Enclave PQC-OTP — Chiffrement bout-en-bout garanti</p>
        </div>`,
      attachments: [{
        filename: 'pacte-enclave.png',
        content: qrBuffer,
        cid: 'pact-qr'   // référencé dans le HTML via cid:
      }]
    });

    res.json({ success: true });
  } catch (e) {
    console.error("Email error:", e.message);
    res.status(500).json({ error: "Échec envoi email : " + e.message });
  }
});

// ─── NEXTCLOUD ───────────────────────────────────────────────────
const {
  depositMessage, retrieveMessage, deleteMessage,
  ensureFolder, depositFile, retrieveFile, deleteFile
} = require("./nextcloud");

// ─── SEND ────────────────────────────────────────────────────────
app.post("/send", sensitiveLimiter, async (req, res) => {
  const { subject, body, contact_id, file_data, file_name } = req.body;
  if (!subject || !body || !contact_id) {
    return res.status(400).json({ error: "subject, body et contact_id requis" });
  }

  const pairSecret = await getSharedSecret(contact_id);
  if (!pairSecret) return res.status(400).json({ error: "Aucun secret de paire." });

  const keyData = await consumeKey(contact_id);
  if (!keyData) return res.status(400).json({ error: "Plus de clés disponibles." });

  try {
    let finalBody = body;
    let fileUploaded = false;

    if (file_data && file_name) {
      const fileBuffer = Buffer.from(file_data, "base64");
      await depositFile(keyData.id, fileBuffer, file_name);
      finalBody += `\n\n[PJ: ${file_name}]`;
      fileUploaded = true;
    }

    const result = sign(subject, finalBody, pairSecret, keyData.keyBlob);

    const payload = {
      v: 3,
      key_id: keyData.id,
      device_id: await getDeviceId(),
      encrypted_subject: result.encrypted_subject,
      subject_len: result.subject_len,
      encrypted_body: result.encrypted_body,
      body_len: result.body_len,
      ciphertext_b64: result.ciphertext_b64,
      file_name: fileUploaded ? file_name : null,
      sent_at: Date.now()
    };

    await depositMessage(keyData.id, payload);
    res.json({
      success: true,
      key_id: keyData.id,
      file_uploaded: fileUploaded,
      message: `Message chiffré & déposé sur NextCloud.`,
      confidentiality: "✅ Chiffré par XOR OTP"
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── RECEIVE ─────────────────────────────────────────────────────
app.post("/receive", sensitiveLimiter, async (req, res) => {
  const { key_id, contact_id } = req.body;
  if (!key_id || !contact_id) return res.status(400).json({ error: "Champs manquants" });

  try {
    const payload = await retrieveMessage(key_id);
    if (!payload) return res.status(404).json({ error: "Message introuvable." });

    const pairSecret = await getSharedSecret(contact_id);
    const keyData = await findAndConsumeKey(key_id, contact_id);
    if (!keyData) return res.status(400).json({ error: "Clé déjà détruite." });

    const { subject, body } = decryptPayload(payload, keyData.keyBlob);
    const ok = verify(subject, body, pairSecret, keyData.keyBlob, payload.ciphertext_b64);

    // FIX: Si la signature est invalide, on rejette sans dévoiler le contenu déchiffré.
    // La clé est déjà détruite (PFS garanti), on nettoie NextCloud proprement.
    if (!ok) {
      await deleteMessage(key_id);
      if (payload.file_name) await deleteFile(key_id, payload.file_name).catch(() => {});
      return res.status(400).json({ error: "Signature invalide — message rejeté." });
    }

    let fileData = null;
    if (payload.file_name) {
      const fileBuffer = await retrieveFile(key_id, payload.file_name);
      if (fileBuffer) {
        fileData = fileBuffer.toString("base64");
        await deleteFile(key_id, payload.file_name);
      }
    }

    await deleteMessage(key_id);

    res.json({
      valid: true,
      subject,
      body,
      file_name: payload.file_name,
      file_data: fileData,
      sent_at: payload.sent_at,
      pfs: "Clé détruite + message supprimé de NextCloud."
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── QR CODES ────────────────────────────────────────────────────
app.get("/qrcode/:contact_id", async (req, res) => {
  const contact_id = req.params.contact_id;
  try {
    const secret = await getSharedSecret(contact_id);
    if (!secret) return res.status(400).json({ error: "Faites d'abord le Pacte" });

    const domain = process.env.RAILWAY_PUBLIC_DOMAIN || "localhost:8080";
    const pactUrl = `https://${domain}/import-pact?contact_id=${encodeURIComponent(contact_id)}&secret=${encodeURIComponent(secret)}&from=${encodeURIComponent(await getDeviceId())}`;
    const qrDataUrl = await QRCode.toDataURL(pactUrl, { width: 300 });
    res.json({ qr: qrDataUrl, url: pactUrl });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/qrcode-identity", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "url requis" });
  try {
    const qrDataUrl = await QRCode.toDataURL(decodeURIComponent(url), { width: 300 });
    res.json({ qr: qrDataUrl });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── PAGES HTML ──────────────────────────────────────────────────
app.get("/import-pact", async (req, res) => {
  const { contact_id, secret, from } = req.query;

  // FIX XSS : escapeHtml() pour le contenu dans le DOM, JSON.stringify() pour
  // les valeurs dans le bloc <script>. JSON.stringify ajoute les guillemets
  // et échappe automatiquement les caractères dangereux (\, ", <, >, &).
  const safeFrom      = escapeHtml(from || "inconnu");
  const safeContactJs = JSON.stringify(contact_id || "");
  const safeSecretJs  = JSON.stringify(secret || "");

  res.send(`<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Enclave</title>
<style>
body{background:#060910;color:#e2eeff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
.card{background:#0b0f1a;border:1px solid #1c2840;border-radius:16px;padding:28px;max-width:400px;width:100%;text-align:center;}
h1{color:#00e5ff;font-size:1.2rem;margin-bottom:20px;}
button{background:#00e5ff;color:#000;border:none;border-radius:10px;padding:14px;font-weight:700;cursor:pointer;width:100%;}
</style>
</head>
<body>
<div class="card">
  <h1>🔐 ENCLAVE PQC</h1>
  <p>Pacte de <strong>${safeFrom}</strong></p>
  <button onclick="importPact()">Accepter le Pacte</button>
  <div id="ok" style="display:none;color:#00e676;margin-top:15px;">✅ Pacte établi !</div>
</div>
<script>
async function importPact() {
  const r = await fetch('/accept-pact', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contact_id: ${safeContactJs}, secret: ${safeSecretJs} })
  });
  const d = await r.json();
  if (d.success) document.getElementById('ok').style.display = 'block';
}
</script>
</body></html>`);
});

app.get("/meet", async (req, res) => {
  const { identity } = req.query;
  if (!identity) return res.status(400).send("Lien invalide");

  // FIX: try/catch — une URL malformée ne doit pas crasher le serveur Node.
  let data;
  try {
    data = JSON.parse(decodeURIComponent(identity));
    if (!data.email || !data.name || !data.device_id || !data.secret) {
      return res.status(400).send("Données d'identité incomplètes.");
    }
  } catch (e) {
    return res.status(400).send("Données d'identité invalides.");
  }

  const db = await require("./db").getDb();
  const contactId = 'contact-' + data.email.replace(/[@.]/g, '_');

  db.run("INSERT OR IGNORE INTO contacts (id,owner_id,name,device_id) VALUES (?,?,?,?)",
    [contactId, OWNER_ID, data.name, data.device_id]);

  await setSharedSecret(contactId, data.secret);
  require("./db").save();

  res.send(`<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Enclave</title>
<style>
body{background:#060910;color:#e2eeff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;}
.card{background:#0b0f1a;border:1px solid #1c2840;border-radius:16px;padding:30px;text-align:center;}
button{background:#00e5ff;padding:12px;border:none;border-radius:8px;cursor:pointer;font-weight:bold;}
</style>
</head>
<body>
<div class="card">
  <h1>✅ Contact ajouté</h1>
  <p>Le répertoire de <strong>${escapeHtml(OWNER_ID)}</strong> a été mis à jour.</p>
  <button onclick="window.location='/'">Retourner à l'Enclave</button>
</div>
</body></html>`);
});

app.post("/accept-pact", async (req, res) => {
  const { contact_id, secret } = req.body;
  if (!contact_id || !secret) return res.status(400).json({ error: "Champs manquants" });
  await setSharedSecret(contact_id, secret);
  res.json({ success: true });
});

// ─── DÉMARRAGE ───────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`\n🔐 Enclave PQC-OTP v2.0 opérationnelle`);
  console.log(`   → URL : https://enclave-pqc-production-7090.up.railway.app`);
  console.log(`   → Port : ${PORT}`);
  console.log(`   → Owner : ${OWNER_ID}\n`);
});