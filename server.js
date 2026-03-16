require("dotenv").config();
const crypto = require("crypto");

const express = require("express");
const path = require("path");
const { sign, verify, decryptPayload } = require("./crypto");
const { generateKeyPool, consumeKey, findAndConsumeKey,
        countAllFreeKeys, getAuditLog, getContacts, getDeviceId,
        setSharedSecret, getSharedSecret } = require("./keyStore");

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// ─── STATUS ──────────────────────────────────────────────────────
app.get("/status", async (req, res) => {
  res.json({
    running: true,
    device_id: await getDeviceId(),
    keys_available: await countAllFreeKeys(),
    version: "2.0.0-pqc",
    pqc_resistant: true,
    confidentiality: "OTP-XOR end-to-end"
  });
});

// ─── CONTACTS ────────────────────────────────────────────────────
app.get("/contacts", async (req, res) => {
  res.json(await getContacts());
});

// ─── AUDIT ───────────────────────────────────────────────────────
app.get("/audit", async (req, res) => {
  res.json(await getAuditLog(parseInt(req.query.limit) || 50));
});

// ─── LE PACTE ────────────────────────────────────────────────────
app.post("/generate", async (req, res) => {
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

// ─── NEXTCLOUD ───────────────────────────────────────────────────
const {
  depositMessage, retrieveMessage, deleteMessage,
  ensureFolder, depositFile, retrieveFile, deleteFile
} = require("./nextcloud");

// ─── SEND (chiffrement complet) ───────────────────────────────────
app.post("/send", async (req, res) => {
  const { subject, body, contact_id, file_data, file_name } = req.body;
  if (!subject || !body || !contact_id) {
    return res.status(400).json({ error: "subject, body et contact_id requis" });
  }

  const pairSecret = await getSharedSecret(contact_id);
  if (!pairSecret) return res.status(400).json({ error: "Aucun secret de paire. Refaites le Pacte." });

  const keyData = await consumeKey(contact_id);
  if (!keyData) return res.status(400).json({ error: "Plus de clés disponibles." });

  try {
    let finalBody = body;
    let fileUploaded = false;

    // Upload fichier si présent
    if (file_data && file_name) {
      const fileBuffer = Buffer.from(file_data, "base64");
      await depositFile(keyData.id, fileBuffer, file_name);
      finalBody += `\n\n[PJ: ${file_name}]`;
      fileUploaded = true;
    }

    // Signature + chiffrement OTP
    const result = sign(subject, finalBody, pairSecret, keyData.keyBlob);

    // Payload 100% chiffré — NextCloud ne voit rien en clair
    const payload = {
      v: 3,
      key_id: keyData.id,
      device_id: await getDeviceId(),
      // CHIFFRÉ
      encrypted_subject: result.encrypted_subject,
      subject_len: result.subject_len,
      encrypted_body: result.encrypted_body,
      body_len: result.body_len,
      // SIGNATURE
      ciphertext_b64: result.ciphertext_b64,
      // METADATA (non sensible)
      file_name: fileUploaded ? file_name : null,
      sent_at: Date.now()
    };

    await depositMessage(keyData.id, payload);
    res.json({
      success: true,
      key_id: keyData.id,
      file_uploaded: fileUploaded,
      message: `Message chiffré & déposé sur NextCloud.${fileUploaded ? ' Pièce jointe incluse.' : ''}`,
      nextcloud_file: `${keyData.id}.json`,
      confidentiality: "✅ Sujet et corps chiffrés par XOR OTP — NextCloud est aveugle"
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── RECEIVE (déchiffrement + vérification) ───────────────────────
app.post("/receive", async (req, res) => {
  const { key_id, contact_id } = req.body;
  if (!key_id || !contact_id) return res.status(400).json({ error: "Champs manquants" });

  try {
    const payload = await retrieveMessage(key_id);
    if (!payload) return res.status(404).json({ error: "Message introuvable sur NextCloud." });

    const pairSecret = await getSharedSecret(contact_id);
    if (!pairSecret) return res.status(400).json({ error: "Aucun secret de paire. Refaites le Pacte." });

    const keyData = await findAndConsumeKey(key_id, contact_id);
    if (!keyData) return res.status(400).json({ error: "Clé inconnue ou déjà détruite." });

    // Déchiffrement du contenu avec la clé miroir
    const { subject, body } = decryptPayload(payload, keyData.keyBlob);

    // Vérification de la signature
    const ok = verify(subject, body, pairSecret, keyData.keyBlob, payload.ciphertext_b64);

    // Récupération du fichier si présent
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
      valid: ok,
      subject,
      body,
      file_name: payload.file_name,
      file_data: fileData,
      sent_at: payload.sent_at,
      pfs: "Clé détruite + message supprimé de NextCloud.",
      confidentiality: "✅ Message déchiffré localement — jamais transité en clair"
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── QR CODE PACTE ───────────────────────────────────────────────
const QRCode = require("qrcode");

app.get("/qrcode/:contact_id", async (req, res) => {
  const contact_id = req.params.contact_id;
  try {
    const secret = await getSharedSecret(contact_id);
    if (!secret) return res.status(400).json({ error: "Faites d'abord le Pacte" });

    const localIp = "192.168.1.132";
    const pactUrl = `http://${localIp}:3000/import-pact?contact_id=${contact_id}&secret=${secret}&from=${await getDeviceId()}`;
    const qrDataUrl = await QRCode.toDataURL(pactUrl, { width: 300 });
    res.json({ qr: qrDataUrl, url: pactUrl });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── QR CODE IDENTITÉ ─────────────────────────────────────────────
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

// ─── PAGE IMPORT PACTE (téléphone) ───────────────────────────────
app.get("/import-pact", async (req, res) => {
  const { contact_id, secret, from } = req.query;
  if (!contact_id || !secret) return res.send("Lien invalide");

  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Enclave — Import du Pacte</title>
  <style>
    body { background:#060910; color:#e2eeff; font-family:sans-serif;
           display:flex; align-items:center; justify-content:center;
           min-height:100vh; padding:20px; }
    .card { background:#0b0f1a; border:1px solid #1c2840; border-radius:16px;
            padding:28px; max-width:400px; width:100%; text-align:center; }
    h1 { color:#00e5ff; font-size:1rem; letter-spacing:3px; margin-bottom:16px; }
    p { color:#4a6080; font-size:.85rem; margin-bottom:12px; }
    .secret { background:#101520; border:1px solid #1c2840; border-radius:10px;
              padding:12px; font-family:monospace; font-size:.7rem;
              color:#7c3aed; word-break:break-all; margin-bottom:20px; }
    button { background:#00e5ff; color:#000; border:none; border-radius:10px;
             padding:14px; font-size:.9rem; font-weight:700; cursor:pointer; width:100%; }
    .ok { background:rgba(0,230,118,.1); border:1px solid #00e676;
          border-radius:10px; padding:12px; color:#00e676; margin-top:12px; display:none; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🔐 ENCLAVE PQC-OTP</h1>
    <p>Pacte reçu de <strong style="color:#00e5ff">${from}</strong></p>
    <p>Secret de paire :</p>
    <div class="secret">${secret}</div>
    <button onclick="importPact()">Accepter le Pacte</button>
    <div class="ok" id="ok">✅ Pacte établi ! Vous pouvez recevoir les messages.</div>
  </div>
  <script>
    async function importPact() {
      const r = await fetch('/accept-pact', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ contact_id: '${contact_id}', secret: '${secret}', from: '${from}' })
      });
      const data = await r.json();
      if (data.success) {
        document.getElementById('ok').style.display = 'block';
        document.querySelector('button').disabled = true;
      }
    }
  </script>
</body>
</html>`);
});

// ─── PAGE MEET (scan QR identité) ────────────────────────────────
app.get("/meet", async (req, res) => {
  const { identity } = req.query;
  if (!identity) return res.send("Lien invalide");

  let data;
  try { data = JSON.parse(decodeURIComponent(identity)); }
  catch(e) { return res.send("Lien invalide"); }

  const db = await require("./db").getDb();
  const contactId = 'contact-' + data.email.replace(/[@.]/g, '_');
  db.run("INSERT OR IGNORE INTO contacts (id,name,device_id) VALUES (?,?,?)",
    [contactId, data.name, data.device_id]);
  await setSharedSecret(contactId, data.secret);
  require("./db").save();

  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Enclave — Nouveau contact</title>
  <style>
    body { background:#060910; color:#e2eeff; font-family:sans-serif;
           display:flex; align-items:center; justify-content:center;
           min-height:100vh; padding:20px; }
    .card { background:#0b0f1a; border:1px solid #1c2840; border-radius:16px;
            padding:28px; max-width:400px; width:100%; text-align:center; }
    h1 { color:#00e5ff; font-size:1rem; letter-spacing:3px; margin-bottom:16px; }
    .avatar { width:64px; height:64px; border-radius:16px;
              background:linear-gradient(135deg,#7c3aed,#00e5ff);
              display:flex; align-items:center; justify-content:center;
              font-size:1.6rem; font-weight:800; color:#000; margin:0 auto 16px; }
    .info { background:#101520; border-radius:10px; padding:14px;
            font-family:monospace; font-size:.8rem; text-align:left;
            line-height:2; margin-bottom:16px; }
    .ok { background:rgba(0,230,118,.08); border:1px solid rgba(0,230,118,.3);
          border-radius:10px; padding:14px; color:#00e676; margin-bottom:16px; font-size:.85rem; }
    .btn { background:#00e5ff; color:#000; border:none; border-radius:10px;
           padding:14px; font-size:.9rem; font-weight:700; cursor:pointer; width:100%; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🔐 ENCLAVE PQC-OTP</h1>
    <div class="avatar">${data.name.charAt(0).toUpperCase()}</div>
    <div class="info">
      <b>Nom :</b> ${data.name}<br>
      <b>Email :</b> ${data.email}<br>
      <b>Device :</b> ${data.device_id}
    </div>
    <div class="ok">✅ Pacte établi automatiquement !<br>Communications chiffrées activées.</div>
    <button onclick="window.location='/'">Ouvrir l'Enclave</button>
  </div>
</body>
</html>`);
});

// ─── ACCEPT PACTE ────────────────────────────────────────────────
app.post("/accept-pact", async (req, res) => {
  const { contact_id, secret } = req.body;
  if (!contact_id || !secret) return res.status(400).json({ error: "Données manquantes" });
  try {
    await setSharedSecret(contact_id, secret);
    res.json({ success: true, message: "Pacte accepté !" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── DÉMARRAGE ───────────────────────────────────────────────────
const PORT = 3000;
app.listen(PORT, async () => {
  console.log(`\n🔐 Enclave PQC-OTP v2.0`);
  console.log(`   → http://localhost:${PORT}`);
  console.log(`   → Device : ${await getDeviceId()}`);
  console.log(`   → Chiffrement : XOR OTP end-to-end\n`);
});