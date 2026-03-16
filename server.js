require("dotenv").config();
const crypto = require("crypto");
const express = require("express");
const path = require("path");
const QRCode = require("qrcode");

const { sign, verify, decryptPayload } = require("./crypto");
const { generateKeyPool, consumeKey, findAndConsumeKey,
        countAllFreeKeys, getAuditLog, getContacts, getDeviceId,
        setSharedSecret, getSharedSecret } = require("./keyStore");

const app = express();

// IDENTIFIANT UNIQUE POUR RAILWAY
const OWNER_ID = process.env.NEXTCLOUD_USER || "admin-esiee";

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// ─── STATUS ──────────────────────────────────────────────────────
app.get("/status", async (req, res) => {
  res.json({
    running: true,
    owner: OWNER_ID,
    device_id: await getDeviceId(),
    keys_available: await countAllFreeKeys(),
    version: "2.0.0-pqc",
    pqc_resistant: true,
    confidentiality: "OTP-XOR end-to-end"
  });
});

// ─── CONTACTS (FILTRÉS) ──────────────────────────────────────────
app.get("/contacts", async (req, res) => {
  try {
    const all = await getContacts();
    // On ne montre que les contacts qui nous appartiennent
    const mine = all.filter(c => c.owner_id === OWNER_ID);
    res.json(mine);
  } catch (e) {
    res.json([]);
  }
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

// ─── SEND ────────────────────────────────────────────────────────
app.post("/send", async (req, res) => {
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
app.post("/receive", async (req, res) => {
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

    // On utilise l'URL publique Railway au lieu de l'IP locale
    const domain = process.env.RAILWAY_PUBLIC_DOMAIN || "localhost:3000";
    const pactUrl = `https://${domain}/import-pact?contact_id=${contact_id}&secret=${secret}&from=${await getDeviceId()}`;
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
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Enclave</title><style>body{background:#060910;color:#e2eeff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}.card{background:#0b0f1a;border:1px solid #1c2840;border-radius:16px;padding:28px;max-width:400px;width:100%;text-align:center;}h1{color:#00e5ff;font-size:1.2rem;margin-bottom:20px;}button{background:#00e5ff;color:#000;border:none;border-radius:10px;padding:14px;font-weight:700;cursor:pointer;width:100%;}</style></head><body><div class="card"><h1>🔐 ENCLAVE PQC</h1><p>Pacte de <strong>${from}</strong></p><button onclick="importPact()">Accepter le Pacte</button><div id="ok" style="display:none;color:#00e676;margin-top:15px;">✅ Pacte établi !</div></div><script>async function importPact(){const r=await fetch('/accept-pact',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({contact_id:'${contact_id}',secret:'${secret}'})});const d=await r.json();if(d.success)document.getElementById('ok').style.display='block';}</script></body></html>`);
});

app.get("/meet", async (req, res) => {
  const { identity } = req.query;
  if (!identity) return res.send("Lien invalide");
  let data = JSON.parse(decodeURIComponent(identity));

  const db = await require("./db").getDb();
  const contactId = 'contact-' + data.email.replace(/[@.]/g, '_');
  
  // ICI ON ENREGISTRE AVEC L'OWNER_ID
  db.run("INSERT OR IGNORE INTO contacts (id,owner_id,name,device_id) VALUES (?,?,?,?)",
    [contactId, OWNER_ID, data.name, data.device_id]);
    
  await setSharedSecret(contactId, data.secret);
  require("./db").save();

  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Enclave</title><style>body{background:#060910;color:#e2eeff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;}.card{background:#0b0f1a;border:1px solid #1c2840;border-radius:16px;padding:30px;text-align:center;}button{background:#00e5ff;padding:12px;border:none;border-radius:8px;cursor:pointer;font-weight:bold;}</style></head><body><div class="card"><h1>✅ Contact ajouté</h1><p>Le répertoire de <strong>${OWNER_ID}</strong> a été mis à jour.</p><button onclick="window.location='/'">Retourner à l'Enclave</button></div></body></html>`);
});

app.post("/accept-pact", async (req, res) => {
  const { contact_id, secret } = req.body;
  await setSharedSecret(contact_id, secret);
  res.json({ success: true });
});

// ─── DÉMARRAGE ───────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`\n🔐 Enclave PQC-OTP v2.0 opérationnelle`);
  console.log(`   → Port : ${PORT}`);
  console.log(`   → Owner : ${OWNER_ID}\n`);
});