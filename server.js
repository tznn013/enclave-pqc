require("dotenv").config();
const crypto = require("crypto");
const express = require("express");
const path = require("path");
const QRCode = require("qrcode");

// Import des fonctions de cryptographie et de stockage
const { sign, verify, decryptPayload } = require("./crypto");
const { 
    generateKeyPool, consumeKey, findAndConsumeKey,
    countAllFreeKeys, getAuditLog, getContacts, getDeviceId,
    setSharedSecret, getSharedSecret 
} = require("./keyStore");

const app = express();

// Configuration de l'ID propriétaire via Railway (ou défaut pour le local)
const OWNER_ID = process.env.NEXTCLOUD_USER || "admin-esiee";

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// ─── STATUS ──────────────────────────────────────────────────────
app.get("/status", async (req, res) => {
  res.json({
    running: true,
    owner: OWNER_ID, // Affiche qui possède cette enclave
    device_id: await getDeviceId(),
    keys_available: await countAllFreeKeys(),
    version: "2.0.0-pqc",
    pqc_resistant: true,
    confidentiality: "OTP-XOR end-to-end"
  });
});

// ─── CONTACTS (FILTRÉS PAR OWNER) ────────────────────────────────
app.get("/contacts", async (req, res) => {
  const allContacts = await getContacts();
  // On ne retourne que les contacts appartenant à l'utilisateur actuel
  const mine = allContacts.filter(c => c.owner_id === OWNER_ID);
  res.json(mine);
});

// ─── AUDIT ───────────────────────────────────────────────────────
app.get("/audit", async (req, res) => {
  res.json(await getAuditLog(parseInt(req.query.limit) || 50));
});

// ─── LE PACTE ────────────────────────────────────────────────────