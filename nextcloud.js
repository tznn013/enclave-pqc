/**
 * nextcloud.js — Relais Agnostique NextCloud
 * NextCloud agit comme un hôte aveugle :
 * il stocke des paquets chiffrés sans jamais voir le contenu en clair.
 */

require("dotenv").config();
const fetch = require("node-fetch");

const BASE_URL = process.env.NEXTCLOUD_URL;
const USER = process.env.NEXTCLOUD_USER;
const PASS = process.env.NEXTCLOUD_PASS;
const FOLDER = "enclave-messages";

function getHeaders() {
  const auth = Buffer.from(`${USER}:${PASS}`).toString("base64");
  return {
    "Authorization": `Basic ${auth}`,
    "Content-Type": "application/json"
  };
}

async function ensureFolder() {
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}`;
  const res = await fetch(url, {
    method: "MKCOL",
    headers: getHeaders()
  });
  // 201 = créé, 405 = existe déjà — les deux sont OK
  return res.status === 201 || res.status === 405;
}

async function depositMessage(keyId, payload) {
  await ensureFolder(); // ← crée le dossier si nécessaire
  
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}/${keyId}.json`;
  const body = JSON.stringify(payload);

  const res = await fetch(url, {
    method: "PUT",
    headers: getHeaders(),
    body: body
  });

  if (res.status === 201 || res.status === 204) {
    return { success: true, url };
  }
  throw new Error(`NextCloud deposit failed: ${res.status}`);
}

/**
 * Bob récupère le paquet depuis NextCloud
 */
async function retrieveMessage(keyId) {
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}/${keyId}.json`;

  const res = await fetch(url, {
    method: "GET",
    headers: getHeaders()
  });

  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`NextCloud retrieve failed: ${res.status}`);

  const data = await res.json();
  return data;
}

async function depositFile(keyId, fileBuffer, fileName) {
  await ensureFolder();
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}/${keyId}_${fileName}`;
  
  const res = await fetch(url, {
    method: "PUT",
    headers: {
      "Authorization": `Basic ${Buffer.from(`${USER}:${PASS}`).toString("base64")}`,
      "Content-Type": "application/octet-stream"
    },
    body: fileBuffer
  });

  if (res.status === 201 || res.status === 204) {
    return { success: true, fileName: `${keyId}_${fileName}` };
  }
  throw new Error(`File deposit failed: ${res.status}`);
}

async function retrieveFile(keyId, fileName) {
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}/${keyId}_${fileName}`;
  
  const res = await fetch(url, {
    method: "GET",
    headers: {
      "Authorization": `Basic ${Buffer.from(`${USER}:${PASS}`).toString("base64")}`
    }
  });

  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`File retrieve failed: ${res.status}`);

  return await res.buffer();
}

async function deleteFile(keyId, fileName) {
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}/${keyId}_${fileName}`;
  await fetch(url, {
    method: "DELETE",
    headers: {
      "Authorization": `Basic ${Buffer.from(`${USER}:${PASS}`).toString("base64")}`
    }
  });
}

/**
 * Supprime le paquet après vérification
 */
async function deleteMessage(keyId) {
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}/${keyId}.json`;

  await fetch(url, {
    method: "DELETE",
    headers: getHeaders()
  });
}
module.exports = { depositMessage, retrieveMessage, deleteMessage, ensureFolder, depositFile, retrieveFile, deleteFile };