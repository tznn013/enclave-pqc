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

function getHeaders(contentType = "application/json") {
  const auth = Buffer.from(`${USER}:${PASS}`).toString("base64");
  return {
    "Authorization": `Basic ${auth}`,
    "Content-Type": contentType
  };
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function ensureFolder() {
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}`;
  console.log(`Nextcloud ensure folder: ${url}`);
  const res = await fetchWithTimeout(url, {
    method: "MKCOL",
    headers: getHeaders()
  }, 10000);

  if (res.status === 201 || res.status === 405) return true;
  if (res.status === 401 || res.status === 403) throw new Error(`NextCloud auth failed: ${res.status}`);
  throw new Error(`NextCloud ensureFolder failed: ${res.status}`);
}

async function depositMessage(keyId, payload) {
  await ensureFolder();

  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}/${keyId}.json`;
  const body = JSON.stringify(payload);

  console.log(`Nextcloud deposit: ${url}`);
  const res = await fetchWithTimeout(url, {
    method: "PUT",
    headers: getHeaders("application/json"),
    body
  }, 20000);

  if (res.status === 201 || res.status === 204) {
    console.log(`Nextcloud deposit successful for ${keyId}`);
    return { success: true, url };
  }

  const details = await res.text().catch(() => "");
  console.error(`Nextcloud deposit failed ${res.status}: ${details}`);
  throw new Error(`NextCloud deposit failed: ${res.status}`);
}

async function retrieveMessage(keyId) {
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}/${keyId}.json`;
  console.log(`Nextcloud retrieve: ${url}`);

  const res = await fetchWithTimeout(url, {
    method: "GET",
    headers: getHeaders()
  }, 15000);

  if (res.status === 404) return null;
  if (!res.ok) {
    const details = await res.text().catch(() => "");
    throw new Error(`NextCloud retrieve failed: ${res.status} ${details}`);
  }

  return await res.json();
}

async function depositFile(keyId, fileBuffer, fileName) {
  await ensureFolder();
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}/${keyId}_${fileName}`;
  console.log(`Nextcloud depositFile: ${url}`);

  const res = await fetchWithTimeout(url, {
    method: "PUT",
    headers: {
      "Authorization": `Basic ${Buffer.from(`${USER}:${PASS}`).toString("base64")}`,
      "Content-Type": "application/octet-stream"
    },
    body: fileBuffer
  }, 60000);

  if (res.status === 201 || res.status === 204) {
    return { success: true, fileName: `${keyId}_${fileName}` };
  }

  const details = await res.text().catch(() => "");
  throw new Error(`File deposit failed: ${res.status} ${details}`);
}

async function retrieveFile(keyId, fileName) {
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}/${keyId}_${fileName}`;
  console.log(`Nextcloud retrieveFile: ${url}`);

  const res = await fetchWithTimeout(url, {
    method: "GET",
    headers: {
      "Authorization": `Basic ${Buffer.from(`${USER}:${PASS}`).toString("base64")}`
    }
  }, 15000);

  if (res.status === 404) return null;
  if (!res.ok) {
    const details = await res.text().catch(() => "");
    throw new Error(`File retrieve failed: ${res.status} ${details}`);
  }

  return await res.buffer();
}

async function deleteFile(keyId, fileName) {
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}/${keyId}_${fileName}`;
  console.log(`Nextcloud deleteFile: ${url}`);
  await fetchWithTimeout(url, {
    method: "DELETE",
    headers: {
      "Authorization": `Basic ${Buffer.from(`${USER}:${PASS}`).toString("base64")}`
    }
  }, 15000);
}

async function deleteMessage(keyId) {
  const url = `${BASE_URL}/remote.php/dav/files/${encodeURIComponent(USER)}/${FOLDER}/${keyId}.json`;
  console.log(`Nextcloud deleteMessage: ${url}`);
  await fetchWithTimeout(url, {
    method: "DELETE",
    headers: getHeaders()
  }, 15000);
}

module.exports = { depositMessage, retrieveMessage, deleteMessage, ensureFolder, depositFile, retrieveFile, deleteFile };