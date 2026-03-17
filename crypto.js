/**
 * crypto.js — Moteur cryptographique OTP
 *
 * PRINCIPE :
 *   - Signature : hash(sujet+corps+secret) XOR clé[0:32]
 *   - Chiffrement : contenu XOR clé[32:32+len(contenu)]
 *
 * La clé OTP (256 bytes) est découpée en zones :
 *   - bytes  0-31  : signature du hash
 *   - bytes 32-63  : chiffrement du sujet
 *   - bytes 64-255 : chiffrement du corps
 *
 * NextCloud ne voit jamais rien en clair — hôte aveugle garanti.
 */

const crypto = require("crypto");
const { normalize } = require("./normalize");

const HASH_SIZE = 32;      // bytes 0-31
const SUBJECT_OFFSET = 32; // bytes 32-63 (max 32 bytes de sujet)
const BODY_OFFSET = 64;    // bytes 64-255 (max 192 bytes de corps)
const MAX_SUBJECT = 32;
const MAX_BODY = 192;

// ─── HASH ────────────────────────────────────────────────────────
function hash(data) {
  return crypto.createHash("sha256").update(data, "utf8").digest();
}

// ─── XOR ─────────────────────────────────────────────────────────
function xorBuffers(a, b) {
  if (a.length !== b.length) {
    throw new Error(`XOR impossible : tailles différentes (${a.length} vs ${b.length})`);
  }
  const result = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

// ─── CHIFFREMENT XOR d'un texte avec une zone de la clé ─────────
function encryptText(text, keyBlob, offset, maxLen) {
  const normalized = normalize(text);
  const textBytes = Buffer.from(normalized, 'utf8');

  if (textBytes.length > maxLen) {
    throw new Error(`Texte trop long : ${textBytes.length} bytes > ${maxLen} max`);
  }

  // Pad avec des zéros pour avoir une taille fixe
  const padded = Buffer.alloc(maxLen, 0);
  textBytes.copy(padded);

  const keySlice = keyBlob.slice(offset, offset + maxLen);
  const encrypted = xorBuffers(padded, keySlice);

  // On retourne aussi la longueur réelle pour pouvoir déchiffrer
  return {
    data_b64: encrypted.toString('base64'),
    len: textBytes.length
  };
}

function decryptText(data_b64, len, keyBlob, offset, maxLen) {
  const encrypted = Buffer.from(data_b64, 'base64');
  const keySlice = keyBlob.slice(offset, offset + maxLen);
  const decrypted = xorBuffers(encrypted, keySlice);
  // On ne lit que len bytes pour récupérer le texte original
  return decrypted.slice(0, len).toString('utf8');
}

// ─── PRÉPARATION ─────────────────────────────────────────────────
function prepare(subject, body, secret) {
  return normalize(subject) + "\n---\n" + normalize(body) + "\n---\n" + normalize(secret);
}

// ─── SIGNATURE + CHIFFREMENT ─────────────────────────────────────
function sign(subject, body, secret, keyBlob) {
  if (!Buffer.isBuffer(keyBlob) || keyBlob.length < 256) {
    throw new Error(`Clé OTP invalide : 256 bytes requis minimum`);
  }

  // 1. Signature du hash (bytes 0-31)
  const prepared = prepare(subject, body, secret);
  const messageHash = hash(prepared);
  const keySlice = keyBlob.slice(0, HASH_SIZE);
  const ciphertext = xorBuffers(messageHash, keySlice);

  // 2. Chiffrement du sujet (bytes 32-63)
  const encSubject = encryptText(subject, keyBlob, SUBJECT_OFFSET, MAX_SUBJECT);

  // 3. Chiffrement du corps (bytes 64-255)
  const encBody = encryptText(body, keyBlob, BODY_OFFSET, MAX_BODY);

  return {
    ciphertext_b64: ciphertext.toString('base64'),
    encrypted_subject: encSubject.data_b64,
    subject_len: encSubject.len,
    encrypted_body: encBody.data_b64,
    body_len: encBody.len
  };
}

// ─── VÉRIFICATION + DÉCHIFFREMENT ────────────────────────────────
function verify(subject, body, secret, keyBlob, ciphertext_b64) {
  try {
    if (!Buffer.isBuffer(keyBlob) || keyBlob.length < HASH_SIZE) return false;

    const prepared = prepare(subject, body, secret);
    const expectedHash = hash(prepared);
    const keySlice = keyBlob.slice(0, HASH_SIZE);
    const ciphertext = Buffer.from(ciphertext_b64, 'base64');
    const decrypted = xorBuffers(ciphertext, keySlice);

    return crypto.timingSafeEqual(decrypted, expectedHash);
  } catch (e) {
    return false;
  }
}

// ─── DÉCHIFFREMENT STANDALONE ────────────────────────────────────
function decryptPayload(payload, keyBlob) {
  const subject = decryptText(
    payload.encrypted_subject,
    payload.subject_len,
    keyBlob,
    SUBJECT_OFFSET,
    MAX_SUBJECT
  );
  const body = decryptText(
    payload.encrypted_body,
    payload.body_len,
    keyBlob,
    BODY_OFFSET,
    MAX_BODY
  );
  return { subject, body };
}

module.exports = { sign, verify, hash, prepare, xorBuffers, decryptPayload };