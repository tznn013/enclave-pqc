/**
 * normalize.js — Standardisation du texte avant signature
 * Garantit que deux représentations identiques d'un même message
 * produisent toujours le même hash.
 */
function normalize(text) {
  text = String(text);
  text = text.replace(/\r\n/g, "\n");
  text = text.replace(/\r/g, "\n");
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    lines[i] = lines[i].trim();
  }
  return lines.join("\n").trim();
}

module.exports = { normalize };
