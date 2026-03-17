const { getDb } = require('./db');
(async () => {
  const db = await getDb();
  const cnt = db.exec("SELECT c.id,c.owner_id,c.shared_secret, COUNT(k.id) AS free_keys FROM contacts c LEFT JOIN keys k ON k.contact_id=c.id AND k.status='free' GROUP BY c.id");
  if (!cnt.length) { console.log('no contacts'); return; }
  cnt[0].values.forEach(r => console.log('contact', r));
  const all = db.exec("SELECT id,contact_id,status FROM keys LIMIT 50");
  if (all.length) { all[0].values.forEach(r => console.log('key', r)); }
})();
