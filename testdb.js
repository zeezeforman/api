import db from './db.js';

try {
  const [rows] = await db.query('SELECT 1 + 1 AS result');
  console.log('✅ Teste DB OK:', rows);
  process.exit();
} catch (err) {
  console.error('❌ Erro no banco:', err.message);
  process.exit(1);
}