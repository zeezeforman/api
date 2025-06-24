import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

console.log('Conexão com o banco de dados estabelecida!');

export default pool;

pool.getConnection()
  .then(conn => {
    console.log('✅ Conectado com sucesso ao banco de dados!');
    conn.release();
  })
  .catch(err => {
    console.error('❌ Erro ao conectar ao banco de dados:', err.message);
  });