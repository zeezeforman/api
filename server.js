import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import db from './db.js'; // Importa a conexão com o banco

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'sua_chave_secreta_pode_ser_qualquer_coisa_complexa';


// Helper para obter o caminho do diretório atual com ES Modules

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename)

// Configuração do Multer para upload de imagens

const uploadDir = path.join(__dirname, 'imgs');

// Garante que o diretório uploads exista
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true })
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Configuração do CORS para permitir que o frontend acesse a API
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5174',
  'https://quiosk.com.br',
  'https://dashboard.quiosk.com.br'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'CORS bloqueado para esta origem.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));
app.use(express.json());

const checkAuth = (req, res, next) => {
    // Pega o token do cabeçalho 'Authorization'
    const authHeader = req.headers.authorization;

    // Verifica se o cabeçalho existe e se está no formato correto ("Bearer TOKEN")
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Acesso negado: token não fornecido ou mal formatado.' });
    }

    // Pega só a parte do token, removendo o "Bearer " do início
    const token = authHeader.split(' ')[1];

    // Verifica se o token é válido
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            // Se o token for inválido ou tiver expirado, o acesso é proibido
            return res.status(403).json({ message: 'Acesso negado: token inválido ou expirado.' });
        }
        // Se o token for válido, anexa os dados do usuário na requisição e permite continuar
        req.userData = decoded;
        next();
    });
};

// --- ROTA DE TESTE ---
app.get('/', (req, res) => {
    res.json({ message: 'Bem-vindo à API da ZeeZe Modas! O servidor está no ar!' });
});

// --- ROTA DE LOGIN (SEM HASH DE SENHA) ---
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const [users] = await db.query('SELECT id, username, password, name FROM users WHERE username = ?', [username]);

        if (users.length === 0) {
            return res.status(401).json({ message: 'Usuário ou senha inválidos' });
        }

        const user = users[0];
        const isPasswordCorrect = (password === user.password);

        if (!isPasswordCorrect) {
            return res.status(401).json({ message: 'Usuário ou senha inválidos' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, name: user.name },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.status(200).json({ message: 'Login bem-sucedido!', token: token });
    } catch (error) {
        console.error('Erro no servidor durante o login:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

// --- ROTAS DE CATEGORIAS (PROTEGIDAS PELO checkAuth) ---

// Rota para BUSCAR todas as categorias
app.get('/api/categories', async (req, res) => {
    try {
        const [categories] = await db.query('SELECT * FROM categories ORDER BY name ASC');
        res.status(200).json(categories);
    } catch (error) {
        console.error('Erro ao buscar categorias:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

// Rota para ADICIONAR uma nova categoria
app.post('/api/categories', checkAuth, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name) {
            return res.status(400).json({ message: 'O nome da categoria é obrigatório.' });
        }
        const [result] = await db.query('INSERT INTO categories (name) VALUES (?)', [name]);
        const newCategory = { id: result.insertId, name: name };
        res.status(201).json(newCategory);
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Essa categoria já existe.' });
        }
        console.error('Erro ao criar categoria:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

// Rota para DELETAR uma categoria
app.delete('/api/categories/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await db.query('DELETE FROM categories WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Categoria não encontrada.' });
        }
        res.status(200).json({ message: 'Categoria deletada com sucesso!' });
    } catch (error) {
        console.error('Erro ao deletar categoria:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// Rota para atualizar uma categoria

app.put('/api/categories/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params; // Pega o ID da categoria pela URL
        const { name } = req.body; // Pega o novo nome enviado pelo formulário

        // Validação básica para garantir que o nome não está vazio
        if (!name || name.trim() === '') {
            return res.status(400).json({ message: 'O nome da categoria é obrigatório.' });
        }

        // Executa o comando UPDATE no banco de dados
        const [result] = await db.query(
            'UPDATE categories SET name = ? WHERE id = ?',
            [name, id]
        );

        // Se nenhuma linha foi afetada, significa que a categoria não foi encontrada
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Categoria não encontrada.' });
        }

        // Retorna a categoria atualizada para o frontend
        res.status(200).json({ id: parseInt(id), name: name });

    } catch (error) {
        // Trata o erro de nome duplicado, caso o novo nome já exista
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Essa categoria já existe.' });
        }
        console.error('Erro ao atualizar categoria:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});


// Rota para BUSCAR todos os clientes
app.get('/api/clients', checkAuth, async (req, res) => {
    try {
        const [clients] = await db.query('SELECT * FROM clients ORDER BY name ASC');
        res.status(200).json(clients);
    } catch (error) {
        console.error('Erro ao buscar clientes:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

// Rota para ADICIONAR um novo cliente
app.post('/api/clients', checkAuth, async (req, res) => {
    try {
        const { name, email, phone, cpfCnpj, address } = req.body;

        // Validação básica
        if (!name || !cpfCnpj) {
            return res.status(400).json({ message: 'Nome e CPF/CNPJ são obrigatórios.' });
        }

        const query = `
            INSERT INTO clients (name, email, phone, cpfCnpj, street, number, neighborhood, city, state)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const values = [name, email, phone, cpfCnpj, address.street, address.number, address.neighborhood, address.city, address.state];

        const [result] = await db.query(query, values);

        const newClient = { id: result.insertId, ...req.body };
        res.status(201).json(newClient);

    } catch (error) {
        console.error('Erro ao criar cliente:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

// Rota para ATUALIZAR um cliente existente
app.put('/api/clients/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, email, phone, cpfCnpj, address } = req.body;

        const query = `
            UPDATE clients SET 
            name = ?, email = ?, phone = ?, cpfCnpj = ?, 
            street = ?, number = ?, neighborhood = ?, city = ?, state = ?
            WHERE id = ?
        `;
        const values = [name, email, phone, cpfCnpj, address.street, address.number, address.neighborhood, address.city, address.state, id];

        const [result] = await db.query(query, values);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Cliente não encontrado.' });
        }

        res.status(200).json({ id: id, ...req.body });

    } catch (error) {
        console.error('Erro ao atualizar cliente:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

// Rota para DELETAR um cliente
app.delete('/api/clients/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await db.query('DELETE FROM clients WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Cliente não encontrado.' });
        }

        res.status(200).json({ message: 'Cliente deletado com sucesso.' });
    } catch (error) {
        console.error('Erro ao deletar cliente:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});


// Rota para BUSCAR todos os produtos (com o nome da categoria)
app.get('/api/products', async (req, res) => {
    try {
        // Usamos um JOIN para buscar o nome da categoria junto com os dados do produto
        const query = `
            SELECT 
                p.id, p.code, p.name, p.price, p.stock, p.imageUrl, 
                c.id as category_id, c.name as category_name 
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            ORDER BY p.name ASC
        `;
        const [products] = await db.query(query);
        res.status(200).json(products);
    } catch (error) {
        console.error('Erro ao buscar produtos:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

// Rota para ADICIONAR um novo produto
app.post('/api/products', checkAuth, async (req, res) => {
    try {
        const { code, name, category_id, price, stock, imageUrl } = req.body;
        if (!name || !code || !price) {
            return res.status(400).json({ message: 'Código, nome e preço são obrigatórios.' });
        }

        const query = `
            INSERT INTO products (code, name, category_id, price, stock, imageUrl)
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        const values = [code, name, category_id, parseFloat(price), parseInt(stock, 10), imageUrl];

        const [result] = await db.query(query, values);

        // Busca o produto recém-criado para retornar com o nome da categoria
        const [newProduct] = await db.query('SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id WHERE p.id = ?', [result.insertId]);

        res.status(201).json(newProduct[0]);

    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Já existe um produto com este código.' });
        }
        console.error('Erro ao criar produto:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

// Rota para ATUALIZAR um produto existente
app.put('/api/products/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { code, name, category_id, price, stock, imageUrl } = req.body;

        const query = `
            UPDATE products SET 
            code = ?, name = ?, category_id = ?, price = ?, stock = ?, imageUrl = ?
            WHERE id = ?
        `;
        const values = [code, name, category_id, parseFloat(price), parseInt(stock, 10), imageUrl, id];

        await db.query(query, values);

        // Busca o produto atualizado para retornar com o nome da categoria
        const [updatedProduct] = await db.query('SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id WHERE p.id = ?', [id]);

        if (updatedProduct.length === 0) {
            return res.status(404).json({ message: 'Produto não encontrado.' });
        }

        res.status(200).json(updatedProduct[0]);
    } catch (error) {
        console.error('Erro ao atualizar produto:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});


// Rota para ATUALIZAR APENAS O ESTOQUE de um produto
app.put('/api/products/:id/stock', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { amount } = req.body; // amount pode ser positivo ou negativo

        const query = `UPDATE products SET stock = stock + ? WHERE id = ?`;
        const [result] = await db.query(query, [parseInt(amount, 10), id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Produto não encontrado.' });
        }

        const [updatedProduct] = await db.query('SELECT stock FROM products WHERE id = ?', [id]);
        res.status(200).json({ newStock: updatedProduct[0].stock });

    } catch (error) {
        console.error('Erro ao atualizar estoque:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});


// Rota para DELETAR um produto
app.delete('/api/products/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await db.query('DELETE FROM products WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Produto não encontrado.' });
        }

        res.status(200).json({ message: 'Produto deletado com sucesso.' });
    } catch (error) {
        console.error('Erro ao deletar produto:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// Rota para upload de imagens
app.post('/api/upload', checkAuth, upload.single('productImage'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'Nenhum arquivo enviado.' });
        }
        // Retorna a URL completa para acessar a imagem
        const imageUrl = `${req.protocol}://${req.get('host')}/imgs/${req.file.filename}`;
        res.status(200).json({ imageUrl: imageUrl });
    } catch (error) {
        res.status(500).json({ message: 'Erro no upload da imagem' });
    }
});


// Rota para BUSCAR todos os pedidos (com o nome do cliente)
app.get('/api/orders', checkAuth, async (req, res) => {
    try {
        const query = `
            SELECT 
                o.id, o.order_date, o.total, o.status,
                c.id as client_id, c.name as client_name
            FROM orders o
            LEFT JOIN clients c ON o.client_id = c.id
            ORDER BY o.order_date DESC
        `;
        const [orders] = await db.query(query);
        res.status(200).json(orders);
    } catch (error) {
        console.error('Erro ao buscar pedidos:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

// Rota para CRIAR um novo pedido (a mais complexa, usa transação)
app.post('/api/orders', checkAuth, async (req, res) => {
    const connection = await db.getConnection(); // Pega uma conexão do pool
    try {
        const { clientId, total, items } = req.body;

        // Inicia a transação
        await connection.beginTransaction();

        // 1. Insere o cabeçalho do pedido na tabela 'orders'
        const orderQuery = 'INSERT INTO orders (client_id, total, status) VALUES (?, ?, ?)';
        const [orderResult] = await connection.query(orderQuery, [clientId, total, 'Processando']);
        const newOrderId = orderResult.insertId;

        // 2. Prepara as inserções para cada item do pedido
        const itemInsertPromises = items.map(item => {
            const itemQuery = 'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)';
            return connection.query(itemQuery, [newOrderId, item.productId, item.qty, item.price]);
        });

        // 3. Prepara as atualizações de estoque para cada produto
        const stockUpdatePromises = items.map(item => {
            const stockQuery = 'UPDATE products SET stock = stock - ? WHERE id = ?';
            return connection.query(stockQuery, [item.qty, item.productId]);
        });

        // Executa todas as inserções e atualizações em paralelo
        await Promise.all([...itemInsertPromises, ...stockUpdatePromises]);

        // Se tudo deu certo, efetiva a transação
        await connection.commit();

        // Busca o pedido recém-criado para retornar ao frontend
        const [newOrder] = await db.query('SELECT o.*, c.name as client_name FROM orders o LEFT JOIN clients c ON o.client_id = c.id WHERE o.id = ?', [newOrderId]);

        res.status(201).json(newOrder[0]);

    } catch (error) {
        // Se qualquer passo falhar, desfaz a transação inteira
        await connection.rollback();
        console.error('Erro ao criar pedido:', error);
        res.status(500).json({ message: 'Erro ao criar pedido. A operação foi cancelada.' });
    } finally {
        // Libera a conexão de volta para o pool
        connection.release();
    }
});

// Rota para ATUALIZAR o status de um pedido
app.put('/api/orders/:id/status', checkAuth, async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    const connection = await db.getConnection(); // Pega uma conexão para usar na transação

    try {
        await connection.beginTransaction();

        // 1. Verifica se o pedido já não está cancelado para evitar devolução dupla de estoque
        const [currentOrder] = await connection.query('SELECT status FROM orders WHERE id = ?', [id]);
        if (currentOrder.length === 0) {
            throw new Error('Pedido não encontrado.');
        }
        if (currentOrder[0].status === 'Cancelado') {
            // JÁ ESTÁ CANCELADO, ENTÃO NÃO PERMITA NENHUMA MUDANÇA.
            await connection.rollback(); // Desfaz a transação iniciada
            connection.release();
            return res.status(403).json({ message: 'Este pedido já foi cancelado e não pode ser alterado.' });
        }

        // 2. Atualiza o status do pedido
        await connection.query('UPDATE orders SET status = ? WHERE id = ?', [status, id]);

        let restoredStockInfo = [];

        // 3. Se o novo status for "Cancelado", devolve o estoque
        if (status === 'Cancelado') {
            // Busca todos os itens do pedido
            const [items] = await connection.query('SELECT product_id, quantity FROM order_items WHERE order_id = ?', [id]);

            if (items.length > 0) {
                // Cria uma promessa de atualização para cada item
                const stockRestorePromises = items.map(item => {
                    return connection.query(
                        'UPDATE products SET stock = stock + ? WHERE id = ?',
                        [item.quantity, item.product_id]
                    );
                });

                // Executa todas as atualizações de estoque
                await Promise.all(stockRestorePromises);

                // Prepara os dados para retornar ao frontend
                const productIds = items.map(item => item.product_id);
                const [newStockLevels] = await connection.query('SELECT id, stock FROM products WHERE id IN (?)', [productIds]);
                restoredStockInfo = newStockLevels.map(p => ({ product_id: p.id, new_stock: p.stock }));
            }
        }

        // 4. Se tudo correu bem, confirma a transação
        await connection.commit();

        // 5. Retorna uma resposta de sucesso, incluindo os dados do estoque atualizado se for o caso
        res.status(200).json({
            message: 'Status do pedido atualizado com sucesso.',
            restored_stock: restoredStockInfo
        });

    } catch (error) {
        // Se qualquer erro ocorrer, desfaz todas as operações
        await connection.rollback();
        console.error('Erro ao atualizar status do pedido:', error);
        res.status(500).json({ message: error.message || 'Erro interno no servidor' });
    } finally {
        // Sempre libera a conexão de volta para o pool
        connection.release();
    }
});


// Rota para buscar detalhes de um pedido (com itens)
app.get('/api/orders/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;

        // 1. Busca os dados gerais do pedido e do cliente
        const orderQuery = `
            SELECT 
                o.id, o.order_date, o.total, o.status,
                c.id as client_id, c.name as client_name, c.email, c.phone, c.cpfCnpj,
                c.street, c.number, c.neighborhood, c.city, c.state
            FROM orders o
            LEFT JOIN clients c ON o.client_id = c.id
            WHERE o.id = ?
        `;
        const [orderDetails] = await db.query(orderQuery, [id]);

        if (orderDetails.length === 0) {
            return res.status(404).json({ message: 'Pedido não encontrado.' });
        }

        // 2. Busca os itens associados a esse pedido
        const itemsQuery = `
            SELECT 
                oi.quantity, oi.price,
                p.id as product_id, p.name as product_name, p.code as product_code
            FROM order_items oi
            LEFT JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = ?
        `;
        const [orderItems] = await db.query(itemsQuery, [id]);

        // 3. Combina tudo em uma única resposta
        const fullOrder = {
            ...orderDetails[0],
            items: orderItems
        };

        res.status(200).json(fullOrder);

    } catch (error) {
        console.error('Erro ao buscar detalhes do pedido:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});



// =============================================================================
//  ROTAS PARA BANNERS
// =============================================================================

// Rota PÚBLICA para buscar apenas os banners ativos (para a loja virtual)
app.get('/api/public/banners', async (req, res) => {
    try {
        const [banners] = await db.query('SELECT * FROM banners WHERE isActive = TRUE ORDER BY created_at DESC');
        res.status(200).json(banners);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar banners.' });
    }
});

// Rota PRIVADA para buscar TODOS os banners (para o painel de gestão)
app.get('/api/banners', checkAuth, async (req, res) => {
    try {
        const [banners] = await db.query('SELECT * FROM banners ORDER BY created_at DESC');
        res.status(200).json(banners);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar banners.' });
    }
});

// Rota PRIVADA para ADICIONAR um novo banner
app.post('/api/banners', checkAuth, async (req, res) => {
    try {
        const { title, imageUrl, linkUrl, isActive } = req.body;
        if (!title || !imageUrl) {
            return res.status(400).json({ message: 'Título e Imagem são obrigatórios.' });
        }
        const query = 'INSERT INTO banners (title, imageUrl, linkUrl, isActive) VALUES (?, ?, ?, ?)';
        const [result] = await db.query(query, [title, imageUrl, linkUrl, isActive]);
        const newBanner = { id: result.insertId, title, imageUrl, linkUrl, isActive };
        res.status(201).json(newBanner);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao criar banner.' });
    }
});

// Rota PRIVADA para ATUALIZAR um banner
app.put('/api/banners/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, imageUrl, linkUrl, isActive } = req.body;
        const query = 'UPDATE banners SET title = ?, imageUrl = ?, linkUrl = ?, isActive = ? WHERE id = ?';
        const [result] = await db.query(query, [title, imageUrl, linkUrl, isActive, id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Banner não encontrado.' });
        }
        res.status(200).json({ id: parseInt(id), ...req.body });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao atualizar banner.' });
    }
});

// Rota PRIVADA para DELETAR um banner
app.delete('/api/banners/:id', checkAuth, async (req, res) => {
    try {
        const { id } = req.params;
        // Futuramente, aqui você também deveria deletar o arquivo da imagem do servidor
        const [result] = await db.query('DELETE FROM banners WHERE id = ?', [id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Banner não encontrado.' });
        }
        res.status(200).json({ message: 'Banner deletado com sucesso.' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao deletar banner.' });
    }
});



app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta http://localhost:${PORT}`);
});
