import express, { Router } from 'express';
import * as mysql from 'mysql2/promise';
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken';

// Trecho: função utilitária para criar conexão com o MySQL.
// Importante: cada endpoint cria e fecha uma conexão (você usa connection.end()).
// Em apps maiores, normalmente se usa "pool" de conexões, mas aqui está ok para estudo.
function createConnection(){
    return mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'root',
        database: 'tickets',
        port: 33060
    })
}

const app = express();

// Trecho: habilita JSON no body (req.body).
// Sem isso, req.body viria undefined em POST/PUT com JSON.
app.use(express.json())

// Trecho: lista de rotas que NÃO precisam autenticação (token).
// Qualquer request que bater método + path nessa lista passa direto no middleware de auth.
const unprotectedRoutes = [
    { method: "POST", path: "/auth/login"},
    { method: "POST", path: "/customers/register"},
    { method: "POST", path: "/partners/register"},
    { method: "GET", path: "/events"},
]

// Trecho: middleware global de autenticação (roda ANTES das rotas).
// Ele decide: "rota pública? passa sem token. rota protegida? exige token."
app.use(async (req, res, next) => {

    // Trecho: verifica se a request atual é uma rota pública.
    // - route.method == req.method: compara o método (GET/POST etc).
    // - req.path.startsWith(route.path): permite que "/events" libere também "/events/123".
    // Se achar qualquer item que bata, some(...) devolve true.
    const isUnprotectedRoute = unprotectedRoutes.some(
        (route) => route.method == req.method && req.path.startsWith(route.path)
    );
    
    // Se for rota pública, pula a validação de token.
    if (isUnprotectedRoute) {
        return next();
    }

    // Trecho: extrai token do header Authorization: "Bearer <token>".
    // split(" ")[1] pega a segunda parte. Se não vier header ou vier diferente, dá undefined.
    const token = req.headers['authorization']?.split(" ")[1]
    if(!token){
        res.status(401).json({message: "No token provided"})
        return;
    }
    
    try{
        // Trecho: valida e decodifica o JWT.
        // Se o token estiver inválido/expirado/assinatura errada, jwt.verify lança erro.
        // payload aqui é o objeto que você colocou no sign (id e email).
        const payload = jwt.verify(token, "123456") as {id: number; email: string};

        // Trecho: “autenticação forte”: além de validar o token, você confirma no banco
        // se o usuário ainda existe.
        // Isso garante que tokens de usuários deletados parem de funcionar.
        const connection = await createConnection();
        const [rows] = await connection.execute<mysql.RowDataPacket[]>(
            "SELECT * FROM users WHERE id = ?",
            [payload.id]
        );

        // Trecho: se não encontrar usuário, você considera o token inválido.
        const user = rows.length ? rows[0] : null;
        if(!user){
            res.status(401).json({message: "Failed to authenticate token"});
            return;
        }

        // Trecho: você “injeta” o user dentro do req para as rotas usarem.
        // Por isso mais abaixo você consegue fazer: req.user!.id
        // Observação: req.user não existe por padrão no Express (é algo que você adicionou).
        req.user = user as {id: number; email: string};

        // OK, usuário autenticado, segue para a rota.
        next();

    } catch (error) {
        // Trecho: qualquer erro no verify cai aqui (token inválido/expirado etc).
        res.status(401).json({message: "Failed to authenticate token"});
    }
})


// Trecho: rota simples de teste.
app.get('/', (req, res) => {
    res.json({message: "Hello World!"})
});


// Trecho: login.
// Como está em unprotectedRoutes, esse endpoint deve funcionar sem token.
// Ele verifica e-mail/senha e gera JWT com expiração de 1h.
app.post("/auth/login",  async (req, res) => {
    const {email, password} = req.body;
    const connection = await createConnection();
    try {
        const [rows] = await connection.execute<mysql.RowDataPacket[]>(
            "SELECT * FROM users WHERE email = ?", [email]
        );

        // Trecho: bcrypt.compareSync compara a senha “crua” com o hash do banco.
        // Se bater, gera token.
        const user = rows.length ? rows[0]: null;
        if(user && bcrypt.compareSync(password, user.password)){
            const token = jwt.sign({id: user.id, email: user.email}, "123456", {
                expiresIn: "1h",
            });
            res.json({ token });
        } else {
            res.status(401).json({message: "Invalid credentials"});
        }
    } finally {
        await connection.end();
    }

    // Trecho importante: aqui tem um problema lógico.
    // Você já respondeu lá em cima com res.json(...) ou res.status(...).json(...),
    // mas depois você faz res.send() de novo.
    // Isso normalmente estoura erro: "Cannot set headers after they are sent".
    console.log(email, password);
    res.send();
});


// Trecho: registro de parceiro (público).
// Cria usuário na tabela users e depois cria parceiro ligado a esse user_id.
app.post("/partners/register", async (req, res) => {
    const {name, email, password, company_name} = req.body;
    
    const connection = await createConnection();
    try {
        const createAt = new Date();
        const hashedPassword = bcrypt.hashSync(password, 10);

        // Trecho: primeiro cria o usuário e pega o insertId.
        const [userResult] = await connection.execute<mysql.ResultSetHeader>(
            "INSERT INTO users (name, email, password, created_at) VALUES (?,?,?,?)", 
            [name, email, hashedPassword, createAt]
        );
        const userId = userResult.insertId;

        // Trecho: depois cria o parceiro usando o userId recém-criado.
        const [partnerResult] = await connection.execute<mysql.ResultSetHeader>(
            "INSERT INTO partners (user_id, company_name, created_at) VALUES (?,?,?)", 
            [userId, company_name, createAt]
        );

        res
        .status(201)
        .json({id: partnerResult.insertId, name, user_id: userId, company_name, created_at: createAt});
    } finally {
        await connection.end();
    }
});


// Trecho: registro de cliente (público).
// Mesma ideia do parceiro: cria user e depois cria customer ligado ao user_id.
app.post("/customers/register", async (req, res) => {
    const {name, email, password, address, phone} = req.body;

    const connection = await createConnection();
    try {
        const createAt = new Date();
        const hashedPassword = bcrypt.hashSync(password, 10);

        const [userResult] = await connection.execute<mysql.ResultSetHeader>(
            "INSERT INTO users (name, email, password, created_at) VALUES (?, ?, ?, ?)", 
            [name, email, hashedPassword, createAt]
        );
        const userId = userResult.insertId;

        const [partnerResult] = await connection.execute<mysql.ResultSetHeader>(
            "INSERT INTO customers (user_id, address, phone, created_at) VALUES (?, ?, ?, ?)", 
            [userId, address, phone, createAt]
        );

        res
        .status(201)
        .json({id: partnerResult.insertId, name, user_id: userId, address, created_at: createAt});
    } finally {
        await connection.end();
    }
});


// Trecho: criar evento para o parceiro logado (PROTEGIDO).
// Repare que essa rota NÃO está no unprotectedRoutes, então exige token.
// Ela usa req.user!.id (setado pelo middleware) para descobrir qual parceiro é esse usuário.
app.post("/partners/events", async (req, res) => {
    const {name, description, date, location} = req.body;

    // Trecho: req.user! assume que existe user. Isso só é verdade se passou pelo middleware com token.
    const userId = req.user!.id;

    const connection = await createConnection();
    try {
        // Trecho: pega o parceiro associado ao usuário autenticado.
        // Isso impede um usuário que não seja parceiro de criar evento.
        const [rows] = await connection.execute<mysql.RowDataPacket[]>(
            "SELECT * FROM partners WHERE user_id = ?",
            [userId]
        );
        const partner = rows.length ? rows[0] : null;

        if (!partner) {
            res.status(403).json({message: "Not authorized"});
            return;
        }

        // Trecho: converte a string de date para Date.
        const eventDate = new Date(date);
        const createdAt = new Date();

        // Trecho: cria evento ligado ao partner.id.
        const [eventResult] = await connection.execute<mysql.ResultSetHeader>(
            "INSERT INTO events (name, description, date, location, created_at, partner_id) VALUES (?, ?, ?, ?, ?, ?)",
            [name, description, eventDate, location, createdAt, partner.id]
        );

        res.status(201).json({
            id: eventResult.insertId,
            name,
            description,
            date: eventDate,
            location,
            created_at: createdAt,
            partner_id: partner.id,
        });
    } finally{
        await connection.end();
    }
});


// Trecho: listar eventos do parceiro logado (PROTEGIDO).
// Mesmo raciocínio: acha o partner pelo user_id do token e lista os eventos daquele partner_id.
app.get("/partners/events", async (req, res) => {
    const userId = req.user!.id;
    const connection = await createConnection();
    try {
        const [rows] = await connection.execute<mysql.RowDataPacket[]>(
            "SELECT * FROM partners WHERE user_id = ?",
            [userId]
        );
        const partner = rows.length ? rows[0] : null;

        if (!partner) {
            res.status(403).json({message: "Not authorized"});
            return;
        }
        
        const [eventRows] = await connection.execute<mysql.RowDataPacket[]>(
            "SELECT * FROM events WHERE partner_id = ?",
            [partner.id]
        );
        res.json(eventRows);
    } finally{
        await connection.end();
    }
});


// Trecho: buscar UM evento específico do parceiro logado (PROTEGIDO).
// Além de checar o partner, você filtra pelo partner_id e id do evento.
// Isso evita que um parceiro veja evento de outro parceiro.
app.get("/partners/events/:eventId", async (req, res) => {
    const {eventId} = req.params;
    const userId = req.user!.id;
    const connection = await createConnection();
    try {
        const [rows] = await connection.execute<mysql.RowDataPacket[]>(
            "SELECT * FROM partners WHERE user_id = ?",
            [userId]
        );
        const partner = rows.length ? rows[0] : null;

        if (!partner) {
            res.status(403).json({message: "Not authorized"});
            return;
        }
        
        const [eventRows] = await connection.execute<mysql.RowDataPacket[]>(
            "SELECT * FROM events WHERE partner_id = ? and id = ?",
            [partner.id, eventId]
        );
        const event = eventRows.length ? eventRows[0] : null;

        if (!event) {
            res.status(404).json({message: "Event not found"});
            return;
        }

        res.json(event);
    } finally{
        await connection.end();
    }
});


// Trecho: listar TODOS os eventos (PÚBLICO pelo seu unprotectedRoutes).
// Como você liberou GET /events, essa rota não exige token.
// Isso é “visão geral” do sistema (eventos de todos os parceiros).
app.get("/events", async (req, res) => {
    const connection = await createConnection();
    try {
        const [eventRows] = await connection.execute<mysql.RowDataPacket[]>(
            "SELECT * FROM events"
        );
        res.json(eventRows);
    } finally{
        await connection.end();
    }
});


// Trecho: detalhes de um evento por ID (ATENÇÃO).
// Pelo seu middleware, isso também fica público, porque:
/// req.path "/events/10" startsWith "/events" => true.
// Ou seja, liberar GET /events libera também GET /events/:eventId.
app.get("/events/:eventId", async (req, res) => {
    const {eventId} = req.params;
    const connection = await createConnection();
    try {
        const [eventRows] = await connection.execute<mysql.RowDataPacket[]>(
            "SELECT * FROM events WHERE id = ?",
            [eventId]
        );
        const event = eventRows.length ? eventRows[0] : null;

        if (!event) {
            res.status(404).json({message: "Event not found"});
            return;
        }

        res.json(event);
    } finally{
        await connection.end();
    }
});


// Trecho: start do servidor.
// Você está zerando as tabelas toda vez que inicia (TRUNCATE).
// Isso é útil para teste, mas em produção seria perigoso.
// O SET FOREIGN_KEY_CHECKS = 0/1 é para conseguir truncar tabelas com FK.
app.listen(3000, async () => {
    //zera as tabelas do banco toda vez que o inicia
    const connection = await createConnection();
    await connection.execute("SET FOREIGN_KEY_CHECKS = 0");
    await connection.execute("TRUNCATE TABLE events");
    await connection.execute("TRUNCATE TABLE customers");
    await connection.execute("TRUNCATE TABLE partners");
    await connection.execute("TRUNCATE TABLE users");
    await connection.execute("SET FOREIGN_KEY_CHECKS = 1");
    console.log('Running in http://localhost:3000')
});