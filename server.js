// ============================================================
//  ANURA FINTECH — server.js (Unified Backend)
//  Node.js + Express + MongoDB/Mongoose
// ============================================================

require('dotenv').config();
const express       = require('express');
const mongoose      = require('mongoose');
const bcrypt        = require('bcryptjs');
const jwt           = require('jsonwebtoken');
const cookieParser  = require('cookie-parser');
const cors          = require('cors');
const path          = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── MIDDLEWARE ────────────────────────────────────────────────
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ── DATABASE ──────────────────────────────────────────────────
const MONGODB_URI = process.env.MONGODB_URI ||
  'mongodb+srv://carialavagnerrodrigues_db_user:V2008J1975r@cluster0.fwk50ay.mongodb.net/anura?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅  MongoDB Atlas connected'))
  .catch(err => console.error('❌  MongoDB error:', err.message));

// ── MODELS ────────────────────────────────────────────────────

// User
const userSchema = new mongoose.Schema({
  nome:              { type: String, required: true, trim: true },
  email:             { type: String, required: true, unique: true, lowercase: true },
  telefone:          { type: String, required: true },
  passwordHash:      { type: String, required: true },
  role:              { type: String, enum: ['user','admin'], default: 'user' },
  kycAprovado:       { type: Boolean, default: false },
  saldoDisponivel:   { type: Number, default: 0 },
  saldoInvestido:    { type: Number, default: 0 },
  creditScore:       { type: Number, default: 0 },
  criadoEm:         { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Transaction
const transactionSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  tipo:        { type: String, enum: ['deposito','levantamento','investimento','rendimento','credito'], required: true },
  valor:       { type: Number, required: true },
  estado:      { type: String, enum: ['pendente','confirmado','rejeitado','a_caminho','depositado'], default: 'pendente' },
  referencia:  { type: String },
  descricao:   { type: String },
  criadoEm:   { type: Date, default: Date.now },
  atualizadoEm:{ type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', transactionSchema);

// Investment
const investmentSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  plano:       { type: String, enum: ['starter','gold','elite'], required: true },
  valor:       { type: Number, required: true },
  apy:         { type: Number, required: true },
  estado:      { type: String, enum: ['ativo','encerrado'], default: 'ativo' },
  alocadoEm:  { type: Date, default: Date.now },
  encerradoEm:{ type: Date }
});
const Investment = mongoose.model('Investment', investmentSchema);

// Loan
const loanSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  valor:       { type: Number, required: true },
  taxaMensal:  { type: Number, required: true },
  prazoMeses:  { type: Number, required: true },
  estado:      { type: String, enum: ['pendente','aprovado','rejeitado','pago'], default: 'pendente' },
  criadoEm:   { type: Date, default: Date.now }
});
const Loan = mongoose.model('Loan', loanSchema);

// ── AUTH MIDDLEWARE ───────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'anura_secret_2026_xK9pQ';

function authMiddleware(req, res, next) {
  const token =
    req.cookies?.token ||
    (req.headers.authorization?.startsWith('Bearer ') && req.headers.authorization.split(' ')[1]);
  if (!token) return res.status(401).json({ erro: 'Não autenticado.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido ou expirado.' });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.role !== 'admin')
      return res.status(403).json({ erro: 'Acesso restrito a administradores.' });
    next();
  });
}

// ── HELPERS ───────────────────────────────────────────────────
function gerarToken(user) {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

const APY_MAP = { starter: 8, gold: 16, elite: 24 };
const MIN_DEPOSITO = { starter: 200, gold: 2000, elite: 10000 };

// ── ROTAS: AUTH ───────────────────────────────────────────────

// Registar
app.post('/api/auth/registar', async (req, res) => {
  try {
    const { nome, email, telefone, password } = req.body;
    if (!nome || !email || !telefone || !password)
      return res.status(400).json({ erro: 'Todos os campos são obrigatórios.' });

    const existe = await User.findOne({ email });
    if (existe) return res.status(409).json({ erro: 'Email já registado.' });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ nome, email, telefone, passwordHash });

    const token = gerarToken(user);
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', maxAge: 7*24*3600*1000 });
    res.status(201).json({ mensagem: 'Conta criada com sucesso.', token, user: { id: user._id, nome: user.nome, email: user.email, saldoDisponivel: 0 } });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ erro: 'Credenciais inválidas.' });

    const valido = await bcrypt.compare(password, user.passwordHash);
    if (!valido) return res.status(401).json({ erro: 'Credenciais inválidas.' });

    const token = gerarToken(user);
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', maxAge: 7*24*3600*1000 });
    res.json({
      mensagem: 'Login bem-sucedido.',
      token,
      user: {
        id: user._id,
        nome: user.nome,
        email: user.email,
        role: user.role,
        saldoDisponivel: user.saldoDisponivel,
        saldoInvestido: user.saldoInvestido,
        creditScore: user.creditScore,
        kycAprovado: user.kycAprovado
      }
    });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ mensagem: 'Sessão encerrada.' });
});

// Perfil
app.get('/api/auth/perfil', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    if (!user) return res.status(404).json({ erro: 'Utilizador não encontrado.' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// ── ROTAS: DEPÓSITOS ──────────────────────────────────────────

app.post('/api/depositos/iniciar', authMiddleware, async (req, res) => {
  try {
    const { valor } = req.body;
    if (!valor || valor < 200)
      return res.status(400).json({ erro: 'Depósito mínimo de 200 MT obrigatório.' });
    res.json({ mensagem: 'Envie o comprovativo para confirmar o depósito.', valor });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

app.post('/api/depositos/validar-comprovativo', authMiddleware, async (req, res) => {
  try {
    const { textoComprovativo, valor } = req.body;

    if (!textoComprovativo || textoComprovativo.length < 15)
      return res.status(400).json({ erro: 'Cole o texto completo do comprovativo.' });

    const montante = parseFloat(valor);
    if (!montante || montante < 200)
      return res.status(400).json({ erro: 'Depósito mínimo de 200 MT obrigatório.' });

    // Validação sintática do comprovativo
    const padroes = [
      /transac[aã]o\s*(no|n[oº°])?[:\s]*[\w\d]+/i,
      /recebemos\s+de/i,
      /transfer[eê]ncia/i,
      /m[\-\s]?pesa/i,
      /millenium\s*bim|bci|standard\s*bank/i,
      /valor[:\s]+[\d]+/i,
      /ref(erencia)?[:\s]*[\w\d]+/i,
    ];
    const valido = padroes.some(p => p.test(textoComprovativo));
    if (!valido)
      return res.status(422).json({ erro: 'Comprovativo não reconhecido. Certifique-se de colar o texto completo do SMS M-Pesa ou comprovativo bancário.' });

    // Extrair referência para evitar duplicados
    const refMatch = textoComprovativo.match(/(?:transac[aã]o|ref(?:erencia)?|no)[:\s#]*([A-Z0-9\-]{5,20})/i);
    const referencia = refMatch ? refMatch[1].toUpperCase() : `DEP-${Date.now()}`;

    const duplicado = await Transaction.findOne({ referencia, tipo: 'deposito' });
    if (duplicado)
      return res.status(409).json({ erro: 'Este comprovativo já foi utilizado anteriormente.' });

    // Criar transação e creditar saldo
    const transacao = await Transaction.create({
      userId: req.user.id,
      tipo: 'deposito',
      valor: montante,
      estado: 'confirmado',
      referencia,
      descricao: 'Depósito via comprovativo validado'
    });

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $inc: { saldoDisponivel: montante, creditScore: Math.floor(montante / 100) } },
      { new: true }
    );

    res.json({
      mensagem: `Depósito de MT ${montante.toLocaleString('pt-MZ')} confirmado com sucesso!`,
      saldoDisponivel: user.saldoDisponivel,
      creditScore: user.creditScore,
      referencia
    });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// ── ROTAS: INVESTIMENTOS ──────────────────────────────────────

app.post('/api/investimentos/alocar', authMiddleware, async (req, res) => {
  try {
    const { valor, plano } = req.body;
    const apy = APY_MAP[plano];
    if (!apy) return res.status(400).json({ erro: 'Plano inválido. Escolha: starter, gold ou elite.' });

    const minimo = MIN_DEPOSITO[plano];
    if (!valor || valor < minimo)
      return res.status(400).json({ erro: `Depósito mínimo para o plano ${plano} é ${minimo} MT.` });

    const user = await User.findById(req.user.id);
    if (user.saldoDisponivel < valor)
      return res.status(400).json({ erro: 'Saldo insuficiente.' });

    await User.findByIdAndUpdate(req.user.id, {
      $inc: { saldoDisponivel: -valor, saldoInvestido: valor }
    });

    const investimento = await Investment.create({
      userId: req.user.id,
      plano,
      valor,
      apy
    });

    await Transaction.create({
      userId: req.user.id,
      tipo: 'investimento',
      valor,
      estado: 'confirmado',
      descricao: `Investimento Plano ${plano.toUpperCase()} — APY ${apy}%`
    });

    const userAtualizado = await User.findById(req.user.id);
    res.json({
      mensagem: `Capital de MT ${valor.toLocaleString('pt-MZ')} alocado no Plano ${plano.toUpperCase()}. APY: ${apy}%.`,
      investimento,
      saldoDisponivel: userAtualizado.saldoDisponivel,
      saldoInvestido: userAtualizado.saldoInvestido
    });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

app.get('/api/investimentos/meus', authMiddleware, async (req, res) => {
  try {
    const investimentos = await Investment.find({ userId: req.user.id }).sort({ alocadoEm: -1 });
    res.json(investimentos);
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// ── ROTAS: LEVANTAMENTOS ──────────────────────────────────────

app.post('/api/levantamentos/pedir', authMiddleware, async (req, res) => {
  try {
    const { valor } = req.body;
    if (!valor || valor <= 0)
      return res.status(400).json({ erro: 'Valor de levantamento inválido.' });

    const user = await User.findById(req.user.id);
    if (user.saldoDisponivel < valor)
      return res.status(400).json({ erro: 'Saldo disponível insuficiente.' });

    // Verificar carência de 15 dias sobre investimentos ativos
    const agora = new Date();
    const limiteCarencia = new Date(agora.getTime() - 15 * 24 * 3600 * 1000);
    const investimentoEmCarencia = await Investment.findOne({
      userId: req.user.id,
      estado: 'ativo',
      alocadoEm: { $gt: limiteCarencia }
    });

    if (investimentoEmCarencia) {
      const diasRestantes = Math.ceil(
        (investimentoEmCarencia.alocadoEm.getTime() + 15*24*3600*1000 - agora.getTime()) / 86400000
      );
      return res.status(403).json({
        erro: `O seu capital investido encontra-se em período de carência de 15 dias. Levantamento disponível em ${diasRestantes} dia(s).`
      });
    }

    // Reduzir saldo e criar transação com estado "a_caminho"
    await User.findByIdAndUpdate(req.user.id, { $inc: { saldoDisponivel: -valor } });

    const transacao = await Transaction.create({
      userId: req.user.id,
      tipo: 'levantamento',
      valor,
      estado: 'a_caminho',
      descricao: 'Levantamento de fundos a caminho'
    });

    // ── Automação MVP: após 2 minutos atualiza para "depositado" ──
    const transacaoId = transacao._id;
    setTimeout(async () => {
      try {
        const t = await Transaction.findById(transacaoId);
        if (t && t.estado === 'a_caminho') {
          await Transaction.findByIdAndUpdate(transacaoId, {
            estado: 'depositado',
            descricao: 'Fundos depositados na conta',
            atualizadoEm: new Date()
          });
          console.log(`✅  Levantamento ${transacaoId} — Fundos depositados na conta (simulação 2min)`);
        }
      } catch (e) {
        console.error('Erro automação levantamento:', e.message);
      }
    }, 120000); // 2 minutos

    const userAtualizado = await User.findById(req.user.id);
    res.json({
      mensagem: 'Levantamento de fundos a caminho. Os fundos serão depositados na sua conta em 2 minutos.',
      transacaoId: transacao._id,
      estado: 'a_caminho',
      saldoDisponivel: userAtualizado.saldoDisponivel
    });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// ── ROTAS: EMPRÉSTIMOS ────────────────────────────────────────

app.post('/api/emprestimos/pedir', authMiddleware, async (req, res) => {
  try {
    // Verificar se há pelo menos um depósito confirmado
    const depositoExiste = await Transaction.findOne({
      userId: req.user.id,
      tipo: 'deposito',
      estado: 'confirmado'
    });

    if (!depositoExiste) {
      return res.status(403).json({
        erro: 'Funcionalidade de Crédito desabilitada. Efetue o seu primeiro depósito mínimo de 200 MT para habilitar o seu Score de Crédito.'
      });
    }

    const { valor, prazoMeses } = req.body;
    if (!valor || valor <= 0 || !prazoMeses)
      return res.status(400).json({ erro: 'Especifique o valor e o prazo do empréstimo.' });

    const user = await User.findById(req.user.id);
    const limiteCredito = user.creditScore * 50; // Cálculo simples de limite
    if (valor > limiteCredito && limiteCredito > 0)
      return res.status(400).json({ erro: `Valor excede o seu limite de crédito atual (MT ${limiteCredito.toLocaleString('pt-MZ')}).` });

    const taxaMensal = 3.5;
    const emprestimo = await Loan.create({
      userId: req.user.id,
      valor,
      taxaMensal,
      prazoMeses,
      estado: 'aprovado'
    });

    // Creditar saldo
    await User.findByIdAndUpdate(req.user.id, { $inc: { saldoDisponivel: valor } });

    await Transaction.create({
      userId: req.user.id,
      tipo: 'credito',
      valor,
      estado: 'confirmado',
      descricao: `Empréstimo aprovado — ${prazoMeses} meses @ ${taxaMensal}% a.m.`
    });

    const userAtualizado = await User.findById(req.user.id);
    res.json({
      mensagem: `Empréstimo de MT ${valor.toLocaleString('pt-MZ')} aprovado e creditado na sua conta.`,
      emprestimo,
      saldoDisponivel: userAtualizado.saldoDisponivel
    });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// ── ROTAS: TRANSAÇÕES ─────────────────────────────────────────

app.get('/api/transacoes', authMiddleware, async (req, res) => {
  try {
    const transacoes = await Transaction.find({ userId: req.user.id })
      .sort({ criadoEm: -1 }).limit(50);
    res.json(transacoes);
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// ── ROTAS: ADMIN ──────────────────────────────────────────────

app.get('/api/admin/utilizadores', adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select('-passwordHash').sort({ criadoEm: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

app.get('/api/admin/transacoes', adminMiddleware, async (req, res) => {
  try {
    const transacoes = await Transaction.find().populate('userId', 'nome email').sort({ criadoEm: -1 }).limit(100);
    res.json(transacoes);
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

app.post('/api/admin/levantamentos/aprovar/:id', adminMiddleware, async (req, res) => {
  try {
    const t = await Transaction.findById(req.params.id);
    if (!t) return res.status(404).json({ erro: 'Transação não encontrada.' });
    if (t.tipo !== 'levantamento') return res.status(400).json({ erro: 'Não é um levantamento.' });

    await Transaction.findByIdAndUpdate(req.params.id, {
      estado: 'depositado',
      descricao: 'Fundos depositados na conta (aprovação manual admin)',
      atualizadoEm: new Date()
    });

    res.json({ mensagem: 'Levantamento aprovado manualmente.', transacaoId: req.params.id });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

app.post('/api/admin/kyc/aprovar/:userId', adminMiddleware, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.userId, { kycAprovado: true });
    res.json({ mensagem: 'KYC aprovado.' });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// ── SERVIR SPA ────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── INICIAR SERVIDOR ──────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀  ANURA Fintech rodando em http://localhost:${PORT}`);
});

module.exports = app;