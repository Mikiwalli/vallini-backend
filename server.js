// File: server.js
// server.js — backend di sviluppo completo (auth, profili, tariffe, shipping, pagamenti)
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

// =================== CONFIG ===================
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// Frontend consentiti (aggiungi se usi 8080 ecc.)
app.use(
  cors({
    origin: [
      'http://localhost:8000',
      'http://127.0.0.1:8000',
      'http://localhost:8080',
      'http://127.0.0.1:8080',
      'https://vallini.eu'   // <— aggiunta per il tuo dominio
    ],
    credentials: false,
  })
);
app.use(express.json({ limit: '8mb' }));
// Serve i file statici (index.html, checkout.html, ecc.)
app.use(express.static(path.join(__dirname)));

// =================== STATIC FRONTEND ===================
// Serve i file .html/.css/.js dalla stessa cartella di server.js
app.use(express.static(path.join(__dirname)));

// Servi i file statici della cartella corrente (index.html, checkout.html, ecc.)
app.use(express.static(path.join(__dirname)));

// =================== DEV "DB" SU FILE ===================
const DB_FILE = path.join(__dirname, 'dev-db.json');

function ensureDb() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({
      users: [],
      suppliers: {},
      tariffs: {},
      chatThreads: {},
      orders: {}            // <<< AGGIUNTO
    }, null, 2));
    return;
  }
  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    let changed = false;
    if (!db.users)       { db.users = []; changed = true; }
    if (!db.suppliers)   { db.suppliers = {}; changed = true; }
    if (!db.tariffs)     { db.tariffs = {}; changed = true; }
    if (!db.chatThreads) { db.chatThreads = {}; changed = true; }
    if (!db.orders)      { db.orders = {}; changed = true; }   // <<< AGGIUNTO
    if (changed) fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
  } catch {
    fs.writeFileSync(DB_FILE, JSON.stringify({
      users: [],
      suppliers: {},
      tariffs: {},
      chatThreads: {},
      orders: {}          // <<< AGGIUNTO
    }, null, 2));
  }
}
function readDb() { ensureDb(); return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
function writeDb(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }

function newId(prefix='id') {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2,8)}`;
}

// =================== AUTH MIDDLEWARE ===================
function authRequired(req, res, next) {
  const hdr = req.headers.authorization || '';
  theToken = hdr.startsWith('Bearer ') ? hdr.slice(7) : null; // (var non dichiarata: lasciata com’era)
  const token = theToken;
  if (!token) return res.status(401).json({ error: 'Missing bearer token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET); // { id, email, role }
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// =================== HEALTH ===================
app.get('/health', (req, res) => res.json({ ok: true }));

// =================== AUTH ===================
// === Registrazione fornitore semplice (email, password, conferma, nome, cognome, anno) ===
app.post('/suppliers/register', (req, res) => {
  try {
    const {
      email,
      password,
      confirmPassword,
      firstName,
      lastName,
      birthYear
    } = req.body || {};

    // Validazioni minime
    if (!email || !password || !confirmPassword || !firstName || !lastName || !birthYear) {
      return res.status(400).json({ error: 'Tutti i campi sono obbligatori' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Le password non coincidono' });
    }
    const y = Number(birthYear);
    if (!Number.isFinite(y) || String(birthYear).length !== 4) {
      return res.status(400).json({ error: 'Anno di nascita non valido' });
    }
    const nowYear = new Date().getFullYear();
    if ((nowYear - y) < 18) {
      return res.status(400).json({ error: 'Devi essere maggiorenne per registrarti' });
    }

    // DB
    const db = readDb();
    db.users = db.users || [];
    db.suppliers = db.suppliers || {};
    db.tariffs = db.tariffs || {};

    const exists = db.users.find(u => u.email.toLowerCase() === String(email).toLowerCase());
    if (exists) {
      return res.status(409).json({ error: 'Email già registrata' });
    }

    // Crea utente fornitore
    const id = 'u_' + Date.now();
    const createdAt = new Date().toISOString();
    db.users.push({
      id,
      email,
      password,           // (nota: per semplicità ora testo in chiaro; poi mettiamo hash)
      role: 'supplier',
      firstName,
      lastName,
      birthYear: y,
      createdAt
    });

    // Crea profilo fornitore di base (keyed by email)
    db.suppliers[email] = {
      userId: id,
      email,
      displayName: `${firstName} ${lastName}`,
      company: '',
      processes: ['Stampa3D'],   // default
      materials: ['PLA'],        // default
      address: {},
      tariffs: [],               // gestite dalle tue API /suppliers/tariffs
      createdAt,
      updatedAt: createdAt
    };

    writeDb(db);

    // Login immediato
    const token = jwt.sign({ id, email, role: 'supplier' }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Supplier signup error' });
  }
});

app.post('/auth/signup', (req, res) => {
  try {
    const { email, password, role } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Email e password sono obbligatorie' });
    }
    const db = readDb();
    const exists = db.users.find(u => u.email.toLowerCase() === String(email).toLowerCase());
    if (exists) {
      return res.status(400).json({ error: 'Utente già registrato' });
    }
    const id = 'u_' + Date.now();
    db.users.push({ id, email, password, role: role || 'supplier', createdAt: new Date().toISOString() });
    writeDb(db);

    const token = jwt.sign({ id, email, role: role || 'supplier' }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Signup error' });
  }
});

app.post('/auth/login', (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Email e password sono obbligatorie' });
    }
    const db = readDb();
    const user = db.users.find(u => u.email.toLowerCase() === String(email).toLowerCase());
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Credenziali non valide' });
    }
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role || 'supplier' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    return res.json({ token });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Login error' });
  }
});

// =================== PROFILO FORNITORE ===================
app.post('/suppliers/update', authRequired, (req, res) => {
  try {
    const profile = req.body || {};
    profile.email = req.user.email; // coerenza
    profile.updatedAt = new Date().toISOString();

    // 👇 Rende i profili visibili di default (a meno che sia inviato visibile:false)
    profile.visibile = (profile.visibile !== false);

    const db = readDb();
    db.suppliers[profile.email] = profile;
    writeDb(db);

    return res.json({ ok: true, supplier: profile });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Update profile error' });
  }
});

app.get('/me', authRequired, (req, res) => {
  try {
    const db = readDb();
    const email = req.user.email;
    const profile = db.suppliers[email] || null;
    res.json({
      user: { id: req.user.id, email, role: req.user.role },
      profile
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'me error' });
  }
});

// =================== CATALOGO MATERIALI ===================
const CATALOG = {
  Stampa3D: [
    { key:'PLA',        name:'PLA',                unit:'€/cm³', marketPrice:0.020, ratePerMin:0.10, process:'Stampa3D' },
    { key:'ABS',        name:'ABS',                unit:'€/cm³', marketPrice:0.025, ratePerMin:0.12, process:'Stampa3D' },
    { key:'PETG',       name:'PETG',               unit:'€/cm³', marketPrice:0.030, ratePerMin:0.15, process:'Stampa3D' },
    { key:'Nylon',      name:'Nylon (PA12)',       unit:'€/cm³', marketPrice:0.050, ratePerMin:0.20, process:'Stampa3D' },
    { key:'ResinaSLA',  name:'Resina (SLA)',       unit:'€/cm³', marketPrice:0.060, ratePerMin:0.22, process:'Stampa3D' },
    { key:'AlSi10Mg',   name:'Alluminio AlSi10Mg', unit:'€/cm³', marketPrice:0.500, ratePerMin:1.20, process:'Stampa3D' },
  ],
  CNC: [
    { key:'Al6061',   name:'Alluminio 6061', unit:'€/cm³', marketPrice:0.003, ratePerMin:0.50, process:'CNC' },
    { key:'Al7075',   name:'Alluminio 7075', unit:'€/cm³', marketPrice:0.004, ratePerMin:0.70, process:'CNC' },
    { key:'Steel1018',name:'Acciaio 1018',   unit:'€/cm³', marketPrice:0.006, ratePerMin:0.80, process:'CNC' },
    { key:'POM',      name:'POM/Delrin',     unit:'€/cm³', marketPrice:0.003, ratePerMin:0.45, process:'CNC' },
  ],
  Laser: [
    { key:'PMMA',     name:'Acrilico (PMMA)',     unit:'€/cm²', marketPrice:0.010, ratePerMin:20.00, process:'Laser' },
    { key:'Plywood',  name:'Compensato (Plywood)',unit:'€/cm²', marketPrice:0.008, ratePerMin:18.00, process:'Laser' },
    { key:'MDF',      name:'MDF',                 unit:'€/cm²', marketPrice:0.006, ratePerMin:18.00, process:'Laser' },
    { key:'Leather',  name:'Pelle',               unit:'€/cm²', marketPrice:0.012, ratePerMin:22.00, process:'Laser' },
  ],
};

app.get('/catalog/materials', authRequired, (req, res) => {
  const process = String(req.query.process || 'Stampa3D');
  const q = (req.query.q || '').toString().toLowerCase();
  const base = CATALOG[process] || [];
  const filtered = base.filter(m => !q || m.name.toLowerCase().includes(q) || m.key.toLowerCase().includes(q));
  res.json(filtered);
});

// --- Endpoints PUBBLICI di sola lettura (senza auth) ---
app.get('/public/catalog/materials', (req, res) => {
  const process = String(req.query.process || 'Stampa3D');
  const q = (req.query.q || '').toString().toLowerCase();
  const base = CATALOG[process] || [];
  const filtered = base.filter(m => !q || m.name.toLowerCase().includes(q) || m.key.toLowerCase().includes(q));
  res.json(filtered);
});

app.get('/public/shipping/carriers', (req, res) => {
  res.json(CARRIERS_IT);
});

// ======= ELENCO PUBBLICO FORNITORI (solo profili validi; nasconde chi ha visibile:false) =======
app.get('/public/suppliers', (req, res) => {
  try {
    const db = readDb();
    const suppliers = db.suppliers || {};
    const tariffs = db.tariffs || {};

    const out = Object.values(suppliers)
      .filter(s => s && s.email)                // profilo valido
      .filter(s => s.visibile !== false)        // nascondi chi non è visibile
      .map(s => {
        const email = s.email;
        const mats = Array.isArray(tariffs[email]) ? tariffs[email] : [];

        // Porta i materiali in un formato che il front-end capisce già
        const materials = mats.map(m => ({
          name: m.name || m.key || '',
          // Se l’unità è €/kg uso myPrice; se è €/cm³ lascio undefined (il front-end ha fallback)
          pricePerKg: (m.unit === '€/kg') ? Number(m.myPrice || m.marketPrice || 0) : undefined
        }));

        return {
          email,
          name: [s.nome, s.cognome].filter(Boolean).join(' ') || s.azienda || s.displayName || email,
          settings: {
            machineType: s.macchine || s.processes?.[0] || '3d',
            bed: s.maxBuild || s.bed || null,
            pricePerMinute: (mats.find(x => Number(x.ratePerMin) > 0)?.ratePerMin) || 0,
            materials,
            shipping: { city: s.citta || s.city || s.address?.city || '' },
            processTech: (Array.isArray(s.lavorazioni) && s.lavorazioni[0]) || s.processes?.[0] || 'fdm',
            machineModel: s.machineModel || ''
          }
        };
      });

    res.json(out);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'suppliers list error' });
  }
});

// =================== TARIFFE FORNITORE ===================
app.get('/suppliers/tariffs', authRequired, (req, res) => {
  const db = readDb();
  const email = req.user.email;
  res.json(db.tariffs[email] || []);
});

app.post('/suppliers/tariffs', authRequired, (req, res) => {
  try {
    const db = readDb();
    const email = req.user.email;
    const { materials } = req.body || {};
    if (!Array.isArray(materials)) {
      return res.status(400).json({ error:'Bad materials' });
    }
    const cleaned = materials.map(m => ({
      key:        String(m.key || '').slice(0,60),
      name:       String(m.name || '').slice(0,120),
      process:    String(m.process || '').slice(0,20),
      unit:       String(m.unit || '€/cm³'),
      marketPrice:Number(m.marketPrice || 0),
      myPrice:    Number(m.myPrice || 0),
      ratePerMin: Number(m.ratePerMin || 0),
      minQty:     Number(m.minQty || 0),
    }));
    db.tariffs[email] = cleaned;
    writeDb(db);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error:'save tariffs error' });
  }
});

// ====== Shipping: corrieri IT & prenotazione ritiro (mock) ======
const CARRIERS_IT = [
  { id: 'brt',  name: 'BRT (Bartolini)',     services: ['Standard', 'Express'] },
  { id: 'sda',  name: 'SDA',                 services: ['Standard'] },
  { id: 'gls',  name: 'GLS',                 services: ['Standard', '24h'] },
  { id: 'poste',name: 'Poste Italiane',      services: ['Crono', 'Raccomandata'] },
  { id: 'dhl',  name: 'DHL',                 services: ['Express Worldwide'] },
  { id: 'ups',  name: 'UPS',                 services: ['Standard', 'Saver'] },
  { id: 'fedex',name: 'FedEx/TNT',           services: ['International Priority'] },
];

app.get('/shipping/carriers', authRequired, (req, res) => {
  res.json(CARRIERS_IT);
});

app.post('/shipping/pickup', authRequired, (req, res) => {
  const { carrierId, date, timeFrom, timeTo, address, contact, parcels, notes } = req.body || {};
  if (!carrierId || !date || !timeFrom || !timeTo) {
    return res.status(400).json({ error: 'Dati pickup incompleti (carrierId, date, timeFrom, timeTo obbligatori).' });
  }
  const pickupId = 'pk_' + Math.random().toString(36).slice(2, 10);
  res.json({
    ok: true,
    pickupId,
    status: 'requested',
    carrierId, date, timeFrom, timeTo, address, contact, parcels, notes
  });
});

// =================== PAGAMENTI (Stripe o MOCK) ===================
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
let stripe = null;
let stripeActive = false;
try {
  if (STRIPE_SECRET_KEY && STRIPE_SECRET_KEY.startsWith('sk_')) {
    // eslint-disable-next-line global-require
    stripe = require('stripe')(STRIPE_SECRET_KEY);
    stripeActive = true;
    console.log('[payments] Stripe attivo');
  } else {
    console.log('[payments] Modalità MOCK (nessuna chiave Stripe valida)');
  }
} catch (e) {
  console.log('[payments] Stripe non inizializzato, uso MOCK:', e?.message || e);
}

const PLATFORM_FEE_PERCENT = Number(process.env.PLATFORM_FEE_PERCENT || 5);

app.post('/api/create-payment-intent', async (req, res) => {
  try {
    const { amount_cents, currency = 'eur', receipt_email, supplier_account_id, metadata, order_id } = req.body || {};
    if (!amount_cents || amount_cents <= 0) {
      return res.status(400).json({ error: 'amount_cents non valido' });
    }

    let clientSecret, mode;
    if (stripeActive && stripe) {
      const base = {
        amount: amount_cents,
        currency,
        automatic_payment_methods: { enabled: true },
        receipt_email: receipt_email || undefined,
        metadata: metadata || {}
      };
      if (supplier_account_id) {
        const fee = Math.round(amount_cents * (PLATFORM_FEE_PERCENT / 100));
        base.application_fee_amount = fee;
        base.transfer_data = { destination: supplier_account_id };
      }
      const intent = await stripe.paymentIntents.create(base);
      clientSecret = intent.client_secret;
      mode = 'stripe';
    } else {
      clientSecret = 'pi_mock_' + Math.random().toString(36).slice(2);
      mode = 'mock';
    }

    // Se arriva un order_id, memorizza clientSecret nel record ordine
    if (order_id) {
      const db = readDb();
      const order = db.orders?.[order_id];
      if (order) {
        order.payment = { ...(order.payment||{}), clientSecret, mode };
        order.status = 'awaiting_payment';
        order.updatedAt = new Date().toISOString();
        db.orders[order_id] = order;
        writeDb(db);
      }
    }

    return res.json({ clientSecret, mode });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'payment error' });
  }
});

// =================== ORDERS (crea/leggi/aggiorna stato) ===================

/**
 * POST /orders
 * Crea un ordine a partire da un preventivo lato client.
 * Body atteso (esempio):
 * {
 *   "items":[{ "name":"Pezzo PLA", "qty":1, "unit_price_cents": 1299 }],
 *   "subtotal_cents": 1299,
 *   "shipping_cents": 0,
 *   "total_cents": 1299,
 *   "currency":"eur",
 *   "customer":{ "email":"cliente@mail.com", "name":"Mario Rossi" },
 *   "supplier_email": "vendor@mail.com",
 *   "payment_method": "card|bank",
 *   "notes": "opzionale"
 * }
 */
app.post('/orders', async (req, res) => {
  try {
    const body = req.body || {};
    const required = ['items','total_cents'];
    for (const k of required) {
      if (!body[k]) return res.status(400).json({ error: `Campo mancante: ${k}` });
    }

    const id = newId('ord');
    const now = new Date().toISOString();
    const db = readDb();

    const order = {
      id,
      status: 'created',                    // created | awaiting_payment | paid | failed | awaiting_bank
      createdAt: now,
      updatedAt: now,
      items: Array.isArray(body.items) ? body.items : [],
      subtotal_cents: Number(body.subtotal_cents || 0),
      shipping_cents: Number(body.shipping_cents || 0),
      total_cents: Number(body.total_cents || 0),
      currency: String(body.currency || 'eur'),
      customer: body.customer || {},
      supplier_email: body.supplier_email || null,
      payment_method: body.payment_method || 'card',
      notes: body.notes || null,
      payment: { mode: null, clientSecret: null } // compilato in checkout
    };

    db.orders[id] = order;
    writeDb(db);
    res.json({ ok:true, order });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error:'create order error' });
  }
});

/**
 * GET /orders/:id
 */
app.get('/orders/:id', (req, res) => {
  const id = String(req.params.id || '');
  const db = readDb();
  const order = db.orders[id];
  if (!order) return res.status(404).json({ error:'order not found' });
  res.json(order);
});

/**
 * POST /orders/:id/paid
 * Segna l’ordine come pagato (es. callback client dopo conferma Stripe o mock).
 * Body: { payment_intent_id?: string }
 */
app.post('/orders/:id/paid', (req, res) => {
  const id = String(req.params.id || '');
  const db = readDb();
  const order = db.orders[id];
  if (!order) return res.status(404).json({ error:'order not found' });
  order.status = 'paid';
  order.updatedAt = new Date().toISOString();
  order.payment = { ...(order.payment||{}), intentId: req.body?.payment_intent_id || null, paidAt: order.updatedAt };
  db.orders[id] = order;
  writeDb(db);
  res.json({ ok:true, order });
});

/**
 * POST /orders/:id/awaiting-bank
 * Per bonifico: segna l’ordine come "in attesa" e salva eventuali istruzioni.
 * Body: { instructions?: string }
 */
app.post('/orders/:id/awaiting-bank', (req, res) => {
  const id = String(req.params.id || '');
  const db = readDb();
  const order = db.orders[id];
  if (!order) return res.status(404).json({ error:'order not found' });
  order.status = 'awaiting_bank';
  order.updatedAt = new Date().toISOString();
  order.payment = { ...(order.payment||{}), bankInstructions: req.body?.instructions || 'Bonifico SEPA entro 3 giorni' };
  db.orders[id] = order;
  writeDb(db);
  res.json({ ok:true, order });
});

// =================== AVVIO ===================
app.listen(PORT, () => {
  console.log(`Backend di sviluppo attivo:  http://localhost:${PORT}`);
  console.log(`Health check:               http://localhost:${PORT}/health`);
  console.log(`Static files:               http://localhost:${PORT}/index.html`);
});

