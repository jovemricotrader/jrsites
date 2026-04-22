'use strict';
const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();

// ── BODY PARSERS (sem isso /lead crasha com req.body undefined)
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

// ── HARDENING
app.disable('x-powered-by');
app.set('trust proxy', true);

// ── ENV
const ZAPY_WEBHOOK  = process.env.ZAPY_WEBHOOK  || '';
const QUARTEL_URL   = process.env.QUARTEL_URL   || ''; // https://quartel.jovemrico.com

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// www → sem www
app.use((req, res, next) => {
  if (req.headers.host && req.headers.host.startsWith('www.')) {
    return res.redirect(301, 'https://' + req.headers.host.replace('www.', '') + req.url);
  }
  next();
});

// Estáticos (foto.png, etc.) — sem cache no HTML, cache em assets
app.use(express.static(path.join(__dirname), {
  maxAge: '1h', etag: true,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-store');
  }
}));

// Sanitiza URL para injeção segura no HTML (remove " < > \ e afins)
function safeUrl(u) {
  return String(u || '').replace(/[^a-zA-Z0-9:/?&=_.\-~%]/g, '');
}

// Notifica Quartel quando lead novo entra (fire-and-forget)
function notifyQuartel(nome, email, telefone) {
  if (!QUARTEL_URL) return;
  try {
    const body = JSON.stringify({ nome, email, telefone, fonte: 'leadlovers' });
    const u = new URL(QUARTEL_URL + '/webhook/leadlovers');
    const lib = u.protocol === 'https:' ? require('https') : require('http');
    const r = lib.request(
      { hostname: u.hostname, port: u.port || (u.protocol==='https:'?443:80),
        path: u.pathname, method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      s => { s.on('data', () => {}); s.on('end', () => {}); }
    );
    r.on('error', () => {});
    r.setTimeout(5000, () => r.destroy());
    r.write(body); r.end();
  } catch {}
}

// Helper: serve HTML injetando vars como variáveis JS
function serveWithVars(res, filePath) {
  fs.readFile(filePath, 'utf8', (err, html) => {
    if (err) return res.status(404).send('Not found');
    const zapy    = JSON.stringify(safeUrl(ZAPY_WEBHOOK));
    const quartel = JSON.stringify(safeUrl(QUARTEL_URL));
    const inject = `<script>window.ZAPY_WEBHOOK=${zapy};window.QUARTEL_URL=${quartel};</script>`;
    html = html.replace('</head>', inject + '\n</head>');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(html);
  });
}

// ── ROTAS PRINCIPAIS
app.get('/', (req, res) => serveWithVars(res, path.join(__dirname, 'index.html')));
app.get('/obrigado', (req, res) => serveWithVars(res, path.join(__dirname, 'obrigado.html')));

// ── FUNIL: novoindicador.jovemrico.com/novoindicadorjr → cap
app.get('/novoindicadorjr', (req, res) => serveWithVars(res, path.join(__dirname, 'index.html')));
app.get('/novoindicadorjr/', (req, res) => res.redirect(301, '/novoindicadorjr'));

// ── FUNIL: VSL liberado
app.get('/novoindicadorliberado', (req, res) => serveWithVars(res, path.join(__dirname, 'obrigado.html')));

// ── COMPAT
app.get('/novoindicador', (req, res) => res.redirect(301, '/'));
app.get('/novoindicador/', (req, res) => res.redirect(301, '/'));
app.get('/novoindicador/obrigado', (req, res) => res.redirect(301, '/obrigado'));

// ── LEAD — recebe dados do form client-side e notifica Quartel server-side
app.post('/lead', (req, res) => {
  const b = req.body || {};
  const nome = String(b.nome || '').slice(0, 200);
  const email = String(b.email || '').slice(0, 200);
  const telefone = String(b.telefone || '').slice(0, 30);
  if (email || telefone) notifyQuartel(nome, email, telefone);
  res.json({ ok: true });
});

// 404
app.use((req, res) => res.status(404).redirect('/'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`JR INDEX rodando na porta ${PORT}`));

process.on('uncaughtException', (err) => console.error('[CRASH]', err.message));
process.on('unhandledRejection', (r) => console.error('[REJECT]', r));
