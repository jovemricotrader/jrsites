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
function notifyQuartel(nome, email, telefone, abVisitor, abSlug) {
  if (!QUARTEL_URL) return;
  try {
    const body = JSON.stringify({ nome, email, telefone, fonte: 'leadlovers', ab_visitor: abVisitor, ab_slug: abSlug });
    const u = new URL(QUARTEL_URL + '/webhook/leadlovers');
    const lib = u.protocol === 'https:' ? require('https') : require('http');
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body)
    };
    if (process.env.WEBHOOK_SECRET) headers['x-webhook-secret'] = process.env.WEBHOOK_SECRET;
    const r = lib.request(
      { hostname: u.hostname, port: u.port || (u.protocol==='https:'?443:80),
        path: u.pathname, method: 'POST', headers },
      s => { s.on('data', () => {}); s.on('end', () => {}); }
    );
    r.on('error', () => {});
    r.setTimeout(5000, () => r.destroy());
    r.write(body); r.end();
  } catch {}
}

// V8: Marca conversão direta no A/B LP (chamado pelo /lead)
function trackConversao(slug, visitorHash) {
  if (!QUARTEL_URL || !slug || !visitorHash) return;
  try {
    const body = JSON.stringify({ slug, visitor_hash: visitorHash });
    const u = new URL(QUARTEL_URL + '/api/ab-lp/converteu');
    const lib = u.protocol === 'https:' ? require('https') : require('http');
    const r = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol==='https:'?443:80),
      path: u.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, s => { s.on('data',()=>{}); s.on('end',()=>{}); });
    r.on('error', () => {});
    r.setTimeout(3000, () => r.destroy());
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

// ═══════════════════════════════════════════════════════════════════════════
// V8 — A/B TEST LP BANDIT (rota mágica /ir/:slug)
// Anúncios apontam pra essa URL. Sistema decide qual variante mostrar.
// ═══════════════════════════════════════════════════════════════════════════
const crypto = require('crypto');

// Gera/lê visitor cookie (sticky bucket — mesmo user vê mesma variante)
function getOrSetVisitor(req, res) {
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/jr_v=([a-zA-Z0-9_-]+)/);
  if (m) return m[1];
  const v = crypto.randomBytes(16).toString('base64url');
  res.setHeader('Set-Cookie', `jr_v=${v}; Max-Age=31536000; Path=/; SameSite=Lax; Secure; HttpOnly`);
  return v;
}

// Chama Quartel pra decidir variante
function decideVariante(slug, visitorHash, callback) {
  if (!QUARTEL_URL) return callback(null);
  try {
    const u = new URL(`${QUARTEL_URL}/api/ab-lp/decide?slug=${encodeURIComponent(slug)}&visitor=${encodeURIComponent(visitorHash)}`);
    const lib = u.protocol === 'https:' ? require('https') : require('http');
    const r = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol==='https:'?443:80),
      path: u.pathname + u.search, method: 'GET'
    }, s => {
      let data = '';
      s.on('data', c => data += c);
      s.on('end', () => {
        try { const j = JSON.parse(data); callback(j.ok ? j : null); } catch { callback(null); }
      });
    });
    r.on('error', () => callback(null));
    r.setTimeout(3000, () => { r.destroy(); callback(null); });
    r.end();
  } catch { callback(null); }
}

// Registra visita no Quartel (fire-and-forget)
function trackVisita(slug, varianteId, visitorHash, req) {
  if (!QUARTEL_URL || !varianteId) return;
  try {
    const ua = req.headers['user-agent'] || '';
    const body = JSON.stringify({
      slug, variante_id: varianteId, visitor_hash: visitorHash,
      ua_short: /Mobile|Android|iPhone/i.test(ua) ? 'mobile' : 'desktop',
      utm_source: (req.query.utm_source || '').slice(0,80),
      utm_medium: (req.query.utm_medium || '').slice(0,80),
      utm_campaign: (req.query.utm_campaign || '').slice(0,80),
      ref: (req.headers.referer || '').slice(0,200)
    });
    const u = new URL(QUARTEL_URL + '/api/ab-lp/visita');
    const lib = u.protocol === 'https:' ? require('https') : require('http');
    const r = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol==='https:'?443:80),
      path: u.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, s => { s.on('data', () => {}); s.on('end', () => {}); });
    r.on('error', () => {});
    r.setTimeout(3000, () => r.destroy());
    r.write(body); r.end();
  } catch {}
}

// ROTA MÁGICA: /ir/:slug — anúncios apontam aqui
// Ex: /ir/jr-index-cap → bandit decide → redireciona pra v1, v2 ou v3
app.get('/ir/:slug', (req, res) => {
  const slug = String(req.params.slug || '').replace(/[^a-z0-9_-]/gi, '').slice(0, 40);
  if (!slug) return res.redirect('/');

  const visitor = getOrSetVisitor(req, res);

  decideVariante(slug, visitor, decision => {
    if (!decision || !decision.url) {
      return res.redirect('/'); // fallback se Quartel offline
    }

    // V10: valida URL retornada pelo Quartel — defense in depth
    const rawUrl = String(decision.url || '').trim();

    // URL interna: /lp/vX — whitelist absoluta
    if (/^\/lp\/v[1-6](\?.*)?$/.test(rawUrl)) {
      // Track visita async (não bloqueia redirect)
      trackVisita(slug, decision.variante_id, visitor, req);
      const qs = new URLSearchParams(req.query);
      qs.set('_v', visitor);
      qs.set('_s', slug);
      const cleanPath = rawUrl.split('?')[0];
      return res.redirect(302, cleanPath + '?' + qs.toString());
    }

    // URL externa: só permite se começar com https:// e for domínio confiável
    const TRUSTED_DOMAINS = [
      'jovemrico.com', 'novoindicador.jovemrico.com',
      'plano10k.net', 'jrindex.com.br',
      'pay.cakto.com.br', 'go.hotmart.com'
    ];
    try {
      const parsed = new URL(rawUrl);
      if (parsed.protocol !== 'https:') return res.redirect('/');
      const hostOk = TRUSTED_DOMAINS.some(d => parsed.hostname === d || parsed.hostname.endsWith('.' + d));
      if (!hostOk) return res.redirect('/');
      trackVisita(slug, decision.variante_id, visitor, req);
      return res.redirect(302, parsed.toString());
    } catch {
      return res.redirect('/');
    }
  });
});

// VARIANTES INTERNAS DE LP (cópias do index.html com tweaks)
// Servem com vars do experimento injetadas pra tracking
function serveLPVariant(file) {
  return (req, res) => {
    const visitor = getOrSetVisitor(req, res);
    const slug = String(req.query._s || '').replace(/[^a-z0-9_-]/gi, '').slice(0, 40);
    fs.readFile(path.join(__dirname, file), 'utf8', (err, html) => {
      if (err) return res.status(404).send('Not found');
      const inject = `<script>
window.ZAPY_WEBHOOK=${JSON.stringify(safeUrl(ZAPY_WEBHOOK))};
window.QUARTEL_URL=${JSON.stringify(safeUrl(QUARTEL_URL))};
window.AB_VISITOR=${JSON.stringify(visitor)};
window.AB_SLUG=${JSON.stringify(slug)};
</script>`;
      html = html.replace('</head>', inject + '\n</head>');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.send(html);
    });
  };
}

app.get('/lp/v1', serveLPVariant('lp-v1.html'));
app.get('/lp/v2', serveLPVariant('lp-v2.html'));
app.get('/lp/v3', serveLPVariant('lp-v3.html'));
app.get('/lp/v4', serveLPVariant('lp-v4.html'));
app.get('/lp/v5', serveLPVariant('lp-v5.html'));
app.get('/lp/v6', serveLPVariant('lp-v6.html'));

// ═══════════════════════════════════════════════════════════════════════════

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
  const abVisitor = String(b.ab_visitor || '').slice(0, 64);
  const abSlug = String(b.ab_slug || '').replace(/[^a-z0-9_-]/gi,'').slice(0, 40);
  if (email || telefone) notifyQuartel(nome, email, telefone, abVisitor, abSlug);
  // V8: marca conversão no bandit
  if (abVisitor && abSlug) trackConversao(abSlug, abVisitor);
  res.json({ ok: true });
});

// 404
app.use((req, res) => res.status(404).redirect('/'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`JR INDEX rodando na porta ${PORT}`));

process.on('uncaughtException', (err) => console.error('[CRASH]', err.message));
process.on('unhandledRejection', (r) => console.error('[REJECT]', r));
