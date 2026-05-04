'use strict';
const express = require('express');
const path = require('path');
const fs = require('fs');
const compression = require('compression');
const app = express();

// ── V34: Compression gzip (reduz HTML 60-70%)
app.use(compression({
  level: 6,
  threshold: 1024, // só comprime > 1KB
}));

// ── BODY PARSERS (sem isso /lead crasha com req.body undefined)
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

// ── V34: Error handler (anti info disclosure — JSON malformado não vaza stack)
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError || err.type === 'entity.parse.failed') {
    return res.status(400).json({ ok: false, error: 'json_malformado' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ ok: false, error: 'payload_grande' });
  }
  console.error('[ERR]', req.method, req.path, err.message);
  res.status(500).json({ ok: false, error: 'erro_interno' });
});

// ── HARDENING
app.disable('x-powered-by');
// V15.2 SECURITY FIX: trust proxy = 1 (só 1 hop, evita XFF spoofing por atacante)
// Railway adiciona 1 layer de proxy. Atacante não pode forjar XFF.
app.set('trust proxy', 1);

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

// V15.1 HARDENING: whitelist rigorosa — só assets + bloquear código/config
// Lista de arquivos permitidos diretamente (imagens, fonts, etc)
const STATIC_WHITELIST_EXT = /\.(png|jpg|jpeg|webp|gif|svg|ico|woff2?|ttf|css|mp4|webm)$/i;

// Bloqueia acesso direto a:
// - server.js / package.json / *.md / *.zip
// - arquivos .html (só via rotas com serveWithVars/serveLPVariant)
// - arquivos dotfiles (.env, .git, etc)
app.use((req, res, next) => {
  const p = req.path;
  // Bloqueia dotfiles
  if (/\/\./.test(p)) return res.status(404).end();
  // Bloqueia código/config expostos
  if (/\.(js|json|md|zip|lock|ts|env|log|sh|yml|yaml|sql)$/i.test(p)) {
    return res.status(404).end();
  }
  // Bloqueia HTML direto (só via rotas nomeadas)
  if (/\.html?$/i.test(p)) {
    return res.status(404).end();
  }
  // Só segue pro static se for asset conhecido
  if (STATIC_WHITELIST_EXT.test(p)) return next();
  // Caminhos não-asset seguem pro roteamento normal
  return next();
});

// V34: Estáticos com cache agressivo pra assets + no-store HTML
app.use(express.static(path.join(__dirname), {
  maxAge: '7d', etag: true, immutable: false, index: false, dotfiles: 'deny',
  setHeaders: (res, filePath) => {
    if (/\.(png|jpg|jpeg|webp|gif|svg|woff2?|ttf)$/i.test(filePath)) {
      // assets imutáveis: 1 mês
      res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
    }
  }
}));

// Sanitiza URL para injeção segura no HTML (remove " < > \ e afins)
function safeUrl(u) {
  return String(u || '').replace(/[^a-zA-Z0-9:/?&=_.\-~%]/g, '');
}

// Notifica Quartel quando lead novo entra (fire-and-forget)
function notifyQuartel(nome, email, telefone, abVisitor, abSlug, lpVariant, utm) {
  if (!QUARTEL_URL) {
    console.log('[QUARTEL] notifyQuartel SKIPPED: QUARTEL_URL não configurado no Railway');
    return;
  }
  try {
    // V15.7: passa lp_variant + UTM (pra A/B comparar e segmentar no Quartel)
    const body = JSON.stringify({
      nome, email, telefone,
      fonte: 'leadlovers',
      ab_visitor: abVisitor,
      ab_slug: abSlug,
      lp_variant: lpVariant || '',
      utm_source: utm?.source || '',
      utm_campaign: utm?.campaign || '',
      utm_medium: utm?.medium || ''
    });
    // V15.10 FIX: ?disparar=1 obriga o Quartel a agendar a sequência automática
    // (sem isso o lead é criado mas não recebe a 1a msg do Aquecimento JR INDEX)
    const u = new URL(QUARTEL_URL + '/webhook/leadlovers?disparar=1');
    const lib = u.protocol === 'https:' ? require('https') : require('http');
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body)
    };
    // V15.11 FIX: aceita os 2 nomes de env (Quartel V43 usa LEADLOVERS_WEBHOOK_SECRET)
    const secret = process.env.LEADLOVERS_WEBHOOK_SECRET || process.env.WEBHOOK_SECRET || '';
    if (secret) headers['x-webhook-secret'] = secret;

    // V15.11 FIX: log diagnóstico pra ver no Railway o que tá rolando
    if (!secret) {
      console.warn('[QUARTEL] WARN: nenhum secret configurado (LEADLOVERS_WEBHOOK_SECRET ou WEBHOOK_SECRET) — Quartel vai rejeitar com 401');
    }

    const r = lib.request(
      { hostname: u.hostname, port: u.port || (u.protocol==='https:'?443:80),
        // V15.11 FIX CRÍTICO: u.pathname strippa o query string. PRECISA u.pathname + u.search
        path: u.pathname + u.search, method: 'POST', headers },
      s => {
        let chunks = '';
        s.on('data', d => { chunks += d.toString(); });
        s.on('end', () => {
          if (s.statusCode >= 200 && s.statusCode < 300) {
            console.log(`[QUARTEL] OK ${s.statusCode}: ${chunks.slice(0,200)}`);
          } else {
            console.error(`[QUARTEL] FAIL ${s.statusCode}: ${chunks.slice(0,200)}`);
          }
        });
      }
    );
    r.on('error', e => console.error('[QUARTEL] HTTP ERR:', e.message));
    r.setTimeout(5000, () => { console.error('[QUARTEL] TIMEOUT 5s'); r.destroy(); });
    r.write(body); r.end();
  } catch (e) {
    console.error('[QUARTEL] notifyQuartel exception:', e.message);
  }
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

// Helper: serve HTML injetando vars + pixels + otimizações (V34)
function serveWithVars(res, filePath) {
  fs.readFile(filePath, 'utf8', (err, html) => {
    if (err) return res.status(404).send('Not found');
    const zapy    = JSON.stringify(safeUrl(ZAPY_WEBHOOK));
    const quartel = JSON.stringify(safeUrl(QUARTEL_URL));

    // Meta Pixel — só injeta se META_PIXEL_ID configurado
    const pixelId = process.env.META_PIXEL_ID || '';
    const pixelValid = /^\d{10,20}$/.test(pixelId) ? pixelId : '';
    const metaPixel = pixelValid ? `
<!-- Meta Pixel Code -->
<script>
!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?
n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;
n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;
t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window,
document,'script','https://connect.facebook.net/en_US/fbevents.js');
fbq('init', '${pixelValid}');
fbq('track', 'PageView');
</script>
<noscript><img height="1" width="1" style="display:none" src="https://www.facebook.com/tr?id=${pixelValid}&ev=PageView&noscript=1"/></noscript>
<!-- End Meta Pixel Code -->` : '';

    // Google Analytics / GA4 — se GA_ID configurado
    const gaId = process.env.GA_ID || '';
    const gaValid = /^G-[A-Z0-9]{6,12}$/.test(gaId) ? gaId : '';
    const gaScript = gaValid ? `
<script async src="https://www.googletagmanager.com/gtag/js?id=${gaValid}"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}
gtag('js',new Date());gtag('config','${gaValid}');</script>` : '';

    // TikTok Pixel — se TIKTOK_PIXEL_ID configurado
    const ttId = process.env.TIKTOK_PIXEL_ID || '';
    const ttValid = /^[A-Z0-9]{15,30}$/.test(ttId) ? ttId : '';
    const ttPixel = ttValid ? `
<script>!function(w,d,t){w.TiktokAnalyticsObject=t;var ttq=w[t]=w[t]||[];ttq.methods=["page","track","identify","instances","debug","on","off","once","ready","alias","group","enableCookie","disableCookie"],ttq.setAndDefer=function(t,e){t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}};for(var i=0;i<ttq.methods.length;i++)ttq.setAndDefer(ttq,ttq.methods[i]);ttq.instance=function(t){for(var e=ttq._i[t]||[],n=0;n<ttq.methods.length;n++)ttq.setAndDefer(e,ttq.methods[n]);return e},ttq.load=function(e,n){var i="https://analytics.tiktok.com/i18n/pixel/events.js";ttq._i=ttq._i||{},ttq._i[e]=[],ttq._i[e]._u=i,ttq._t=ttq._t||{},ttq._t[e]=+new Date,ttq._o=ttq._o||{},ttq._o[e]=n||{};var o=document.createElement("script");o.type="text/javascript",o.async=!0,o.src=i+"?sdkid="+e+"&lib="+t;var a=document.getElementsByTagName("script")[0];a.parentNode.insertBefore(o,a)};ttq.load('${ttValid}');ttq.page();}(window,document,'ttq');</script>` : '';

    // Preconnect pra reduzir latência (resource hints)
    const hints = `<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>${pixelValid ? '<link rel="preconnect" href="https://connect.facebook.net">' : ''}${gaValid ? '<link rel="preconnect" href="https://www.googletagmanager.com">' : ''}`;

    // V15: Honeypot anti-bot — campos invisíveis que só bots preenchem
    // + wraps fetch('/lead') pra adicionar honeypot fields automaticamente em todas LPs
    const hpScript = `
<script>
(function(){
  // Intercepta fetch pra injetar honeypot
  var origFetch = window.fetch;
  window.fetch = function(url, opts){
    if (typeof url === 'string' && url.indexOf('/lead') !== -1 && opts && opts.body) {
      try {
        var b = JSON.parse(opts.body);
        // Anti-bot: honeypot fields (bots preenchem, humano deixa vazio)
        b._website = document.getElementById('_website') ? document.getElementById('_website').value : '';
        b._url = document.getElementById('_url') ? document.getElementById('_url').value : '';
        b._company = document.getElementById('_company') ? document.getElementById('_company').value : '';
        // Tempo pra submit (bot é instantâneo)
        b._ts = Date.now() - (window._pageLoadTs || Date.now());
        opts.body = JSON.stringify(b);
      } catch(e){}
    }
    return origFetch(url, opts);
  };
  window._pageLoadTs = Date.now();
  // Injeta campos honeypot invisíveis no body
  document.addEventListener('DOMContentLoaded', function(){
    if (document.getElementById('_hp_wrap')) return;
    var wrap = document.createElement('div');
    wrap.id = '_hp_wrap';
    wrap.setAttribute('aria-hidden', 'true');
    wrap.style.cssText = 'position:absolute;left:-9999px;top:-9999px;height:0;width:0;overflow:hidden;opacity:0;pointer-events:none';
    wrap.innerHTML = '<input type="text" id="_website" name="_website" tabindex="-1" autocomplete="off"><input type="text" id="_url" name="_url" tabindex="-1" autocomplete="off"><input type="text" id="_company" name="_company" tabindex="-1" autocomplete="off">';
    document.body.appendChild(wrap);
  });
})();
</script>`;

    const inject = `${hints}<script>window.ZAPY_WEBHOOK=${zapy};window.QUARTEL_URL=${quartel};window.FB_PIXEL_ID=${JSON.stringify(pixelValid)};</script>${metaPixel}${gaScript}${ttPixel}${hpScript}`;

    html = html.replace('</head>', inject + '\n</head>');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.send(html);
  });
}

// ── ROTAS PRINCIPAIS
// V15.3 FIX: Bandit DEVE rodar nas rotas principais (não só /ir/)
// Antes: /novoindicadorjr e / serviam SEMPRE index.html (sem A/B test)
// Agora: chama Bandit, redireciona pra /lp/vX (sticky bucket via cookie)
function banditRoute(slug) {
  return (req, res) => {
    const visitor = getOrSetVisitor(req, res);

    // Sticky bucket: lê cookie jr_v_lp manualmente (sem cookie-parser)
    const cookieHeader = req.headers.cookie || '';
    const stickyMatch = cookieHeader.match(/(?:^|;\s*)jr_v_lp=(v(?:[1-9]|1[0-2]))(?:;|$)/);
    const stickyVar = stickyMatch ? stickyMatch[1] : '';

    if (stickyVar) {
      // Já tem variante decidida — serve direto
      const file = `lp-${stickyVar}.html`;
      // Track visita assíncrono
      trackVisita(slug, stickyVar, visitor, req);
      return serveLPFile(res, file, visitor, slug);
    }

    // Primeira visita: chama Bandit pra decidir
    decideVariante(slug, visitor, decision => {
      let varId = decision?.variante_id;
      // Fallback: se Quartel offline, escolhe variante aleatória entre as 10
      if (!varId || !/^v([1-9]|1[0-2])$/.test(varId)) {
        const rand = Math.floor(Math.random() * 12) + 1;
        varId = 'v' + rand;
      }
      // Salva cookie de variante (sticky bucket — mesma LP em visitas futuras)
      // Set-Cookie manual (sem cookie-parser)
      const expires = new Date(Date.now() + 30*24*3600*1000).toUTCString();
      const existingCookies = res.getHeader('Set-Cookie') || [];
      const newCookie = `jr_v_lp=${varId}; Expires=${expires}; Path=/; SameSite=Lax`;
      const cookies = Array.isArray(existingCookies) ? [...existingCookies, newCookie] : [existingCookies, newCookie].filter(Boolean);
      res.setHeader('Set-Cookie', cookies);

      // Track visita
      trackVisita(slug, varId, visitor, req);
      // Serve a LP escolhida
      const file = `lp-${varId}.html`;
      serveLPFile(res, file, visitor, slug);
    });
  };
}

// Helper: serve LP file com vars injetadas (mesma lógica do serveLPVariant)
function serveLPFile(res, file, visitor, slug) {
  const fs = require('fs');
  fs.readFile(path.join(__dirname, file), 'utf8', (err, html) => {
    if (err) {
      // Fallback: se arquivo não existe (ex: lp-v999.html), serve index
      return serveWithVars(res, path.join(__dirname, 'index.html'));
    }
    // V15: Honeypot anti-bot
    const hpScript = `<script>(function(){var o=window.fetch;window.fetch=function(u,p){if(typeof u==='string'&&u.indexOf('/lead')!==-1&&p&&p.body){try{var b=JSON.parse(p.body);b._website=document.getElementById('_website')?document.getElementById('_website').value:'';b._url=document.getElementById('_url')?document.getElementById('_url').value:'';b._company=document.getElementById('_company')?document.getElementById('_company').value:'';b._ts=Date.now()-(window._pageLoadTs||Date.now());p.body=JSON.stringify(b);}catch(e){}}return o(u,p);};window._pageLoadTs=Date.now();document.addEventListener('DOMContentLoaded',function(){if(document.getElementById('_hp_wrap'))return;var w=document.createElement('div');w.id='_hp_wrap';w.setAttribute('aria-hidden','true');w.style.cssText='position:absolute;left:-9999px;top:-9999px;height:0;width:0;overflow:hidden;opacity:0;pointer-events:none';w.innerHTML='<input type="text" id="_website" name="_website" tabindex="-1" autocomplete="off"><input type="text" id="_url" name="_url" tabindex="-1" autocomplete="off"><input type="text" id="_company" name="_company" tabindex="-1" autocomplete="off">';document.body.appendChild(w);});})();</script>`;
    const inject = `<script>
window.ZAPY_WEBHOOK=${JSON.stringify(safeUrl(ZAPY_WEBHOOK))};
window.QUARTEL_URL=${JSON.stringify(safeUrl(QUARTEL_URL))};
window.AB_VISITOR=${JSON.stringify(visitor)};
window.AB_SLUG=${JSON.stringify(slug)};
</script>${hpScript}`;
    html = html.replace('</head>', inject + '\n</head>');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.send(html);
  });
}

// V15.3: Rota raiz USA Bandit (antes ia direto pro index.html)
app.get('/', banditRoute('jr-index-cap'));
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

    // URL interna: /lp/vX — whitelist absoluta (V15.3: v1 a v10)
    if (/^\/lp\/v([1-9]|1[0-2])(\?.*)?$/.test(rawUrl)) {
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
      // V15: Honeypot anti-bot
      const hpScript = `<script>(function(){var o=window.fetch;window.fetch=function(u,p){if(typeof u==='string'&&u.indexOf('/lead')!==-1&&p&&p.body){try{var b=JSON.parse(p.body);b._website=document.getElementById('_website')?document.getElementById('_website').value:'';b._url=document.getElementById('_url')?document.getElementById('_url').value:'';b._company=document.getElementById('_company')?document.getElementById('_company').value:'';b._ts=Date.now()-(window._pageLoadTs||Date.now());p.body=JSON.stringify(b);}catch(e){}}return o(u,p);};window._pageLoadTs=Date.now();document.addEventListener('DOMContentLoaded',function(){if(document.getElementById('_hp_wrap'))return;var w=document.createElement('div');w.id='_hp_wrap';w.setAttribute('aria-hidden','true');w.style.cssText='position:absolute;left:-9999px;top:-9999px;height:0;width:0;overflow:hidden;opacity:0;pointer-events:none';w.innerHTML='<input type="text" id="_website" name="_website" tabindex="-1" autocomplete="off"><input type="text" id="_url" name="_url" tabindex="-1" autocomplete="off"><input type="text" id="_company" name="_company" tabindex="-1" autocomplete="off">';document.body.appendChild(w);});})();</script>`;
      const inject = `<script>
window.ZAPY_WEBHOOK=${JSON.stringify(safeUrl(ZAPY_WEBHOOK))};
window.QUARTEL_URL=${JSON.stringify(safeUrl(QUARTEL_URL))};
window.AB_VISITOR=${JSON.stringify(visitor)};
window.AB_SLUG=${JSON.stringify(slug)};
</script>${hpScript}`;
      html = html.replace('</head>', inject + '\n</head>');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
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
app.get('/lp/v7', serveLPVariant('lp-v7.html'));
app.get('/lp/v8', serveLPVariant('lp-v8.html'));
app.get('/lp/v9', serveLPVariant('lp-v9.html'));
app.get('/lp/v10', serveLPVariant('lp-v10.html'));
// V15.5: novas LPs com VSL no topo (testar conversão)
app.get('/lp/v11', serveLPVariant('lp-v11.html'));
app.get('/lp/v12', serveLPVariant('lp-v12.html'));

// ═══════════════════════════════════════════════════════════════════════════

// ── FUNIL: novoindicador.jovemrico.com/novoindicadorjr → cap
// V15.3: novoindicadorjr USA Bandit (antes ia direto pro index.html)
app.get('/novoindicadorjr', banditRoute('jr-index-cap'));
app.get('/novoindicadorjr/', (req, res) => res.redirect(301, '/novoindicadorjr'));

// ── FUNIL: VSL liberado
app.get('/novoindicadorliberado', (req, res) => serveWithVars(res, path.join(__dirname, 'obrigado.html')));

// ── COMPAT
app.get('/novoindicador', (req, res) => res.redirect(301, '/'));
app.get('/novoindicador/', (req, res) => res.redirect(301, '/'));
app.get('/novoindicador/obrigado', (req, res) => res.redirect(301, '/obrigado'));

// ── LEAD — recebe dados do form client-side e notifica Quartel server-side
// ── V15: Rate limit em memória (anti spam/flood no /lead)
const _rateBuckets = new Map();
function rateLimit(ip, maxReq, windowMs) {
  const now = Date.now();
  const b = _rateBuckets.get(ip) || { count: 0, reset: now + windowMs };
  if (now > b.reset) { b.count = 0; b.reset = now + windowMs; }
  b.count++;
  _rateBuckets.set(ip, b);
  return b.count <= maxReq;
}
// Cleanup de buckets antigos a cada 10min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of _rateBuckets) if (now > v.reset + 60000) _rateBuckets.delete(k);
}, 10 * 60 * 1000);

// V15: Validação de email/telefone (aceita só dados reais)
function isEmailValido(e) {
  if (!e || e.length > 200) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
}
function isTelefoneValido(t) {
  if (!t) return false;
  const digits = t.replace(/\D/g, '');
  return digits.length >= 10 && digits.length <= 15;
}

// V15: Detecta padrões de spam/bot no nome
function isNomeSuspeito(nome) {
  if (!nome) return true;
  // Muito curto
  if (nome.length < 2) return true;
  // Só números ou caracteres estranhos
  if (!/[a-záéíóúãõâêôç ]/i.test(nome)) return true;
  // XSS/HTML na name
  if (/<[^>]+>|javascript:|data:|onerror|onclick/i.test(nome)) return true;
  return false;
}

app.post('/lead', (req, res) => {
  // V15.2: req.ip já vem confiável do trust proxy 1 (Railway sobrescreve XFF)
  // Removida a leitura direta de x-forwarded-for (vulnerável a spoofing)
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';

  // V15.2: Fingerprint extra (User-Agent + email) — protege contra IP rotation
  const ua = (req.headers['user-agent'] || '').slice(0, 100);
  const emailRaw = String(req.body?.email || '').trim().toLowerCase();
  // Fingerprint com hash simples (ip + ua + 1º domínio do email)
  const emailDomain = emailRaw.split('@')[1] || '';
  const fingerprint = `${ip}|${ua.slice(0,40)}|${emailDomain}`;

  // V15.2: Rate limit DUPLO — por IP E por fingerprint
  if (!rateLimit(ip, 5, 3600000)) {
    return res.status(429).json({ ok: false, error: 'muitas_tentativas' });
  }
  // Mesmo se atacante trocar de IP, o fingerprint pega
  if (!rateLimit('fp:' + fingerprint, 8, 3600000)) {
    return res.status(429).json({ ok: false, error: 'muitas_tentativas_fp' });
  }

  const b = req.body || {};

  // V15: HONEYPOT — campo invisível "_website" não deve ser preenchido (bots preenchem)
  if (b._website || b._url || b._company) {
    console.warn('[HONEYPOT]', ip, '→ bot detectado (honeypot preenchido)');
    // Retorna ok pra não dar dica que foi detectado
    return res.json({ ok: true });
  }

  // V15: Timing check — submit em menos de 2s é bot (humano leva 10s+ pra preencher form)
  const ts = Number(b._ts || 0);
  if (ts > 0 && ts < 2000) {
    console.warn('[TIMING]', ip, `→ bot detectado (submit em ${ts}ms)`);
    return res.json({ ok: true });
  }

  const nome = String(b.nome || '').trim().slice(0, 200);
  const email = String(b.email || '').trim().toLowerCase().slice(0, 200);
  const telefone = String(b.telefone || '').slice(0, 30);
  const abVisitor = String(b.ab_visitor || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  const abSlug = String(b.ab_slug || '').replace(/[^a-z0-9_-]/gi,'').slice(0, 40);
  // V15.7: lp_variant + UTMs pro Quartel categorizar
  const lpVariant = String(b.lp_variant || '').replace(/[^a-z0-9_-]/gi,'').slice(0, 20);
  const utm = {
    source:   String(b.utm_source   || '').replace(/[^a-z0-9_.-]/gi,'').slice(0, 40),
    campaign: String(b.utm_campaign || '').replace(/[^a-z0-9_.-]/gi,'').slice(0, 60),
    medium:   String(b.utm_medium   || '').replace(/[^a-z0-9_.-]/gi,'').slice(0, 40),
  };

  // V15: Valida nome
  if (isNomeSuspeito(nome)) {
    return res.status(400).json({ ok: false, error: 'nome_invalido' });
  }

  // V15: Pelo menos 1 contato válido (não aceita ambos vazios ou inválidos)
  const emailOk = isEmailValido(email);
  const telOk = isTelefoneValido(telefone);
  if (!emailOk && !telOk) {
    return res.status(400).json({ ok: false, error: 'contato_invalido' });
  }

  // V15: Email temporário/descartável (lista comum)
  if (emailOk) {
    const emailDom = email.split('@')[1] || '';
    const dominiosBad = ['mailinator.com','10minutemail.com','tempmail.com','guerrillamail.com','trashmail.com','yopmail.com','fakemail.com','throwaway.email','maildrop.cc','sharklasers.com'];
    if (dominiosBad.includes(emailDom)) {
      return res.status(400).json({ ok: false, error: 'email_descartavel' });
    }
  }

  // V15: Detecção de flood do mesmo email/tel (mesmo em IPs diferentes — bot net)
  const floodKey = `flood:${emailOk ? email : telefone}`;
  if (!rateLimit(floodKey, 2, 3600000)) {
    return res.status(429).json({ ok: false, error: 'duplicado' });
  }

  notifyQuartel(nome, emailOk ? email : '', telOk ? telefone : '', abVisitor, abSlug, lpVariant, utm);
  if (abVisitor && abSlug) trackConversao(abSlug, abVisitor);
  res.json({ ok: true });
});

// 404
app.use((req, res) => res.status(404).redirect('/'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`JR INDEX rodando na porta ${PORT}`));

process.on('uncaughtException', (err) => console.error('[CRASH]', err.message));
process.on('unhandledRejection', (r) => console.error('[REJECT]', r));
