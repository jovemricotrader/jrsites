const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const https = require('https');
const crypto = require('crypto');

const PORT     = process.env.PORT     || 3000;
const RESEND_KEY  = process.env.RESEND_API_KEY     || 're_athkVvum_BmRSNDFkQyYcjAydedvZj8MM';
const FROM_EMAIL  = process.env.FROM_EMAIL          || 'contato@jovemrico.com';
const SITE_URL    = process.env.SITE_URL            || 'https://fimdeob.jovemrico.com';
const SB_HOST = process.env.SUPABASE_HOST || 'xotatkushgbjivrqkufv.supabase.co';
const SB_KEY  = process.env.SUPABASE_SERVICE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhvdGF0a3VzaGdiaml2cnFrdWZ2Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NTA4NTY3OCwiZXhwIjoyMDkwNjYxNjc4fQ.aYMxEJCI-2gzknvJSqdcqeWfWPu3gaqo9z8VsWnk7Us';
const WA_LINK  = process.env.WA_LINK  || 'https://devzapp.com.br/api-engennier/campanha/api/redirect/67afa5e33a35eb00016e97ff'; // WhatsApp group link — set in Railway env
const WA_LINK_VIP = process.env.WA_LINK_VIP || 'https://devzapp.com.br/api-engennier/campanha/api/redirect/67afa5e33a35eb00016e97ff'; // VIP group link
const CAKTO_SECRET   = process.env.CAKTO_CLIENT_SECRET || 'Shm6PZBoVA0AmSRFr8XhVU69IZPleZL17UiQ7OTWBwIdIXsK4gtR31hdfvObm5UKVsySNqE0HSr81r46L9u9bWxZszSQd88Ca3qgyzg0pHmF3wb6DJj7Nf4bBMs1lMSy';


// ── SUPABASE PERSISTENCE ──
function sbQ(p){return new Promise(res=>{const o={hostname:SB_HOST,path:'/rest/v1/'+p,method:'GET',headers:{'apikey':SB_KEY,'Authorization':'Bearer '+SB_KEY,'Content-Type':'application/json'}};const r=https.request(o,s=>{let d='';s.on('data',c=>d+=c);s.on('end',()=>{try{res(JSON.parse(d))}catch{res([])}})});r.on('error',()=>res([]));r.setTimeout(8000,()=>{r.destroy();res([])});r.end();})}
// sbFetch: GET/POST/PATCH genérico
function sbFetch(path, method, body){
  if(!method||method==='GET') return sbQ(path);
  return new Promise(res=>{
    const p=body?JSON.stringify(body):'';
    const h={'apikey':SB_KEY,'Authorization':'Bearer '+SB_KEY,'Content-Type':'application/json','Prefer':'resolution=merge-duplicates'};
    if(p) h['Content-Length']=Buffer.byteLength(p);
    if(method==='PATCH') h['Prefer']='return=minimal';
    const o={hostname:SB_HOST,path:'/rest/v1/'+path,method,headers:h};
    const r=https.request(o,s=>{let d='';s.on('data',c=>d+=c);s.on('end',()=>{try{res(JSON.parse(d))}catch{res(true)}})});
    r.on('error',()=>res(false));r.setTimeout(8000,()=>{r.destroy();res(false)});
    if(p) r.write(p); r.end();
  });
}
// sbInsert: alias de sbI para compatibilidade
function sbInsert(t,row){return sbI(t,row);}
function sbI(t,row){return new Promise(res=>{const p=JSON.stringify(row);const o={hostname:SB_HOST,path:'/rest/v1/'+t,method:'POST',headers:{'apikey':SB_KEY,'Authorization':'Bearer '+SB_KEY,'Content-Type':'application/json','Prefer':'resolution=merge-duplicates','Content-Length':Buffer.byteLength(p)}};const r=https.request(o,s=>{s.on('data',()=>{});s.on('end',()=>res(true))});r.on('error',()=>res(false));r.setTimeout(8000,()=>{r.destroy();res(false)});r.write(p);r.end();})}
async function genTokenSB(tier,email){const token=crypto.randomBytes(24).toString('hex');const exp=new Date(Date.now()+30*24*3600*1000).toISOString();const ok=await sbI('event_tokens',{token,tier,email:email||'',event:'fim_ob_2026',expires_at:exp});if(!ok){console.error('[TOKEN] falha ao persistir token no Supabase');}TOKENS.set(token,{tier,email:email||'',expiresAt:Date.now()+30*24*3600*1000});return token;}
async function validateTokenSB(token){if(!token||token.length<10)return null;const m=TOKENS.get(token);if(m&&Date.now()<m.expiresAt)return m;try{const rows=await sbQ('event_tokens?token=eq.'+encodeURIComponent(token)+'&select=tier,email,expires_at');if(!Array.isArray(rows)||!rows[0])return null;if(new Date(rows[0].expires_at)<new Date())return null;const t={tier:rows[0].tier,email:rows[0].email||'',expiresAt:new Date(rows[0].expires_at).getTime()};TOKENS.set(token,t);return t;}catch{return null;}}


// ── RESEND EMAIL ──
async function sendEmail({ to, subject, html }) {
  if (!to || !RESEND_KEY) return;
  try {
    const payload = JSON.stringify({ from: FROM_EMAIL, to: [to], subject, html });
    const opts = {
      hostname: 'api.resend.com', path: '/emails', method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + RESEND_KEY,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    };
    await new Promise((resolve) => {
      const r = https.request(opts, res => {
        let d = ''; res.on('data', c => d += c);
        res.on('end', () => { console.log('[EMAIL]', res.statusCode); resolve(); });
      });
      r.on('error', e => { console.error('[EMAIL ERROR]', e.message); resolve(); });
      r.setTimeout(10000, () => { r.destroy(); console.error('[EMAIL TIMEOUT]'); resolve(); });
      r.write(payload); r.end();
    });
  } catch(e) { console.error('[EMAIL]', e.message); }
}

function emailEventoHtml(token, tier, amigoUrl) {
  const isDuplo = tier === 'duplo';
  const isVip   = tier === 'vip';
  const label   = isVip ? 'VIP' : isDuplo ? 'DUPLO' : 'INGRESSO';
  const acesso  = SITE_URL + '/obrigado?t=' + token;
  const amigoBlock = isDuplo && amigoUrl
    ? '<tr><td style="padding:16px 0"><div style="background:rgba(0,224,255,.04);border:1px solid rgba(0,224,255,.15);padding:20px;text-align:center"><div style="font-size:11px;letter-spacing:.2em;color:#00e0ff;margin-bottom:8px">LINK DO SEU AMIGO</div><div style="font-size:11px;color:#7078a0;margin-bottom:12px">Você comprou o ingresso Duplo — manda para seu amigo:</div><div style="background:#10131f;border:1px solid rgba(0,224,255,.15);padding:10px;font-size:11px;color:#00e0ff;word-break:break-all">' + amigoUrl + '</div></div></td></tr>'
    : '';
  return '<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><title>Ingresso Confirmado</title></head>'
    + '<body style="margin:0;padding:0;background:#10131f;font-family:Arial,sans-serif;color:#e0e1f3">'
    + '<table width="100%" cellpadding="0" cellspacing="0" style="background:#10131f;padding:40px 20px"><tr><td align="center">'
    + '<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%">'
    + '<tr><td style="padding:0 0 24px 0;text-align:center">'
    + '<div style="font-size:11px;letter-spacing:.4em;color:#42f09e;text-transform:uppercase;margin-bottom:8px">ACESSO CONFIRMADO</div>'
    + '<div style="font-size:28px;font-weight:900;color:#baf2ff">JR ORÁCULO</div>'
    + '<div style="font-size:11px;letter-spacing:.2em;color:#3b494c;margin-top:4px">FIM DAS OPÇÕES BINÁRIAS · 29 ABRIL · 21H</div>'
    + '</td></tr>'
    + '<tr><td style="padding:0 0 20px 0;text-align:center">'
    + '<div style="display:inline-block;background:rgba(0,224,255,.08);border:1px solid rgba(0,224,255,.2);padding:8px 20px;font-size:11px;letter-spacing:.2em;color:#00e0ff">INGRESSO ' + label + '</div>'
    + '</td></tr>'
    + '<tr><td style="background:#1c1f2b;border:1px solid rgba(0,224,255,.1);padding:32px;text-align:center">'
    + '<div style="font-size:13px;color:#7078a0;margin-bottom:20px;line-height:1.7">Seu ingresso está confirmado. Clica no botão abaixo para acessar o grupo e garantir seu lugar na live.</div>'
    + '<a href="' + acesso + '" style="display:inline-block;background:#00e0ff;color:#10131f;font-weight:900;font-size:15px;letter-spacing:.06em;text-decoration:none;padding:14px 36px;text-transform:uppercase">ACESSAR MEU INGRESSO</a>'
    + '<div style="margin-top:12px;font-size:10px;color:#3b494c">' + acesso + '</div>'
    + '</td></tr>'
    + amigoBlock
    + '<tr><td style="padding:24px 0 0 0;text-align:center;border-top:1px solid rgba(255,255,255,.05)">'
    + '<div style="font-size:10px;color:#3b494c;letter-spacing:.1em;line-height:1.8">@JovemRicoTrader · JR ORÁCULO<br>Este email foi enviado porque você realizou uma compra.</div>'
    + '</td></tr>'
    + '</table></td></tr></table></body></html>';
}

function emailOraculoHtml(licenseKey) {
  return '<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><title>Sua Licença JR ORÁCULO</title></head>'
    + '<body style="margin:0;padding:0;background:#10131f;font-family:Arial,sans-serif;color:#e0e1f3">'
    + '<table width="100%" cellpadding="0" cellspacing="0" style="background:#10131f;padding:40px 20px"><tr><td align="center">'
    + '<table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%">'
    + '<tr><td style="padding:0 0 24px 0;text-align:center">'
    + '<div style="font-size:11px;letter-spacing:.4em;color:#42f09e;text-transform:uppercase;margin-bottom:8px">LICENÇA ATIVA</div>'
    + '<div style="font-size:28px;font-weight:900;color:#baf2ff">JR ORÁCULO</div>'
    + '<div style="font-size:11px;letter-spacing:.2em;color:#3b494c;margin-top:4px">CLONE DA MENTE DO JR TRADER</div>'
    + '</td></tr>'
    + '<tr><td style="background:#1c1f2b;border:1px solid rgba(0,224,255,.15);padding:32px;text-align:center">'
    + '<div style="font-size:12px;color:#7078a0;margin-bottom:16px">Sua chave de licença individual:</div>'
    + '<div style="background:#10131f;border:1px solid rgba(0,224,255,.3);padding:14px 20px;font-size:14px;font-family:monospace;color:#00e0ff;letter-spacing:.08em;word-break:break-all">' + licenseKey + '</div>'
    + '<div style="margin-top:16px;font-size:11px;color:#3b494c;line-height:1.7">Cole essa chave na extensão JR ORÁCULO após instalá-la no Chrome.<br>Ela é única e intransferível — guarde com segurança.</div>'
    + '</td></tr>'
    + '<tr><td style="padding:24px 0 0 0;text-align:center;border-top:1px solid rgba(255,255,255,.05)">'
    + '<div style="font-size:10px;color:#3b494c;letter-spacing:.1em">@JovemRicoTrader · JR ORÁCULO</div>'
    + '</td></tr>'
    + '</table></td></tr></table></body></html>';
}



// ── eNOTAS — NFS-e automática ──
async function emitirNFSe({ email, nome, valorTotal, descricao, idExterno }) {
  const KEY_B64   = process.env.ENOTAS_API_KEY   || 'YWE2ZDYwNWItZjliOC00ZjgwLThjZGQtZDZkYmNmZDlhZWNh';
  const EMPRESA   = process.env.ENOTAS_EMPRESA_ID || '2dcea124-57ea-4867-bd78-083b5a640a00';
  if (!KEY_B64 || !EMPRESA) return;
  const apiKey = Buffer.from(KEY_B64, 'base64').toString();
  const auth   = 'Basic ' + Buffer.from(apiKey + ':').toString('base64');
  const body   = JSON.stringify({
    tipo: 'NFS-e', idExterno: String(idExterno || Date.now()),
    ambienteEmissao: 'Producao', enviarPorEmail: true,
    cliente: {
      nome: nome || email || 'Cliente', email: email || '', tipoPessoa: 'F',
      cpfCnpj: '00000000000',
      endereco: { codigoIbgeCidade: '3106200', cidade: 'Belo Horizonte', uf: 'MG',
                  cep: '30000000', logradouro: 'Não informado', numero: 'SN', bairro: 'Centro' }
    },
    servico: { descricao: descricao || 'Serviço digital - JR Trader' },
    valorTotal: Number(valorTotal) || 0,
  });
  return new Promise(resolve => {
    const req = https.request({
      hostname: 'api.enotasgw.com.br',
      path: `/v1/empresas/${EMPRESA}/nfes`,
      method: 'POST',
      headers: { 'Authorization': auth, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => { try { const r=JSON.parse(d); console.log('[ENOTAS]', res.statusCode, r.id||r.codigo||'ok'); resolve(r); } catch { resolve({}); } });
    });
    req.on('error', e => { console.error('[ENOTAS]', e.message); resolve({}); });
    req.setTimeout(10000, () => { req.destroy(); resolve({}); });
    req.write(body); req.end();
  });
}

// ── ENOTAS QUEUE — 7-day delay ──
async function queueNFSe(data) {
  // Store in Supabase to emit after 7 days
  const emitAfter = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  await sbFetch('pending_nfse', 'POST', { ...data, emit_after: emitAfter, emitted: false });
  console.log('[ENOTAS QUEUE] agendado para:', emitAfter);
}

async function processNFSeQueue() {
  const now = new Date().toISOString();
  const rows = await sbFetch(`pending_nfse?emitted=eq.false&emit_after=lte.${now}`);
  if (!Array.isArray(rows) || !rows.length) return { processed: 0 };
  let count = 0;
  for (const row of rows) {
    try {
      await emitirNFSe({ email: row.email, nome: row.nome, valorTotal: row.valor_total, descricao: row.descricao, idExterno: row.id_externo });
      await sbFetch(`pending_nfse?id=eq.${row.id}`, 'PATCH', { emitted: true, emitted_at: new Date().toISOString() });
      count++;
    } catch(e) { console.error('[ENOTAS QUEUE]', e.message); }
  }
  return { processed: count };
}
// ── TOKEN STORE (in-memory, 48h TTL) ──
// token → { tier, email, used, createdAt, expiresAt }
const TOKENS = new Map();
const TOKEN_TTL = 30 * 24 * 60 * 60 * 1000; // 30 dias — cobre o período do evento

function genToken(tier, email) {
  const token = crypto.randomBytes(24).toString('hex');
  const now = Date.now();
  TOKENS.set(token, {
    tier,
    email: email || '',
    used: 0,
    createdAt: now,
    expiresAt: now + TOKEN_TTL,
  });
  return token;
}

// Cleanup expired tokens every 30min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of TOKENS.entries()) {
    if (now > v.expiresAt) TOKENS.delete(k);
  }
}, 30 * 60 * 1000);

// Processa fila NFSe a cada 6h
setInterval(() => processNFSeQueue().catch(e => console.error('[CRON NFSe]', e.message)), 6 * 60 * 60 * 1000);

// ── HELPERS ──
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    const t = setTimeout(() => reject(new Error('timeout')), 10000);
    req.on('data', c => { body += c; if (body.length > 1e6) { clearTimeout(t); reject(new Error('too large')); } });
    req.on('end', () => { clearTimeout(t); resolve(body); });
    req.on('error', e => { clearTimeout(t); reject(e); });
  });
}

function json(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(data));
}

function serveFile(res, filePath, ct) {
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': ct, 'Cache-Control': 'no-store' });
    res.end(data);
  });
}

// ── CAKTO WEBHOOK ──
// tier detection by product ID or price
function detectProduct(body) {
  const raw = JSON.stringify(body);
  // Match by Cakto product ID (most reliable)
  if (raw.includes('ky2iw3a_839473')) return 'oraculo';
  // Match by product name
  const s = raw.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  if (s.includes('oraculo') || s.includes('oracle') || s.includes('extensao') || s.includes('jr oraculo')) return 'oraculo';
  // Evento products
  if (raw.includes('36e62hm_839322') || raw.includes('i8ffwh9')) return 'evento';
  return 'evento';
}

async function genLicenseKey(email, tier) {
  const licenseKey = crypto.randomUUID().toUpperCase();
  const now = new Date().toISOString();
  // Salva no Supabase oraculo_keys
  await sbInsert('oraculo_keys', {
    license_key: licenseKey,
    email: email || '',
    tier: tier || 'basic',
    active: true,
    daily_count: 0,
    last_reset: now.slice(0,10),
    created_at: now,
  });
  console.log(`[LICENSE] gerada: ${licenseKey.slice(0,8)}… email:${email}`);
  const nfseValor = tier === 'vip' ? 47 : 27;
  await queueNFSe({ email, nome: email, valor_total: nfseValor, id_externo: licenseKey.slice(0,8), descricao: 'JR ORÁCULO - Software de análise de trading - JR Trader' });
  if (email) {
    sendEmail({
      to: email,
      subject: '🔑 Sua Licença JR ORÁCULO — Guarde com segurança',
      html: emailOraculoHtml(licenseKey),
    });
  }
  return licenseKey;
}

function detectTier(body) {
  // Normaliza valor — suporte a centavos (4700) e reais (47)
  const raw   = body.product?.price || body.amount || body.value || body.total || 0;
  const price = Number(raw) > 200 ? Number(raw) / 100 : Number(raw);
  const name  = (body.product?.name || body.plan_name || body.offer_name || '').toLowerCase();
  if (name.includes('vip') || price === 47) return 'vip';
  if (name.includes('duplo') || price === 27) return 'duplo';
  // Fallback: busca no JSON só por nome explícito (nunca por número)
  const s = JSON.stringify(body).toLowerCase();
  if (s.includes('"vip"') || s.includes("'vip'")) return 'vip';
  if (s.includes('"duplo"') || s.includes("'duplo'")) return 'duplo';
  return 'basic';
}

function verifyHmac(payload, signature) {
  if (!CAKTO_SECRET) return true; // sem secret configurado — bypass só em dev
  if (!signature) return false; // tem secret mas sem assinatura → rejeita
  const expected = crypto.createHmac('sha256', CAKTO_SECRET).update(payload).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature)); }
  catch { return false; }
}

// ── SERVER ──
http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  const qs  = new URLSearchParams(req.url.includes('?') ? req.url.split('?')[1] : '');

  // Security headers on all responses
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');

  // ── STATIC FILES ──
  if (url === '/jr-foto.png') {
    return serveFile(res, path.join(__dirname, 'jr-foto.png'), 'image/png');
  }

  // ── MAIN PAGE ──
  if (url === '/' || url === '/fim-das-opcoes.html') {
    return serveFile(res, path.join(__dirname, 'fim-das-opcoes.html'), 'text/html; charset=utf-8');
  }

  
  // ── MANUAL JR (VIP only) ──
  if (url.startsWith('/manual-jr')) {
    const token = qs.get('t') || '';
    const row = await validateTokenSB(token);
    if (!row) { res.writeHead(302,{'Location':'/'}); res.end(); return; }
    if (row.tier !== 'vip') { res.writeHead(302,{'Location':'/obrigado?t='+encodeURIComponent(token)}); res.end(); return; }
    try {
      let pg = fs.readFileSync(path.join(__dirname,'manual-jr.html'),'utf8');
      pg = pg.split('__TOKEN__').join(token).split('__TIER__').join(row.tier);
      res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','X-Robots-Tag':'noindex'});
      res.end(pg); return;
    } catch(e) { res.writeHead(302,{'Location':'/'}); res.end(); return; }
  }

// ── OBRIGADO PAGE (token-gated) ──
  if (url === '/obrigado') {
    const token = qs.get('t') || qs.get('token') || '';
    const data  = await validateTokenSB(token);

    if (!data) {
      // Invalid/expired token → redirect home
      res.writeHead(302, { 'Location': '/?expired=1' });
      res.end();
      return;
    }

    // Read obrigado template and inject tier + anti-leak headers
    fs.readFile(path.join(__dirname, 'obrigado.html'), (err, raw) => {
      if (err) { res.writeHead(404); res.end('Not found'); return; }
      // Inject tier and token into page via meta-tag replacement
      let page = raw.toString()
        .replaceAll('__TOKEN__', token)
        .replaceAll('__TIER__', data.tier);

      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate, private',
        'Pragma': 'no-cache',
        'X-Robots-Tag': 'noindex, nofollow',
      });
      res.end(page);
    });
    return;
  }

  // ── API: get WhatsApp link (only with valid token) ──
  // ── API: amigo-token (duplo — retorna URL do amigo) ──
  if (url === '/api/amigo-token' && req.method === 'GET') {
    const token = qs.get('t') || '';
    const data = await validateTokenSB(token);
    if (!data) return json(res, { ok: false }, 401);
    if (data.tier !== 'duplo') return json(res, { ok: false, msg: 'Não é ingresso duplo' });
    try {
      // Busca coluna amigo_token direto no registro
      const rows = await sbQ('event_tokens?token=eq.'+encodeURIComponent(token)+'&select=amigo_token');
      const amigoToken = Array.isArray(rows) && rows[0] ? rows[0].amigo_token : null;
      if (amigoToken) {
        return json(res, { ok: true, url: '/obrigado?t=' + encodeURIComponent(amigoToken) });
      }
      return json(res, { ok: false, msg: 'Link sendo gerado — verifique seu email' });
    } catch(e) {
      return json(res, { ok: false, msg: 'Erro ao buscar link' });
    }
  }

  if (url === '/api/wa-link' && req.method === 'GET') {
    const token = qs.get('t') || '';
    const data  = await validateTokenSB(token);
    if (!data) return json(res, { ok: false }, 401);
    const link = data.tier === 'vip' ? WA_LINK_VIP : WA_LINK;
    if (!link || link === '#') return json(res, { ok: false, msg: 'Link em breve' }, 200);
    return json(res, { ok: true, link });
  }

  // ── API: generate test token (DEV ONLY — remove in prod) ──
  if (url === '/api/dev-token' && process.env.NODE_ENV !== 'production') {
    const tier  = qs.get('tier') || 'basic';
    const token = genToken(tier, 'test@dev.com');
    if (tier === 'duplo') {
      const token2 = genToken('basic', 'friend@dev.com');
      return json(res, { ok: true, token, token2, url: `/obrigado?t=${token}` });
    }
    return json(res, { ok: true, token, url: `/obrigado?t=${token}` });
  }

  // ── WEBHOOK: Cakto ──
  if (url === '/webhook/cakto' && req.method === 'POST') {
    try {
      const rawBody = await readBody(req);
      const sig = req.headers['x-cakto-signature'] || req.headers['x-signature'] || '';
      if (!verifyHmac(rawBody, sig)) {
        console.warn('[WEBHOOK] HMAC inválido');
        res.writeHead(401); res.end('Unauthorized'); return;
      }
      const body = JSON.parse(rawBody);
      const event = (body.event || body.type || '').toLowerCase();

      if (event.includes('paid') || event.includes('approved') || event.includes('complet')) {
        const email   = body.customer?.email || body.email || '';
        const tier    = detectTier(body);
        const product = detectProduct(body); // 'evento' ou 'oraculo'

        // ── Produto: JR ORÁCULO (pago único — gera license key) ──
        if (product === 'oraculo') {
          const licKey = await genLicenseKey(email, tier);
          console.log(`[WEBHOOK] ORÁCULO — email:${email} key:${licKey.slice(0,8)}…`);
          res.writeHead(200); res.end('OK'); return;
        }

        // ── Produto: Evento (gera token de acesso à pg obrigado) ──
        const token  = await genTokenSB(tier, email);

        if (tier === 'duplo') {
          const token2 = await genTokenSB('duplo_amigo', '');
          await sbFetch('event_tokens?token=eq.'+encodeURIComponent(token), 'PATCH', { amigo_token: token2 });
          console.log(`[WEBHOOK] DUPLO — email:${email} token1:${token.slice(0,8)} token2:${token2.slice(0,8)}`);
          await queueNFSe({ email, nome: email, valor_total: 27, id_externo: token.slice(0,8), descricao: 'Ingresso Duplo - Evento FIM DAS OPÇÕES BINÁRIAS - JR Trader' });
          if (email) {
            const amigoUrl = SITE_URL + '/obrigado?t=' + token2;
            sendEmail({
              to: email,
              subject: '✅ Ingresso Confirmado — FIM DAS OPÇÕES BINÁRIAS · 29 Abril',
              html: emailEventoHtml(token, 'duplo', amigoUrl),
            });
          }
        } else {
          console.log(`[WEBHOOK] ${tier.toUpperCase()} — email:${email} token:${token.slice(0,8)}`);
          await queueNFSe({ email, nome: email, valor_total: tier==='vip'?47:27, id_externo: token.slice(0,8), descricao: 'Ingresso - Evento FIM DAS OPÇÕES BINÁRIAS - JR Trader' });
          if (email) {
            sendEmail({
              to: email,
              subject: '✅ Ingresso Confirmado — FIM DAS OPÇÕES BINÁRIAS · 29 Abril',
              html: emailEventoHtml(token, tier, null),
            });
          }
        }
        res.writeHead(200); res.end('OK');
      } else {
        res.writeHead(200); res.end('OK');
      }
    } catch(e) {
      console.error('[WEBHOOK] error:', e.message);
      res.writeHead(500); res.end('Error');
    }
    return;
  }

  // ── HEALTH ──
  if (url === '/health') {
    res.writeHead(200); res.end(JSON.stringify({ ok: true, tokens: TOKENS.size }));
    return;
  }

  // ── CRON: processar fila NFSe (protegido por ADMIN_KEY) ──
  if (url === '/cron/emit-nfse' && req.method === 'POST') {
    const adminKey = req.headers['x-admin-key'] || qs.get('key') || '';
    if (adminKey !== (process.env.ADMIN_KEY || 'jr_admin_2026')) {
      res.writeHead(401); res.end('Unauthorized'); return;
    }
    const result = await processNFSeQueue();
    json(res, { ok: true, ...result });
    return;
  }

  res.writeHead(404); res.end('Not found');

}).listen(PORT, () => {
  console.log(`JR ORÁCULO SITE :${PORT}`);
  console.log(`Dev token: http://localhost:${PORT}/api/dev-token?tier=vip`);
});

// ── CRASH HANDLER GLOBAL ──
process.on('uncaughtException', (err) => {
  console.error('[CRASH] uncaughtException:', err.message, err.stack);
});
process.on('unhandledRejection', (reason) => {
  console.error('[CRASH] unhandledRejection:', reason);
});
