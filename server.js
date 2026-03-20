'use strict';
const express = require('express');
const path = require('path');
const app = express();

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

// Estáticos (foto.jpg, etc.)
app.use(express.static(path.join(__dirname), { maxAge: '1h', etag: true }));

// ── ROTAS PRINCIPAIS
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/obrigado', (req, res) => res.sendFile(path.join(__dirname, 'obrigado.html')));

// ── FUNIL: novoindicador.jovemrico.com/novoindicadorjr → cap
app.get('/novoindicadorjr', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/novoindicadorjr/', (req, res) => res.redirect(301, '/novoindicadorjr'));

// ── FUNIL: VSL liberado
app.get('/novoindicadorliberado', (req, res) => res.sendFile(path.join(__dirname, 'obrigado.html')));

// ── COMPAT
app.get('/novoindicador', (req, res) => res.redirect(301, '/'));
app.get('/novoindicador/', (req, res) => res.redirect(301, '/'));
app.get('/novoindicador/obrigado', (req, res) => res.redirect(301, '/obrigado'));

// 404
app.use((req, res) => res.status(404).redirect('/'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`JR INDEX rodando na porta ${PORT}`));
