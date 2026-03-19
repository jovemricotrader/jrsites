const express = require('express');
const path = require('path');
const app = express();

// www → sem www
app.use((req, res, next) => {
  if (req.headers.host && req.headers.host.startsWith('www.')) {
    return res.redirect(301, 'https://' + req.headers.host.replace('www.', '') + req.url);
  }
  next();
});

// Estáticos
app.use(express.static(path.join(__dirname)));

// Rotas /novoindicador
app.get('/novoindicador',          (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/novoindicador/',         (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/novoindicador/obrigado', (req, res) => res.sendFile(path.join(__dirname, 'obrigado.html')));

// Raiz → redireciona
app.get('/', (req, res) => res.redirect(301, '/novoindicador'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`JR Index rodando na porta ${PORT}`));
