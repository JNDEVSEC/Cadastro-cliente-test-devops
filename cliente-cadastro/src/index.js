const express = require('express');
const app = express();
app.use(express.json());

let clientes = [];
let idCounter = 1;

// CRUD básico de clientes

// Listar todos
app.get('/clientes', (req, res) => {
  res.json(clientes);
});

// Criar cliente
app.post('/clientes', (req, res) => {
  const cliente = { id: idCounter++, ...req.body };
  clientes.push(cliente);
  res.status(201).json(cliente);
});

// Buscar cliente por id
app.get('/clientes/:id', (req, res) => {
  const cliente = clientes.find(c => c.id === parseInt(req.params.id));
  if (!cliente) return res.status(404).json({ error: 'Cliente não encontrado' });
  res.json(cliente);
});

// Atualizar cliente
app.put('/clientes/:id', (req, res) => {
  const idx = clientes.findIndex(c => c.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Cliente não encontrado' });
  clientes[idx] = { id: clientes[idx].id, ...req.body };
  res.json(clientes[idx]);
});

// Deletar cliente
app.delete('/clientes/:id', (req, res) => {
  clientes = clientes.filter(c => c.id !== parseInt(req.params.id));
  res.status(204).send();
});


// Porta padrão
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));

module.exports = app;
