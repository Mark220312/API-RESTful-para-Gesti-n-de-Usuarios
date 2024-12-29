
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const app = express();

app.use(bodyParser.json());

const PORT = 3000;
const SECRET_KEY = 'mi_secreto_super_seguro';

const usuarios = [];

// Generar token JWT
function generarToken(usuario) {
  return jwt.sign({ id: usuario.id, username: usuario.username }, SECRET_KEY, { expiresIn: '1h' });
}

// Middleware para verificar tokens JWT
function autenticarToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ mensaje: 'Acceso denegado' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ mensaje: 'Token inválido' });
    req.user = user;
    next();
  });
}


// Registro de usuario
app.post('/registro', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ mensaje: 'Se requieren username y password' });
  }

  const hash = await bcrypt.hash(password, 10);
  const nuevoUsuario = { id: usuarios.length + 1, username, password: hash };
  usuarios.push(nuevoUsuario);
  res.status(201).json({ mensaje: 'Usuario registrado', usuario: { id: nuevoUsuario.id, username: nuevoUsuario.username } });
});

// Inicio de sesión
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const usuario = usuarios.find(u => u.username === username);
  if (!usuario) {
    return res.status(404).json({ mensaje: 'Usuario no encontrado' });
  }

  const esValido = await bcrypt.compare(password, usuario.password);
  if (!esValido) {
    return res.status(403).json({ mensaje: 'Credenciales incorrectas' });
  }

  const token = generarToken(usuario);
  res.json({ mensaje: 'Inicio de sesión exitoso', token });
});

// Obtener perfil del usuario autenticado
app.get('/perfil', autenticarToken, (req, res) => {
  const usuario = usuarios.find(u => u.id === req.user.id);
  if (!usuario) {
    return res.status(404).json({ mensaje: 'Usuario no encontrado' });
  }
  res.json({ id: usuario.id, username: usuario.username });
});

// Actualizar perfil
app.put('/perfil', autenticarToken, (req, res) => {
  const { username, password } = req.body;
  const usuario = usuarios.find(u => u.id === req.user.id);
  if (!usuario) {
    return res.status(404).json({ mensaje: 'Usuario no encontrado' });
  }

  if (username) usuario.username = username;
  if (password) usuario.password = bcrypt.hashSync(password, 10);

  res.json({ mensaje: 'Perfil actualizado', usuario: { id: usuario.id, username: usuario.username } });
});

// Eliminar perfil
app.delete('/perfil', autenticarToken, (req, res) => {
  const index = usuarios.findIndex(u => u.id === req.user.id);
  if (index === -1) {
    return res.status(404).json({ mensaje: 'Usuario no encontrado' });
  }
  usuarios.splice(index, 1);
  res.json({ mensaje: 'Usuario eliminado' });
});

// Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
