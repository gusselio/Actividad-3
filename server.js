const express = require('express');
const fs = require('fs').promises;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json()); 

const PORT = 3000;
const SECRET_KEY = 'secreto_super_seguro_api';
const TAREAS_FILE = 'tareas.json';
const USUARIOS_FILE = 'usuarios.json';

// ==========================================
// 1. FUNCIONES AUXILIARES (Manejo de Archivos)
// ==========================================
async function leerDatos(archivo) {
    try {
        const data = await fs.readFile(archivo, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        return []; // Si el archivo no existe o está vacío, retorna un arreglo
    }
}

async function guardarDatos(archivo, datos) {
    await fs.writeFile(archivo, JSON.stringify(datos, null, 2));
}

// ==========================================
// 2. RUTAS DE AUTENTICACIÓN
// ==========================================
app.post('/register', async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) throw { status: 400, message: "Email y password requeridos" };

        const usuarios = await leerDatos(USUARIOS_FILE);
        if (usuarios.find(u => u.email === email)) {
            throw { status: 400, message: "El usuario ya existe" };
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        usuarios.push({ email, password: hashedPassword });
        await guardarDatos(USUARIOS_FILE, usuarios);

        res.status(201).json({ message: "Usuario registrado exitosamente" });
    } catch (error) {
        next(error); // Pasa el error al middleware global
    }
});

app.post('/login', async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const usuarios = await leerDatos(USUARIOS_FILE);
        
        const user = usuarios.find(u => u.email === email);
        if (!user) throw { status: 404, message: "Usuario no encontrado" };

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) throw { status: 401, message: "Contraseña incorrecta" };

        const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token, message: "Login exitoso" });
    } catch (error) {
        next(error);
    }
});

// ==========================================
// 3. MIDDLEWARE DE PROTECCIÓN DE RUTAS
// ==========================================
const verificarToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: "Token requerido" });

    jwt.verify(token.split(" ")[1], SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Token inválido o expirado" });
        req.user = decoded;
        next();
    });
};

// ==========================================
// 4. RUTAS CRUD DE TAREAS (Protegidas)
// ==========================================
// Crear tarea
app.post('/tareas', verificarToken, async (req, res, next) => {
    try {
        const { titulo, descripcion } = req.body;
        if (!titulo || !descripcion) throw { status: 400, message: "Título y descripción son obligatorios" };

        const tareas = await leerDatos(TAREAS_FILE);
        const nuevaTarea = { id: Date.now().toString(), titulo, descripcion };
        
        tareas.push(nuevaTarea);
        await guardarDatos(TAREAS_FILE, tareas);
        
        res.status(201).json(nuevaTarea);
    } catch (error) {
        next(error);
    }
});

// Leer tareas
app.get('/tareas', verificarToken, async (req, res, next) => {
    try {
        const tareas = await leerDatos(TAREAS_FILE);
        res.json(tareas);
    } catch (error) {
        next(error);
    }
});

// Actualizar tarea
app.put('/tareas/:id', verificarToken, async (req, res, next) => {
    try {
        const { id } = req.params;
        const { titulo, descripcion } = req.body;
        
        const tareas = await leerDatos(TAREAS_FILE);
        const index = tareas.findIndex(t => t.id === id);
        
        if (index === -1) throw { status: 404, message: "Tarea no encontrada" };

        tareas[index] = { ...tareas[index], titulo, descripcion };
        await guardarDatos(TAREAS_FILE, tareas);

        res.json(tareas[index]);
    } catch (error) {
        next(error);
    }
});

// Eliminar tarea
app.delete('/tareas/:id', verificarToken, async (req, res, next) => {
    try {
        const { id } = req.params;
        const tareas = await leerDatos(TAREAS_FILE);
        const tareasFiltradas = tareas.filter(t => t.id !== id);

        if (tareas.length === tareasFiltradas.length) {
            throw { status: 404, message: "Tarea no encontrada" };
        }

        await guardarDatos(TAREAS_FILE, tareasFiltradas);
        res.json({ message: "Tarea eliminada exitosamente" });
    } catch (error) {
        next(error);
    }
});

// ==========================================
// 5. MIDDLEWARE DE MANEJO DE ERRORES GLOBAL
// ==========================================
app.use((err, req, res, next) => {
    console.error(`[Error Debug]: ${err.message}`);
    const status = err.status || 500;
    res.status(status).json({
        error: true,
        message: err.message || "Error interno del servidor"
    });
});

// Inicializar servidor
app.listen(PORT, () => {
    console.log(`Servidor API REST ejecutándose en http://localhost:${PORT}`);
});