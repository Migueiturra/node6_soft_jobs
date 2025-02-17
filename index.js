import express from "express";
import cors from "cors";
import pkg from "pg";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import authMiddleware from "./middlewares/authMiddleware.js";

dotenv.config();
const { Pool } = pkg;

// Base de datos
const pool = new Pool({
  user: process.env.DB_USER || "postgres",
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "softjobs",
  password: process.env.DB_PASSWORD || "123456",
  port: process.env.DB_PORT || 5432,
});

const app = express();
app.use(cors());
app.use(express.json());

// Middleware registrar consultas en consola
app.use((req, res, next) => {
    console.log(`📌 Consulta recibida: ${req.method} ${req.url}`);
    next();
});

// Ruta para registrar usuarios (con verificación de duplicados)
app.post("/usuarios", async (req, res) => {
  try {
    const { email, password, rol, lenguaje } = req.body;

    if (!email || !password || !rol || !lenguaje) {
      return res.status(400).json({ error: "Todos los campos son obligatorios" });
    }

    // 🔍 Verificar si el email si es que ya está registrado
    const emailExistente = await pool.query("SELECT * FROM usuarios WHERE email = $1", [email]);

    if (emailExistente.rows.length > 0) {
      return res.status(400).json({ error: "El email ya está registrado" });
    }

    // Encriptar la contraseña
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insertar el usuario en la base de datos
    const query = "INSERT INTO usuarios (email, password, rol, lenguaje) VALUES ($1, $2, $3, $4) RETURNING *";
    const values = [email, hashedPassword, rol, lenguaje];
    const result = await pool.query(query, values);

    res.status(201).json({ message: "Usuario registrado con éxito", usuario: result.rows[0] });
  } catch (error) {
    console.error("Error al registrar usuario:", error);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// Ruta de Login
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        // Verificar que ambos campos están presentes
        if (!email || !password) {
            return res.status(400).json({ error: "Email y contraseña son obligatorios" });
        }

        const { rows } = await pool.query("SELECT * FROM usuarios WHERE email = $1", [email]);

        // Si el usuario no existe, devolver error
        if (rows.length === 0) {
            return res.status(401).json({ error: "Credenciales incorrectas" });
        }

        const usuario = rows[0];

        // Comprobar valores en consola
        console.log("Intento de login para:", email);
        console.log("Contraseña ingresada:", password);
        console.log("Contraseña en BD (hash):", usuario.password);

        // Comparar la contraseña ingresada con la almacenada encriptada
        const passwordCorrecto = await bcrypt.compare(password, usuario.password);

        if (!passwordCorrecto) {
            return res.status(401).json({ error: "Credenciales incorrectas" });
        }

        // Verificar que la clave JWT esté definida
        if (!process.env.JWT_SECRET) {
            throw new Error("Falta la variable JWT_SECRET en el archivo .env");
        }

        // Generar el token JWT
        const token = jwt.sign({ email: usuario.email }, process.env.JWT_SECRET, { expiresIn: "1h" });

        res.json({ token });

    } catch (error) {
        console.error("Error en POST /login:", error.message);
        res.status(500).json({ error: "Error en el servidor durante la autenticación" });
    }
});

// Ruta protegida para obtener datos de usuario identificado
app.get("/usuarios", authMiddleware, async (req, res) => {
    try {
        const { email } = req.user; // Obtenemos el email del token
        const { rows } = await pool.query("SELECT * FROM usuarios WHERE email = $1", [email]);

        if (rows.length === 0) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        res.json(rows[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// Iniciar el servidor
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
