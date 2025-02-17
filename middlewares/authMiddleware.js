import jwt from "jsonwebtoken";

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ error: "Token no proporcionado" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Guardamos los datos en req.user
        next(); // Continuar con la ejecución
    } catch (error) {
        return res.status(401).json({ error: "Token inválido" });
    }
};

export default authMiddleware;
