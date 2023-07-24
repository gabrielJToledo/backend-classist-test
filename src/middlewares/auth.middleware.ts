import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

interface AuthRequest extends Request {
    user?: any;
}

export function authenticateToken(req: AuthRequest, res: Response, next: NextFunction) {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) {
        return res.status(401).send('Token de autenticação não fornecido.');
    }

    jwt.verify(token, `${process.env.SECRET_KEY}`, (err, user) => {
        if (err) {
            return res.status(403).send('Token de autenticação inválido.');
        }
        req.user = user;
        next();
    });
}
