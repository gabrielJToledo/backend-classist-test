import { userModel } from './../model/user.model';
import { Request, Response, Router, NextFunction } from 'express';
import { genSaltSync, hashSync, compareSync } from 'bcrypt';
import jwt from 'jsonwebtoken';

export const userRouter = Router();

userRouter.post('/createUser', async (req: Request, res: Response) => {
    try {
        const { email, password, confirmPassword } = req.body;

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).send('O e-mail fornecido é inválido.');
        }

        if (password !== confirmPassword) {
            return res.status(400).send('A senha e a confirmação de senha não coincidem.');
        }

        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(400).send('Este e-mail já está em uso.');
        }

        const salt = genSaltSync(10);
        const hashedPassword = hashSync(password, salt);

        const newUser = {
            email: email,
            password: hashedPassword
        };

        const result = await userModel.create(newUser);

        return res.status(201).send('Usuário criado com sucesso!');

    } catch (error) {
        return res.status(500).send(error);
    }
});

userRouter.get('/login', async (req: Request, res: Response) => {
    try {
      const { email, password } = req.query;
  
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(String(email))) {
        return res.status(400).send('O e-mail fornecido é inválido.');
      }
  
      const user: any = await userModel.findOne({ email: String(email) });
  
      if (!user || !compareSync(String(password), user.password)) {
        return res.status(401).send('E-mail ou senha incorretos.');
      }
  
      const token = jwt.sign({ userId: user._id, email: user.email }, `${process.env.SECRET_KEY}`, { expiresIn: '1h' });
  
      return res.status(200).send(token);
  
    } catch (error) {
      return res.status(500).send(error);
    }
  });