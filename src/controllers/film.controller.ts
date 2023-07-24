import { filmModel } from '../model/film.model';
import { Request, Response, Router, NextFunction } from 'express';
import { genSaltSync, hashSync, compareSync } from 'bcrypt';

export const filmRouter = Router();

filmRouter.post('/createComment', async (req: Request, res: Response) => {
    try {
        const { name, comment } = req.body;

        if (!name || !comment) {
            return res.status(400).send('Nome e comentário são obrigatórios.');
        }

        if (comment.length > 170) {
            return res.status(400).send('O comentário deve ter no máximo 170 caracteres.');
        }

        const allComments = await filmModel.find({});
        if (allComments.length >= 6) {
            return res.status(400).send('Limite máximo de 6 comentários atingido.');
        }

        const newComment = {
            name: name,
            comment: comment
        };

        const result = await filmModel.create(newComment);

        return res.status(201).send(result);

    } catch (error) {
        return res.status(500).send('Ocorreu um erro ao inserir o comentário.');
    }
});

filmRouter.get('/getAllComments', async (req: Request, res: Response) => {
    try {
        const allComments = await filmModel.find({});

        return res.status(200).send(allComments);

    } catch (error) {
        return res.status(500).send('Ocorreu um erro ao buscar os comentários.');
    }
});

filmRouter.delete('/deleteComment/:id', async (req: Request, res: Response) => {
    try {
        const commentId = req.params.id;

        if (!commentId) {
            return res.status(400).send('ID do comentário não fornecido.');
        }

        const commentToDelete = await filmModel.findById(commentId);

        if (!commentToDelete) {
            return res.status(404).send('Comentário não encontrado.');
        }

        await filmModel.findByIdAndDelete(commentId);

        return res.status(200).send('Comentário deletado.');

    } catch (error) {
        return res.status(500).send('Ocorreu um erro ao deletar o comentário.');
    }
});