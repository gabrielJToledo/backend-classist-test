import { userRouter } from '../controllers/user.controller';
import { filmRouter } from './../controllers/film.controller';
import { Application } from 'express';
import { authenticateToken } from '../middlewares/auth.middleware';

export function initRoutes(app: Application) {
  app.use('/api/film', authenticateToken, filmRouter);
  app.use('/api/user', userRouter);
}
