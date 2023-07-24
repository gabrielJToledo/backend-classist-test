import request from 'supertest';
import { userModel } from './../model/user.model';
import app from '../index'

describe('userRouter', () => {
    it('should not create a user with a duplicate email', async () => {
        const existingUser = {
            email: 'test@example.com',
            password: 'hashedPassword',
        };
        await userModel.create(existingUser);

        const mockReq = {
            body: {
                email: 'test@example.com',
                password: 'testPassword',
                confirmPassword: 'testPassword',
            },
        };

        const response = await request(app).post('/api/user/createUser').send(mockReq.body);

        expect(response.status).toBe(400);
        expect(response.text).toBe('Este e-mail já está em uso.');
    });
});
