import { Schema, model, Document } from 'mongoose';
import { IUser } from '../interfaces/user.interface';

const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
});

export const userModel = model<IUser>('Users', userSchema);
