import { Schema, model} from 'mongoose'

const filmSchema = new Schema({
    name: {
        type: String
    },
    comment: {
        type: String,
        unique: true,
    }
})

export const filmModel = model('Film', filmSchema)