const mongoose = require('mongoose')


const userSchema = new mongoose.Schema({

    name: {
        type: String,
        required: true,

    },
    phone: {
        type: String,

    },
    email: {
        type: String,

    },
    password: {
        type: String,

    }

}, { timestamps: true })


module.exports = mongoose.model('UserData', userSchema)