const userModel = require('../Models/userModel');
const bcrypt = require('bcrypt')
const JWT = require('jsonwebtoken')
const Validator = require('../Validation/validation.js')



const register = async (req, res) => {

    try {

        const data = req.body
        let { name, email, password, phone } = data


        if (!name || !email || !password || !phone)
            return res.status(400).send({ status: false, message: `All fields are mandatory (e.g. name, email, password and phone) !` })

        if (!Validator.isValidName(name)) return res.status(400).send({ status: false, message: `This Name: '${name}' is not valid!` })

        if (!Validator.isValidEmail(email)) return res.status(400).send({ status: false, message: `This EmailID: '${email}' is not valid!` })

        if (!Validator.isValidpassword(password)) { return res.status(400).send({ status: false, message: "To make strong Password Should be use 8 to 15 Characters which including letters, atleast one special character and at least one Number." }) }

        if (!Validator.isValidMobileNumber(phone)) return res.status(400).send({ status: false, message: `This Phone No.: '${phone}' is not valid!` })


        const uniqueCheck = await userModel.findOne({ $or: [{ email: email }, { phone: phone }] })
        if (uniqueCheck) {
            if (uniqueCheck.email == email) {
                return res.render('errorPage', { message: `This EmailID: '${email}' is already used!` })
                // return res.status(400).send({ status: false, message: `This EmailID: '${email}' is already used!` })
            }
            if (uniqueCheck.phone == phone) {
                return res.render('errorPage', { message: `This Phone No.: '${phone}' is already used!` })
                // return res.status(400).send({ status: false, message: `This Phone No.: '${phone}' is already used!` })}
            }
        }

        const saltRound = 10
        data.password = await bcrypt.hash(password, saltRound)

        const savedData = await userModel.create({ name, email, password: data.password, phone })

        return res.render('errorPage', { message: `${name}: your data successfully created!` })

        // return res.status(201).send({ status: true, message: `${name}: your data successfully created!`, data: savedData })

    } catch (error) {

        return res.status(500).send({ status: false, message: error.message })
    }
}



const logInUser = async (req, res) => {

    try {

        const data = req.body
        const { email, password } = data


        if (!email || !password)
            return res.status(400).send({ status: false, message: `All fields are mandatory (e.g. email and password) !` })

        if (!Validator.isValidEmail(email)) return res.status(400).send({ status: false, message: `This EmailID: '${email}' is not valid!` })

        if (!Validator.isValidpassword(password)) {
            return res.status(400).send({ status: false, message: "To make strong Password Should be use 8 to 15 Characters which including letters, atleast one special character and at least one Number." })
        }


        const userData = await userModel.findOne({ email: email })
        if (!userData) {

            return res.render('errorPage', { message: "Invalid Login Credentials! You need to register first." })

            // return res.status(401).send({ status: false, message: "Invalid Login Credentials! You need to register first." })
        }

        const checkPassword = await bcrypt.compare(password, userData.password)

        if (checkPassword) {

            let payload = {
                userId: userData['_id'].toString(),
                Name: "Divyani"
            }

            const token = JWT.sign({ payload }, "Secret-Code-A1Z26", { expiresIn: 60 * 60 });

            const obj = { userId: userData['_id'], token: token }

            return res.render('Logout', { data: obj })

            // return res.status(200).send({ status: true, message: 'User login successfull', data: obj })

        } else {

            return res.render('errorPage', { message: 'Wrong Password !' })

            // return res.status(401).send({ status: false, message: 'Wrong Password' })
        }

    } catch (error) {

        return res.status(500).send({ status: false, message: error.message })
    }
}




module.exports = { register, logInUser }
