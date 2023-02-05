const express = require('express')
const router = express.Router()
const { register, logInUser } = require('../Controllers/userController.js')


router.post('/register', register)
router.post('/login', logInUser)


module.exports = router