const mongoose = require('mongoose')


const isValidBody = value => {
    if (typeof value === "undefined" || typeof value === "null") return false
    if (typeof value === "string" && value.trim().length == 0) return false
    return true
}


const isValidData = value => { return (Object.keys(value).length > 0) }
const isValidObjectId = value => { return mongoose.isValidObjectId(value) }


const isValidName = value => { return (/^[A-Z a-z]+$/).test(value) }
const isValidEmail = value => { return (/^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,3})$/.test(value)) }
const isValidMobileNumber = value => { return ((/^[6789][0-9]{9}$/g).test(value)) }
const isValidDate = value => { return ((/^\d{4}[\-\/\s]?((((0[13578])|(1[02]))[\-\/\s]?(([0-2][0-9])|(3[01])))|(((0[469])|(11))[\-\/\s]?(([0-2][0-9])|(30)))|(02[\-\/\s]?[0-2][0-9]))$/).test(value)) }
const isValidateStatus = value => { return ['ACTIVE', 'INACTIVE'].indexOf(value) !== -1 }
const isValidateCardType = value => { return ['REGULAR', 'SPECIAL'].indexOf(value) !== -1 }
const isValidpassword = (value) => { return (/^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,15}$/.test(value)) }


module.exports = {
    isValidName,
    isValidData,
    isValidObjectId,
    isValidBody,
    isValidMobileNumber,
    isValidEmail,
    isValidDate,
    isValidateStatus,
    isValidateCardType,
    isValidpassword
}