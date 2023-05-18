const { Joi, Segments } = require('celebrate')
    
const signUpUserDto = {
    [Segments.BODY]: Joi.object().keys({
        username: Joi.string().min(6).max(30).required(),
        email: Joi.string().required().email(),
        password: Joi.string()/* .pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')) */.required().min(8),
        repeat_password: Joi.ref('password'),
        role: Joi.string().default('user'),
    })
}
    
const signInUserDto = {
    [Segments.BODY]: Joi.object().keys({
        username: Joi.string().min(6).max(30).required(),
        password: Joi.string()/* .pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')) */.required().min(8),
        role: Joi.string().default('user'),
    })
}

module.exports = {
    signUpUserDto,
    signInUserDto,
}