const { Joi, Segments } = require('celebrate')
    
const getOrderDto = {
    [Segments.BODY]: Joi.object().keys({
        id: Joi.string().required(),
    })
}
    
const confirmOrderDto = {
    [Segments.BODY]: Joi.object().keys({
        id: Joi.string().required(),
    })
}
    
const declineOrderDto = {
    [Segments.BODY]: Joi.object().keys({
        id: Joi.string().required(),
        reason: Joi.string().required(),
    })
}

module.exports = {
    getOrderDto,
    confirmOrderDto,
    declineOrderDto,
}