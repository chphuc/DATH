const { Joi, Segments } = require('celebrate')
    
const productDto = {
    [Segments.BODY]: Joi.object().keys({
        name: Joi.string().required(),
        image:Joi.string([]).required(),
        price:Joi.number().required(),
        colors:Joi.string().required(),
        remained:Joi.number().required(),
        type:Joi.string().required(),
    })
}

module.exports = {
    productDto
}
