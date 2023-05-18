
const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser')
const cors = require('cors')
const morgan = require('morgan')
const swaggerJsdoc = require('swagger-jsdoc')
const swaggerUI = require('swagger-ui-express')
const route = require('../routes')

module.exports = async (app) => {

    app.use(morgan('dev'));

    app.use(cors({
        origin: ['http://localhost:3000', 'http://localhost:3001'],
        credentials: true
    }))

    app.use(cookieParser())

    // parse requests of content-type - application/json
    app.use(bodyParser.json())

    // parse requests of content-type - application/x-www-form-urlencoded
    app.use(bodyParser.urlencoded({ extended: true }))

    app.get('/status', (req, res) => { res.status(200).end(); });
    app.head('/status', (req, res) => { res.status(200).end(); });
    app.enable('trust proxy');

    const options = {
        definition: {
            openapi: '3.0.0',
            info: {
                title: 'Shopping Web App',
                version: '1.0.0',
            },
        },
        apis: ['./src/app/routes/*.js'], // files containing annotations as above
    };

    const openapiSpecification = swaggerJsdoc(options);
    app.use('/swagger-ui', swaggerUI.serve, swaggerUI.setup(openapiSpecification))

    route(app)
}