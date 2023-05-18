const expressLoader = require('./express')
const mongooseLoader = require('./mongoose')
const socketLoader = require('./socket')
const db = require('../data')

module.exports = async (app, io) => {
    await mongooseLoader(db)
    console.log('MongoDB Initialized')

    await expressLoader(app)
    console.log('Express Initialized')

    socketLoader(io)
    console.log('Socket Initialized')

    // more loaders here
}
