const notificationService = require('../services/notification')

module.exports = (io) => {
    io.on('connection', (socket) => {
        console.log('A user conntected.')

        socket.on('newOrder', () => {
            console.log('Socket: New Oder')
            socket.broadcast.emit('newOrder')
        })

        socket.on('updateOrder', () => {
            console.log('Socket: update Oder')
            socket.broadcast.emit('updateOrder')
        })
    })
}