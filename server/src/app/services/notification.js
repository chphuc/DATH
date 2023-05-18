const db = require('../data')
const Notification = db.notification
const User = db.user

const addNewNotification = (data) => {
    User.findById(data.customerId).exec((err, customer) => {
        if (err) {
            console.log('addNewNotification - Find Customer Error: ', err)
            return
        }

        const notification = new Notification({
            orderId: data.id,
            customer: {
                id: data.customerId,
                name: customer.username
            }
        })

        notification.save((err, notification) => {
            console.log('addNewNotification - Save Notification Error: ', err)
        })
    })
} 

module.exports = {
    addNewNotification
}