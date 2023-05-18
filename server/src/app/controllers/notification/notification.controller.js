const db = require('../../data')
const Notification = db.notification

class NotificationController {
    // [Get] /api/notification/getAllNotifications
    getAllNotifications = (req, res) => {
        Notification.find({ for: 'admin' }, {}, { sort: { 'createdAt': -1 } }).exec((err, notifications) => {
            if (err) {
                res.status(500).send({ message: err })
                return
            }

            res.json(notifications.map(notification => notification.toClient()))
        })
    }
}

module.exports = new NotificationController