const mongoose = require('mongoose')

const Notification = mongoose.model(
    'Notification',
    new mongoose.Schema({
        orderId: { type: String, required: true },
        for: { type: String, default: 'admin' },
        type: { type: String, default: 'order' },
        customer: {
            id: { type: String, required: true },
            name: { type: String, required: true },
        },
        seen: { type: Boolean, default: false },
    }, { timestamps: true })
        .method('toClient', function() {
            var obj = this.toObject();
            //Rename fields
            obj.id = obj._id;
            delete obj._id;
        
            return obj;
        })
)

mongoose.Schema

module.exports = Notification