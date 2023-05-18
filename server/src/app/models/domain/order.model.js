const mongoose = require('mongoose')

const Order = mongoose.model(
    'Order',
    new mongoose.Schema({
        customerId: { type: String, required: true },
        status: { type: String, default: 'pending' },
        confirmByAdminId: { type: String, default: '' },
        confirmAt: { type: Date },
        declineReason: { type: String },
        totalAmount: { type: Number, required: true },
        products: [
            {
                productId: { type: String, required: true },
                name: { type: String, required: true },
                type: { type: String, required: true },
                price: { type: Number, required: true },
                quantity: { type: Number, required: true },
            }
        ],
        address: { type: String, required: true },
        note: { type: String, default: '' },
    }, { timestamps: true })
        .method('toClient', function () {
            var obj = this.toObject();
            //Rename fields
            obj.id = obj._id;
            delete obj._id;

            // obj.products = obj.products.map(p => {
            //     p.id = p._id;
            //     delete p._id;
            //     return p
            // })

            return obj;
        })
)

mongoose.Schema

module.exports = Order