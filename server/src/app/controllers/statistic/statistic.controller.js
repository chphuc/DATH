const db = require('../../data')
const Order=db.order
const Product = db.product

class StatisticController {
// [Get ]

getOrderToday = (req, res) => {
    Order.find({}).exec((err, orders) => {
        if (err) {
            res.status(500).send({ message: err })
            return
        }

        res.json(orders.map(order => order.toClient()))
    })
}
// getProductId = (req,res,next) => {
//     Product.findById(req.params.id)
//         .then(product => res.json(product.toClient()))
//         .catch(next)
// }
getProductId = (req, res) => {
    Product.find({}).exec((err, orders) => {
        if (err) {
            res.status(500).send({ message: err })
            return
        }

        res.json(orders.map(order => order.toClient()))
    })
}


}

module.exports = new StatisticController
