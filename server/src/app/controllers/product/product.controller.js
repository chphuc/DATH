const db = require('../../data')
const Product = db.product

class ProductController {
// [Get] /api/product/getAllProduct
    getAllProduct = (req,res) => {
        Product.find({}).exec((error,products) => {
            if(error){
                res.status(500).send({message:error})
                return
            }
            res.json(products.map(product => product.toClient()))
        })
    }
// [Get] /api/product/:id
    getById = (req,res,next) => {
        Product.findById(req.params.id)
            .then(product => res.json(product.toClient()))
            .catch(next)
    }
//  [POST] /api/product/createProduct
    createProduct = (req,res,next) => {
        const newProduct = new Product(req.body)
        newProduct.save()
            .then(product => res.json(product.toClient()))
            .catch(next)
            
    }
// [PUT] /api/product/:id
    updateProduct = (req,res,next) => {
        const id = req.params.id
        const {name,image,price,colors,remained,type} = req.body
        Product.findByIdAndUpdate(id,{name,image,price,colors,remained,type}) 
            .then(product => res.json(product.toClient()))
            .catch(next)
    }

// [DELETE] /api/product/:id
    deleteProduct = (req,res,next) => {
        const id = req.params.id
        Product.findByIdAndRemove(id) 
            .then(product => res.json(product.toClient()))
            .catch(next)

    }
}

module.exports = new ProductController
