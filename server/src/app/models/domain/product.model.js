const mongoose = require('mongoose')

const ProductModel = mongoose.model (
    'Product',
    new mongoose.Schema({
        name: {type: String,required: true},
        image:{type: [String],required: true},
        price:{type: Number,required: true},
        colors: {type: [String],required: true},
        remained: {type: Number,required: true},
        type: {type: String,required: true},
    },{timestamps: true})      
     .method('toClient', function() {
        var obj = this.toObject();
        //Rename fields
        obj.id = obj._id;
        delete obj._id;
    
        return obj;
    })
)


mongoose.Schema
module.exports = ProductModel
