const mongoose = require('mongoose')

const Statistic = mongoose.model (
    'Statistic',
    new mongoose.Schema({
        createdAt: {type: Date,required: true},
        customer:{type:String,required: true},
        product: [
            {
                id: mongoose.Schema.Types.ObjectId,
                quantity: { type: Number, required: true }
            }
        ],
        totalAmount:{type:Number,required: true}
    },{ timestamps: true })
    .method('toClient', function() {
        var obj = this.toObject();
      
        return obj;
    })     
     
)


mongoose.Schema
module.exports = Statistic
