const mongoose = require('mongoose')

const User = mongoose.model(
    'User',
    new mongoose.Schema({
        username: String,
        email: String,
        password: String,
        role: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Role',
        }
    })
    .method('toClient', function() {
        var obj = this.toObject();
    
        //Rename fields
        obj.id = obj._id;
        delete obj._id;
    
        return obj;
    })
)

module.exports = User