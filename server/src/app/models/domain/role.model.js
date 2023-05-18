const mongoose = require('mongoose')

const Role = mongoose.model(
    'Role',
    new mongoose.Schema({
        name: String
    })
    .method('toClient', function() {
        var obj = this.toObject();
    
        //Rename fields
        obj.id = obj._id;
        delete obj._id;
    
        return obj;
    })
)

module.exports = Role