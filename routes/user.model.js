const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
mongoose.connect("mongodb://localhost:27017/CodeSnippet")

const userSchema = new mongoose.Schema({
    userName:{
        type:String,
        required:true,
        unique:true,
        trim:true
    },
    email:{
        type:String,
        required:true,
        unique:true
    },
    password:{
        type:String,
        required:true
    },
    verified:{
        type:Boolean
    },
    snippets:[{
        type:mongoose.Schema.Types.ObjectId,
        ref:'Snippet'
    }],
    languages:[{
        type:String,
        unique:true
    }]
})


userSchema.pre('save', function(next){
    if(this.isModified('password')){
        try{
            var salt = bcrypt.genSaltSync(10)
            this.password = bcrypt.hashSync(this.password, salt)
            next()

        }
        catch (err){
            next(err)
        }

    }
    else{
        next();

    }
})

module.exports = mongoose.model('User', userSchema);
