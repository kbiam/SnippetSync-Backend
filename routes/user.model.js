const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
// mongoose.connect("mongodb://localhost:27017/CodeSnippet")
// mongoose.connect("mongodb+srv://kushbang123:<password>@cluster0.719zpms.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")

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
