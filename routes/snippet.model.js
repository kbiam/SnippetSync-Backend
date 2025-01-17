const mongoose = require('mongoose')
mongoose.connect("mongodb+srv://kushbang123:El3qAGsZPa2gJqGC@cluster0.719zpms.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")


const snippetSchema = new mongoose.Schema({
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    title: {
      type: String,
      required: true
    },
    description:{
      type:String,
      required:true
    },
    snippet: {
      type: String,
      required: true
    },
    language: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    updatedAt: {
      type: Date,
      default: Date.now
    }
  });
  
  // Create a pre-save hook to update the updatedAt field
  snippetSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
  });
  
  // Export the Snippet model
  const Snippet = mongoose.model('Snippet', snippetSchema);
  
  module.exports = Snippet;