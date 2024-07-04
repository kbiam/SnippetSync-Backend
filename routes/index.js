var express = require('express');
var router = express.Router();
const bcrypt = require('bcrypt')
const nodemailer= require('nodemailer')
const userSchema = require('./user.model')
const userVerification = require('./userVerification.model')
const jwt = require('jsonwebtoken');
const UserVerification = require('./userVerification.model');
const SnippetSchema = require('./snippet.model');
const res = require('express/lib/response');
require('dotenv').config()

//nodemailer
const transporter = nodemailer.createTransport({
  service:"gmail",
  host: "smtp.gmail.com",
  port: 587,
  secure: false, // Use `true` for port 465, `false` for all other ports
  auth: {
    user: process.env.USER,
    pass: process.env.PASS,
  },
});

/* GET home page. */


router.post('/register',async(req,res)=>{
  const username = req.body.username
  const password = req.body.password
  const email = req.body.email
    // Validate username
    // if (!username) {
    //   return res.status(400).json({ error: 'Username is required.' });
    // }
    // if (username.length < 3 || username.length > 20) {
    //   return res.status(400).json({ error: 'Username must be between 3 and 20 characters long.' });
    // }
    // if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    //   return res.status(400).json({ error: 'Username must contain only letters, numbers, and underscores.' });
    // }
  
    // // Validate password
    // if (!password) {
    //   return res.status(400).json({ error: 'Password is required.' });
    // }
    // if (password.length < 8) {
    //   return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    // }
    // if (!/\d/.test(password)) {
    //   return res.status(400).json({ error: 'Password must contain at least one number.' });
    // }
    // if (!/[a-z]/.test(password)) {
    //   return res.status(400).json({ error: 'Password must contain at least one lowercase letter.' });
    // }
    // if (!/[A-Z]/.test(password)) {
    //   return res.status(400).json({ error: 'Password must contain at least one uppercase letter.' });
    // }
    // if (!/[@$!%*?&]/.test(password)) {
    //   return res.status(400).json({ error: 'Password must contain at least one special character.' });
    // }
  
    // Validate email
    if (!email) {
      return res.status(400).json({ error: 'Email is required.' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Email must be a valid email address.' });
    }

    const existingUser = await userSchema.findOne({ email: email, verified: true});
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists.' });
    }
    const existingUserNotVerified = await userSchema.findOne({ email: email, verified: false});
    console.log(existingUserNotVerified)

    if(existingUserNotVerified){
      console.log(existingUserNotVerified)
      await userVerification.deleteMany({userId:existingUserNotVerified._id})
      sentOtpforVerification(existingUserNotVerified,res)
    }
    else{
      const newUser = new userSchema({
        userName:username,
        email:email,
        password:password,
        verified:false
      })
      newUser.save()
      .then((result) => {console.log("Account created")
        sentOtpforVerification(result,res)})
    }
  })
    

    

router.post('/login',async (req,res)=>{
  const email = req.body.email
  const password = req.body.password

  const user = await userSchema.findOne({email:email})
  if (!user) {
    return res.json({error:"No such user exists"});
  }

  if(!user.verified){
    sentOtpforVerification(user,res)

  }
  //bcrypt 
  const isMatch = await bcrypt.compare(password, user.password)
  if (!isMatch) {
      return res.json({error:"Password is incorrect"});
  }
  else{
    const token = jwt.sign({ userId: user._id, verified: true }, process.env.JWT_SECRET, {expiresIn:'5d'});
    return res.json({token:token})
  }
})
router.post('/verifyOtp',async(req,res)=>{
  const token = req.cookies.token

  const otp = req.body.otp
  if(!otp){
    return res.status(400).json({error:"Otp is required"})
  }

  const decoded = jwt.verify(token,process.env.JWT_SECRET)
  const {userId} = decoded

  const userVerificationOtp = await UserVerification.findOne({userId : userId ,otp : otp})
  console.log(userVerificationOtp)
  if(!userVerificationOtp){
    return res.status(400).json({error:"Invalid Otp"})
  }
  if (userVerificationOtp.expiresAt < Date.now()) {
    return res.status(400).json({ error: 'OTP has expired.' });
  }
  await userVerification.deleteOne({ userId });

  await userSchema.updateOne({_id:userId},{verified:true})

  const newToken = jwt.sign({ userId: userId, verified: true }, process.env.JWT_SECRET, {expiresIn:'5d'});
  if(newToken){
    res.json({
      message: 'Email verified successfully.',
      token: newToken // Return a new token with updated emailVerified status
    });
  }
  else{
    res.json({
      error: 'Failed to verify email.'
    })
  }


})
router.post('/addSnippet',async(req,res)=>{
  const token = req.cookies.token

  if (!token) {
    return res.status(401).json({ error: 'Token missing' });
  }
  
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const userId = decoded.userId;

  const {title, snippet, language, description}= req.body
  const newSnippet = new SnippetSchema({
    userId:userId,
    title:title,
    description:description,
    snippet:snippet,
    language:language
  })
  await newSnippet.save()

  const user = await userSchema.findById(userId)
  user.snippets.push(newSnippet._id)
  if(!user.languages.includes(language)){
    user.languages.push(language)
  }
  await user.save()
  return res.sendStatus(200)

  

})
router.post("/deleteSnippet", async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: 'Token missing' });
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const userId = decoded.userId;
  const { id } = req.body;

  try {
    // Find the snippet to get its language
    const snippet = await SnippetSchema.findById(id);
    if (!snippet) {
      return res.status(404).json({ error: 'Snippet not found' });
    }
    const snippetLanguage = snippet.language;

    // Remove the snippet from the user's snippets array
    const user = await userSchema.findById(userId);
    user.snippets.pull(id);

    // Check if any other snippet has the same language
    const snippetsArray = await SnippetSchema.find({ _id: { $in: user.snippets } });
    const isLanguageUsed = snippetsArray.some(snippet => snippet.language === snippetLanguage);

    if (!isLanguageUsed) {
      user.languages.pull(snippetLanguage);
    }

    await user.save();
    await SnippetSchema.deleteOne({ _id: id });

    res.sendStatus(200);
  } catch (error) {
    console.error('Error deleting snippet:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


router.post("/updateSnippet",async(req, res)=>{
  const token = req.cookies.token
  if (!token) {
    return res.status(401).json({ error: 'Token missing' });
  }
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const userId = decoded.userId;
  const {snippetId,newSnippet}= req.body
  try{
  const snippet = await SnippetSchema.findOne(snippetId)
  snippet.snippet = newSnippet
  await snippet.save()
  return res.sendStatus(200)
  }
  catch(error){
    return res.sendStatus(400)
  }


})

router.get("/userLanguages",async(req,res)=>{
  const token = req.cookies.token
  if (!token) {
    return res.status(401).json({ error: 'Token missing' });
  }
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const userId = decoded.userId;
  const user = await userSchema.findById(userId)
  const languages = user.languages
  res.json(languages)
})

router.post("/snippets", async(req,res)=>{
  const token = req.cookies.token
  if (!token) {
    return res.status(401).json({ error: 'Token missing' });
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const userId = decoded.userId;

  const user = await userSchema.findById(userId).populate('snippets')
  res.json(user.snippets)

})

router.post('/checkState',async(req, res)=>{
  const token = req.cookies.token
  
  if (!token) {
    res.sendStatus(404)
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if token is expired
    if (Date.now() >= decoded.exp * 1000) {
      // Token is expired
      return res.status(401).json({ message: 'Token expired' });
    }

    // Token is valid, check verification status
    if (!decoded.verified) {
      return res.status(200).json({ isVerified: false });
    } else {
      return res.status(200).json({ isVerified: true });
    }
  } catch (error) {
    // Handle JWT verification errors
    console.error('JWT verification error:', error);
    return res.status(401).json({ message: 'Please Login Again' });
  }
})


router.post("/startAgain",async (req,res)=>{
  const token = req.cookies.token
  if (!token) {
    res.sendStatus(404)
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;
    await userSchema.deleteOne({_id:userId})
    await UserVerification.deleteMany({userId:userId})
    res.sendStatus(200)
  } 
  catch(error){
    return res.status(500).json({ message: 'Internal server error' });

  }

})

//otp

const sentOtpforVerification = async({_id,email},res)=>{
  const otp = Math.floor(100000 + Math.random() * 900000);

  const mailOptions = {
    from: process.env.USER,
    to: email,
    subject:"Verify your Email",
    html:`<p>Enter <b>${otp}</b> in the app to verify your email address and complete your registration</p>
          <p>This code expires in 1 hour</p>.`
  }
  const saltrounds = 10
  // const hashedOtp = await bcrypt.hash(otp,saltrounds)
  const userVerificationOtp = await new userVerification({
    userId:_id,
    otp:otp,
    createdAt:Date.now(),
    expiresAt:Date.now() + 3600000
  })
  await userVerificationOtp.save()
  const mail = await transporter.sendMail(mailOptions)
  console.log(mail)
  const token = jwt.sign({ userId: _id, verified: false }, process.env.JWT_SECRET, { expiresIn: '2h' });
  if(token){
    res.json({
      message:"Email sent",
      data:{
        token:token
      }
    })
  }

}


//middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  console.log(authHeader)
  const token = authHeader && authHeader.split(' ')[1];
  // const token = token;

  if (!token) {
    return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403); // Forbidden
    }
    if(user.verified){
      next();
    }
    
  });
};



module.exports = router;
