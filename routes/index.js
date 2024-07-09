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


router.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Email must be a valid email address.' });
  }

  const existingUser = await userSchema.findOne({ email: email, verified: true });
  if (existingUser) {
    return res.status(400).json({ error: 'User already exists.' });
  }
  const existingUserNotVerified = await userSchema.findOne({ email: email, verified: false });
  console.log(existingUserNotVerified)

  if (existingUserNotVerified) {
    console.log(existingUserNotVerified)
    await userVerification.deleteMany({ userId: existingUserNotVerified._id });
    sentOtpforVerification(existingUserNotVerified, res);
  } else {
    const newUser = new userSchema({
      userName: username,
      email: email,
      password: password,
      verified: false
    });
    newUser.save()
      .then((result) => {
        console.log("Account created")
        sentOtpforVerification(result, res);
      });
  }
});

    

    

  router.post('/login', async (req, res) => {
    const { email, password } = req.body;
  
    const user = await userSchema.findOne({ email: email });
    if (!user) {
      return res.json({ error: "No such user exists" });
    }
  
    if (!user.verified) {
      sentOtpforVerification(user, res);
    } else {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.json({ error: "Password is incorrect" });
      } else {
        const token = jwt.sign({ userId: user._id, verified: true }, process.env.JWT_SECRET, { expiresIn: '10d' });
        return res.json({ token: token });
      }
    }
  });
    
router.post('/verifyOtp',async(req,res)=>{
  // const token = req.cookies.token
  const authHeader = req.headers['authorization'];
  console.log(authHeader)
  const token = authHeader && authHeader.split(' ')[1];
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

  const newToken = jwt.sign({ userId: userId, verified: true }, process.env.JWT_SECRET, {expiresIn:'10d'});
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

router.post('/forgotPassword',async(req,res)=>{
  const email = req.body.email
  if(!email){
    return res.status(400).json({error:"Email is required"})
  }
  const user = await userSchema.findOne({email : email})
  if(!user){
    return res.status(400).json({error:"User not found"})
  }
  const otp = Math.floor(100000 + Math.random() * 900000);
  const userVerification = new UserVerification({
    userId : user._id,
    otp : otp,
    createdAt:Date.now(),
    expiresAt : Date.now() + 360000
  })
  await userVerification.save()
  
  const mailOptions = {
    from: process.env.USER,
    to: email,
    subject: "Verify your Email",
    html: `<p>Enter <b>${otp}</b> in the app to verify your email address and reset your password</p>
          <p>This code expires in 1 hour</p>.`
  }
  await transporter.sendMail(mailOptions)
res.json({message:"Email sent successfully"})
})
router.post('/resetPassword',async(req,res)=>{
  const email = req.body.email
  const newPassword = req.body.newPassword
  const otp = req.body.otp

  if(!email || !newPassword || !otp){
    return res.status(400)
  }
  const user = await userSchema.findOne({email : email})
  if(!user){
    return res.status(400).json({error:"User not found"})
  }
  const userVerification = await UserVerification.findOne({userId : user._id, otp : otp})
  if(!userVerification){
    return res.status(400).json({error:"Invalid OTP"})
  }
  if(userVerification.expiresAt < Date.now()){
    return res.status(400).json({error:"OTP expired"})
  }

  user.password = newPassword;
  await user.save()
  await userVerification.remove()
  return res.sendStatus(200);

})

router.post('/addSnippet',async(req,res)=>{
  // const token = req.cookies.token
  const authHeader = req.headers['authorization'];
  console.log(authHeader)
  const token = authHeader && authHeader.split(' ')[1];

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
  // const token = req.cookies.token;
  const authHeader = req.headers['authorization'];
  console.log(authHeader)
  const token = authHeader && authHeader.split(' ')[1];
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
  // const token = req.cookies.token
  const authHeader = req.headers['authorization'];
  console.log(authHeader)
  const token = authHeader && authHeader.split(' ')[1];
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
  // const token = req.cookies.token
  const authHeader = req.headers['authorization'];
  console.log(authHeader)
  const token = authHeader && authHeader.split(' ')[1];
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
  // const token = req.cookies.token
  const authHeader = req.headers['authorization'];
  console.log(authHeader)
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Token missing' });
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const userId = decoded.userId;

  const user = await userSchema.findById(userId).populate('snippets')
  res.json(user.snippets)

})
router.post("/snippetDets",async(req,res)=>{
  const {snippetId} = req.body
  const snippet = await SnippetSchema.findOne({_id : snippetId})
  if(snippet){
    console.log(snippet)
    res.json(snippet)
  }
  else{
    res.json(404)
  }
})

router.post('/checkState',async(req, res)=>{
  // const token = req.cookies.token
  const authHeader = req.headers['authorization'];
  console.log(authHeader)
  const token = authHeader && authHeader.split(' ')[1];
  console.log("token recieved",token)
  if (!token) {
    console.log("not found")
    res.sendStatus(402)
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("decoding")
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
  // const token = req.cookies.token
  const authHeader = req.headers['authorization'];
  console.log(authHeader)
  const token = authHeader && authHeader.split(' ')[1];
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

const sentOtpforVerification = async({_id, email}, res) => {
  const otp = Math.floor(100000 + Math.random() * 900000);

  const mailOptions = {
    from: process.env.USER,
    to: email,
    subject: "Verify your Email",
    html: `<p>Enter <b>${otp}</b> in the app to verify your email address and complete your registration</p>
          <p>This code expires in 1 hour</p>.`
  }
  const saltrounds = 10
  const userVerificationOtp = await new userVerification({
    userId: _id,
    otp: otp,
    createdAt: Date.now(),
    expiresAt: Date.now() + 3600000
  })
  await userVerificationOtp.save()
  const mail = await transporter.sendMail(mailOptions)
  console.log(mail)
  const token = jwt.sign({ userId: _id, verified: false }, process.env.JWT_SECRET, { expiresIn: '2h' });
  console.log("sending token", token)
  res.json({
    message: "Email sent",
    data: {
      token: token
    }
  }); // Ensure this is the only response sent
}



//middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  console.log(authHeader)
  const token = authHeader && authHeader.split(' ')[1];
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
