const express   = require('express');
const router    = express.Router();
const passport  = require('passport');
const bcrypt    = require('bcrypt');
const User      = require('../models/user');

router.post('/signup', (req,res,next)=>{
  const username = req.body.username;
  const password = req.body.password;
  const nickname = req.body.nickname;

  if(!username || !password){
    res.status(400).json({ message: 'Provide username and password.'});
    return;
  }

  //'_id' === { id: 1}
  User.findOne({ username }, '_id', (err, foundUser) => {
    if(err) return res.status(500).json({ message: 'Something went wrong.'});

    if (foundUser){
      res.status(400).json({ message: 'The username already exists.'});
    }

    const salt     = bcrypt.genSaltSync(10);
    const hashPass = bcrypt.hashSync(password, salt);

    const theUser = new User({
      username,//username: username
      nickname, //nickname: nickname
      password: hashPass

    });

    theUser.save( err =>{
      if(err) return res.status(400).json({ message: 'Something went wrong.'});

      req.login(theUser, (err)=>{ //login right away after signup with passport login method
        if(err) return res.status(400).json({ message: 'Something went wrong.'});

        res.status(200).json(req.user);//req.user is defined because we logged in
      });
    });
  });
});

router.post('/login', (req,res,next)=>{
  const passportFunction = passport.authenticate('local', (err,theUser, failureDetails) => {

    if(err) return res.status(500).json({ message: 'Something went wrong.'});

    if(!theUser) return res.status(401).json(failureDetails);

    req.login(theUser, (err)=>{ //LOGIN
        if(err) return res.status(500).json({ message: 'Something went wrong.'});

        res.status(200).json(req.user);
    });

  });

  passportFunction(req,res,next);//call f right after we defined it
});

router.post('/logout', (req,res,next)=>{
  req.logout();
  res.status(200).json({ message: 'Success'});
});

router.get('/loggedin', (req,res,next)=>{

  if (req.isAuthenticated()) {
    res.status(200).json(req.user); //The user logged in -> send user info to client
    return;
  }

  //User is not logged in
  res.status(401).json({ message: 'Unauthorized.'});
});

function ensureLoggedIn( req, res, next){
  if(!req.isAuthenticated()){
    res.status(403).json({ message: 'FORBIDDEN.'});//Accessing page that requires logging in, and you not logged in
    return;
  }
  next();
}
router.get('/private', ensureLoggedIn, (req,res,next)=>{
  res.json({ message: 'You are lucky'});//you goood to go
});

module.exports = router;
