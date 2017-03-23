const express   = require('express');
const router    = express.Router();
const passport  = require('passport');
const bcrypt    = require('bcrypt');
const User      = require('../models/user');

router.post('/signup',(req,res,next)=>{
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

module.exports = router;
