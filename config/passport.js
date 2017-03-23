const LocalStrategy = require('passport-local').Strategy;
const bcrypt        = require('bcrypt');
const User          = require('../models/user');

module.exports = function( passport ){
  passport.use(new LocalStrategy((username, password, next) => {
    User.findOne({ username }, (err, foundUser) =>{
      if(err)  return next(err);

      if(!foundUser){//not found
        next(null, false, { message: 'Incorrect username' }); // login failed , we did not found any user
        return;
      }

      if (!bcrypt.comareSync(password, foundUser.password)){//compare the passwords
        next(null, false, { message: 'Incorrect password' }); // login failed , passwords did not match
        return;
      }

      next(null, foundUser);//Everything is good, log in

    });
  }));

  //Serialize -> what to save in session
  passport.serializeUser((loggedInUser, cb) => {
    cb(null, loggedInUser._id); //We save only id
  });

  //deSerialize -> get Everything back from DB by using id from session
  passport.deserializeUser((userIdFromSession, cb) => {
    User.findById(userIdFromSession, (err,userDocument)=>{
      if(err) return cb(err);

      cb(null, userDocument);
      //Here we can pull any variable that we need everywhere, in our case we pulling USER document
    });
  });

};
