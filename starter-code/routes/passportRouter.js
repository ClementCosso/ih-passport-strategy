const express        = require("express");
const passport        = require("passport");
const passportRouter = express.Router();
// Require user model
const User = require('../models/user');

// Add bcrypt to encrypt passwords
const bcrypt         = require("bcryptjs");
const bcryptSalt     = 10;

// Add passport 


const ensureLogin = require("connect-ensure-login");

let isAdmin = (req, res, next) => {
  if (req.session.currentUser.role.include('admin')) {
    next();
  } else {
    res.redirect("/login");
  }
}


passportRouter.get('/signup', (req, res, next) => {
  res.render('passport/signup');
});

passportRouter.post('/signup', (req, res, next) => {
  let {username, password} = req.body
  
  const salt     = bcrypt.genSaltSync(bcryptSalt);
  const hashPass = bcrypt.hashSync(password, salt);

  let user = new User({username, password: hashPass})
  user.save()
  .then(usr => {
    res.redirect('/');
  })
  .catch(err => {
    next(err)
  })
});


passportRouter.get('/login', (req, res, next) => {
  res.render('passport/login');
});

passportRouter.post('/login', 
  passport.authenticate('local', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });



passportRouter.get('/auth/google',
  passport.authenticate('google', { scope: 
      [ 'https://www.googleapis.com/auth/plus.login',
      , 'https://www.googleapis.com/auth/plus.profile.emails.read' ] }
));

passportRouter.get( '/auth/google/callback', 
    passport.authenticate( 'google', { 
        successRedirect: '/',
        failureRedirect: '/login'
}));
passportRouter.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("passport/private", { user: req.user });
});

module.exports = passportRouter;