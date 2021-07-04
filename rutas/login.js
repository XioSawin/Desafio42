const express = require('express');
const app = express();

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const router = express.Router();

const loginController = require('../controladores/loginController');

app.engine(
    "hbs", 
    handlebars({
        extname: ".hbs",
        defaultLayout: 'index.hbs',
    })
);

app.set("view engine", "hbs");
app.set("views", "./views");

app.use(express.static('public'));
app.use(passport.initialize());
app.use(passport.session());

/* ----------------------- SERIALIZE & DESERIALIZE ----------------------- */
passport.serializeUser(function(user, cb) {
    cb(null, user);
});

passport.deserializeUser(function(obj, cb) {
    cb(null, obj);
});

/* ----------------------- LOGIN ----------------------- */

/* -------------- local strategy -------------- */

passport.use('login', new LocalStrategy({
    passReqToCallback: true
    },
        loginController.loginUser(req, username, password, done)
    )
);

/* -------------- routes -------------- */

router.get('/login', loginController.LoginOk);

router.post('/login', passport.authenticate('login', { failureRedirect: '/faillogin'}), loginController.Redirect);

router.get('/faillogin', loginController.LoginFail);

router.get('/logout', loginController.Logout);


module.exports = router;


