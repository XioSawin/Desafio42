const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const compression = require('compression');
const log4js = require('log4js');
const config = require('./config');
const args = require('yargs').argv;

const app = express();
app.use(compression());

const login = require('./rutas/login');
const register = require('./rutas/register');
const productos = require('./rutas/productos');

app.use('/', login);
app.use('/user', register);
app.use('/producto', productos);

/* -------------- Datos por CL -------------- */

const portCL = args.port|| 8080;


/* -------------- PASSPORT -------------- */
const passport = require('passport');


/* -------------- LOGGERS -------------- */
log4js.configure({
    appenders: {
        miLoggerConsole: {type: "console"},
        miLoggerFileWarning: {type: 'file', filename: 'warn.log'},
        miLoggerFileError: {type: 'file', filename: 'error.log'}
    },
    categories: {
        default: {appenders: ["miLoggerConsole"], level:"trace"},
        info: {appenders: ["miLoggerConsole"], level: "info"},
        warn: {appenders:["miLoggerFileWarning"], level: "warn"},
        error: {appenders: ["miLoggerFileError"], level: "error"}
    }
});

const loggerInfo = log4js.getLogger('info');
const loggerWarn = log4js.getLogger('warn');
const loggerError = log4js.getLogger('error');

/* -------------------------------------------- */

/* -------------- serialize + deserialize -------------- */
passport.serializeUser(function(user, cb) {
    cb(null, user);
});

passport.deserializeUser(function(obj, cb) {
    cb(null, obj);
});

/* ------------------------------------ */
/* CONFIG */
app.use(express.json());
app.use(express.urlencoded({extended:true}));

app.use(cookieParser());
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        maxAge: 60000
    }
}));


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

   
/* -------------- DB CONNECTION -------------- */

app.listen( process.env.PORT|| portCL, ()=>{
    loggerInfo.info(`Servidor express en modo ${config.NODE_ENV}`);
    loggerInfo.info(`Server running on PORT ${portCL}`);
})

