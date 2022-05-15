require('dotenv').config();
var secret = process.env.SECRET;
var host = process.env.HOST;
var dbUser = process.env.DB_USER;
var dbPassword = process.env.DB_PASSWORD;
var dbName = process.env.DB_NAME;
var Client = require("pg").Client;
var mycrypto = require("node:crypto");
var passport = require("passport");
var LocalStrategy = require("passport-local");
var express = require("express");
var session = require('express-session');
var cors = require("cors");
var cookieParser = require("cookie-parser");
var uuidv4 = require("uuid").v4;
var app = express();
var port = 3002;
var cookieConfig = {
    sameSite: "None",
    secure: true,
    httpOnly: true
};
var sessionConfig = {
    secret: secret,
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
        maxAge: 1000 * 60 * 60 * 24 * 7,
        sameSite: "None",
        secure: true
    }
};
app.use(cors({
    origin: "http://127.0.0.1:3000",
    credentials: true,
    methods: ['GET', 'PUT', 'POST']
}));
app.use(express.json());
app.use(cookieParser(secret));
app.use(session(sessionConfig));
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser(function (user, done) {
    done(null, user);
});
passport.deserializeUser(function (user, done) {
    done(null, user);
});
var client = new Client({
    user: dbUser,
    host: host,
    database: dbName,
    password: dbPassword,
    port: 5432
});
client.connect();
var query = "\nDROP TABLE IF EXISTS users;\nCREATE TABLE users (\n    id SERIAL PRIMARY KEY NOT NULL UNIQUE,\n    email varchar(40) NOT NULL UNIQUE,\n    firstName varchar(40) NOT NULL,\n    lastName varchar(40) NOT NULL,\n    cart json NOT NULL DEFAULT '[]',\n    password TEXT NOT NULL,\n    salt TEXT NOT NULL,\n    isAdmin boolean NOT NULL DEFAULT false,\n    createdAt timestamp NOT NULL DEFAULT now(),\n    updatedAt timestamp NOT NULL DEFAULT now(),\n    deletedAt timestamp NULL,\n    deleted boolean NOT NULL DEFAULT false\n);\n";
var salt = mycrypto.randomBytes(16).toString("hex");
var hash = mycrypto
    .pbkdf2Sync("girts", salt, 310000, 32, "sha256")
    .toString("hex");
var query2 = "INSERT INTO users(email,firstname,lastname, password, salt)\nVALUES\n('girts521@gmail.com', 'girts', 'karcevskis', '".concat(hash, "', '").concat(salt, "');");
console.log('salt: ', salt.toString('hex'));
console.log('hash: ', hash.toString('hex'));
client.query(query, function (err, res) {
    if (err) {
        console.log(err.stack);
    }
    else {
        console.log('Table created');
    }
});
client.query(query2, function (err, res) {
    if (err) {
        console.log(err.stack);
    }
    else {
        console.log('user added');
    }
});
passport.use(new LocalStrategy(function verify(username, password, cb) {
    client.query("SELECT * FROM users WHERE email = '".concat(username, "'"), function (err, res) {
        if (err) {
            console.log(err.stack);
            console.log('there was an error');
        }
        else {
            console.log(res.rows[0]);
            mycrypto.pbkdf2(password, res.rows[0].salt, 310000, 32, "sha256", function (err, hashedPassword) {
                if (err) {
                    console.log(err.stack);
                }
                else {
                    console.log("password verified? maybe?");
                    if (hashedPassword.toString('hex') === res.rows[0].password) {
                        console.log("password really verified");
                        return cb(null, res.rows[0]);
                    }
                    else {
                        console.log("password not verified");
                        console.log(res.rows[0].password.toString('hex'));
                        console.log(hashedPassword);
                        return cb(null, false);
                    }
                }
            });
            // client.end();
        }
    });
}));
app.get("/", function (req, res) {
    res.send("Hello World");
});
app.get("/failed", function (req, res) {
    res.send("Failed");
});
app.post("/login", passport.authenticate("local", {
    failureMessage: true
}), function (req, res) {
    req.session.user = req.user;
    console.log(req.session);
    //send req.user to frontend
    res.sendStatus(200);
});
app.post('/test', function (req, res) {
    console.log('test');
    console.log(req.body);
});
app.get('/session', function (req, res) {
    console.log('session');
    console.log(req.session);
    res.cookie('session', req.session.id, cookieConfig);
    res.sendStatus(200);
    // res.cookie('name', 'girts')
});
app.listen(3002, function () {
    console.log("App listening on port ".concat(port));
});
