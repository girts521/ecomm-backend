require('dotenv').config();
const secret = process.env.SECRET;
const host = process.env.HOST;
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASSWORD;
const dbName = process.env.DB_NAME;

const { Client } = require("pg");
const mycrypto = require("node:crypto");

const passport = require("passport");
const LocalStrategy = require("passport-local");

const express = require("express");
const  session = require('express-session')
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");

const app = express();
const port = 3002;

const cookieConfig = {
  sameSite: "None",
  secure: true,
  httpOnly: true
};

const sessionConfig = {
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
}

app.use(
  cors({
    origin: "http://127.0.0.1:3000",
    credentials: true,
    methods: ['GET', 'PUT', 'POST'],
  })
);
app.use(express.json());
app.use(cookieParser(secret));
app.use(session(sessionConfig))

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function(user:any, done:any) {
  done(null, user);
});

passport.deserializeUser(function(user:any, done:any) {
  done(null, user);
});

const client = new Client({
  user: dbUser,
  host: host,
  database: dbName,
  password: dbPassword,
  port: 5432,
});

client.connect();

const query = `
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id SERIAL PRIMARY KEY NOT NULL UNIQUE,
    email varchar(40) NOT NULL UNIQUE,
    firstName varchar(40) NOT NULL,
    lastName varchar(40) NOT NULL,
    cart json NOT NULL DEFAULT '[]',
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    isAdmin boolean NOT NULL DEFAULT false,
    createdAt timestamp NOT NULL DEFAULT now(),
    updatedAt timestamp NOT NULL DEFAULT now(),
    deletedAt timestamp NULL,
    deleted boolean NOT NULL DEFAULT false
);
`;

var salt = mycrypto.randomBytes(16).toString("hex");
var hash = mycrypto
  .pbkdf2Sync("girts", salt, 310000, 32, "sha256")
  .toString("hex");

const query2 = `INSERT INTO users(email,firstname,lastname, password, salt)
VALUES
('girts521@gmail.com', 'girts', 'karcevskis', '${hash}', '${salt}');`;

console.log('salt: ', salt.toString('hex'));
console.log('hash: ', hash.toString('hex'));

client.query(query, (err:any, res:any) => {

    if (err) {
      console.log(err.stack)
    } else {
      console.log('Table created')
    }
  })

  client.query(query2, (err:any, res:any) => {

    if (err) {
      console.log(err.stack)
    } else {
      console.log('user added')
    }

  })

passport.use(
  new LocalStrategy(function verify(username: any, password: any, cb: any) {
    client.query(
      `SELECT * FROM users WHERE email = '${username}'`,
      (err: any, res: any) => {
        if (err) {
          console.log(err.stack);
          console.log('there was an error')
        } else {
          console.log(res.rows[0]);

          mycrypto.pbkdf2(
            password,
            res.rows[0].salt,
            310000,
            32,
            "sha256",
            function (err: any, hashedPassword: any) {
              if (err) {
                console.log(err.stack);
              } else {
                console.log("password verified? maybe?");
                if (hashedPassword.toString('hex') === res.rows[0].password) {
                  console.log("password really verified");
                  return cb(null, res.rows[0]);
                } else {
                  console.log("password not verified");
                  console.log(res.rows[0].password.toString('hex'));
                  console.log(hashedPassword)
                  return cb(null, false);
                }
              }
            }
          );
          // client.end();
        }
      }
    );
  })
);

app.get("/", (req: any, res: any) => {
  res.send("Hello World");
});

app.get("/failed", (req: any, res: any) => {
  res.send("Failed");
});

app.post(
  "/login",
  passport.authenticate("local", {
    failureMessage: true 
  }),(req: any, res: any) => {
    req.session.user = req.user;

    console.log(req.session)
    //send req.user to frontend
    res.sendStatus(200);
  }
);

app.post('/test', (req: any, res: any) => {
  console.log('test');
  console.log(req.body)
  
})

app.get('/session', (req: any, res: any) => {
  console.log('session');
  console.log(req.session)
  res.cookie('session', req.session.id, cookieConfig);
  res.sendStatus(200);
  // res.cookie('name', 'girts')
})


app.listen(3002, () => {
  console.log(`App listening on port ${port}`);
});
