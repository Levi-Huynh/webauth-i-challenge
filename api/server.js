const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs'); /// <<<<
const session = require('express-session');

const db = require('../database/dbConfig.js');
const Users = require('../users/user-model.js');
const protected= require('../auth/protected-mw.js');
const authRouter = require('../auth/auth-router.js');

const server = express();
const sessionConfig = {
    name: 'monster', //by default would be sid
    secret: 'keep it a secret, keep it safe!- gandalf', //encrypt not infallable adds a layer of security
   cookie: {
     httpOnly: true, //true means prevent access from JavaScript code, including node modules?
     maxAge: 1000 * 60 * 1, //in milliseconds here is one moine 1000*6 *6 *24 is 24 hours
     secure: false, //true means only send the cookie over https (every app that goes to production should be running over)
     //https. channel of info is protected.  THis is for dev only so dont do this now.  When in production
     //true when running production. Make this dynamiclly change for production by using processdotenv 
   },
   resave:false, //resave session even if it didn't change?
   saveUninitialized: true, //create new sessions automatically, make sure to comply with law
   
   //* saveUninitialized: for complying with laws that require permission before setting a cookie
   //dont keep ^ true willynilly on Client -have pop up that asks if its ok by user to use cookies = true, otherwise
   //flag false
  }

  server.use(session(sessionConfig));
server.use(helmet());
server.use(express.json());
server.use(cors());

server.use('/api/auth', authRouter);

server.get('/', (req, res) => {
    const username = req.session.username || 'stranger';
  res.send(`Hello ${username}!`);
});

server.post('/api/register', (req, res) => {
  let user = req.body;
  //check for username & password

  const hash = bcrypt.hashSync(user.password, 10); // 2^10 rounds

  //^when increase rounds 14 (which is 2^14 ) will run significantly seconds longer


//What is Round?
//takes pw> Hashes(function) > hash > hashes > hash >hashes >has
//^rehashes the hashed previous value 
  //hash password
  //salt is added when posting to api/register (even when using same pw), a new pw generated for each post b/c of 
  //salt
  user.password= hash; //<<<

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  //we compare the pw guess against the database hash

  Users.findBy({ username })
    .first()
    .then(user => {
      // can compare here b/c need access to database hash

      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.username = user.username;
        res.status(200).json({ message: `Welcome ${user.username}, have a cookie!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials, You shall not pass' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

//protect this route, users must provide valid username/passwprd to see the list of users
server.get('/api/users', protected, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});


server.get('/api/restricted', protected, (req, res) => {
    Users.find()
      .then(users => {
        res.json(users);
      })
      .catch(err => res.send(err));
  });

  server.get('/logout', (req, res )=> {
    if (req.session) {
      req.session.destroy(err => {
        if(err) {
          res.send('error signing out');
        } else {
          res.send('bye');
        }
      });
    }else{
      res.send('already logged out');
    }
    
    });

  module.exports = server;