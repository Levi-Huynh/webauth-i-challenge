const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs'); /// <<<<

const db = require('./database/dbConfig.js');
const Users = require('./users/user-model.js');
const protected= require('./auth/protected-mw.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
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
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
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

//--------------MIDDLEWARE 

//can always refactor middleware 

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
