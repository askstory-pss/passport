const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const flash = require('express-flash');
const bcrypt = require('bcrypt');
const config = require('./config');

const dbConfig = config.database;

const app = express();

// Initialize session middleware
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));

app.use(flash());

// Initialize Passport and session middleware
app.use(passport.initialize());
app.use(passport.session());

app.set('view engine', 'ejs');

// Database connection
const mysql = require('mysql2');
const db = mysql.createConnection({
  host: dbConfig.host,
  port: dbConfig.port,
  user: dbConfig.user,
  password: dbConfig.password,
  database: dbConfig.database,
});

db.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL database');
});

// Express app configuration
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.listen(3003, () => {
  console.log('Server is running on port 3003');
});

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.query('SELECT * FROM users WHERE id = ?', [id], (err, rows) => {
    done(err, rows[0]);
  });
});

passport.use(new LocalStrategy((email, password, done) => {
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, rows) => {
    if (err) return done(err);
    if (!rows.length) return done(null, false, { message: 'Incorrect email.' });
    
    const user = rows[0];
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) return done(err);
      if (!result) return done(null, false, { message: 'Incorrect password.' });
      
      return done(null, user);
    });
  });
}));

// Sign-up
app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', (req, res) => {
  let { username, email, employeeNum, password, phoneNum} = req.body;
  if(phoneNum === "") phoneNum = null;
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) throw err;
    
    db.query('INSERT INTO users (username, email, employeeNum, password, phoneNum) VALUES (?, ?, ?, ?, ?)', [username, email, employeeNum, hashedPassword, phoneNum], (err, result) => {
      if (err) throw err;
      res.redirect('/login');
    });
  });
});

// Log-in
app.get('/login', (req, res) => {
  res.render('index');
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login',
  failureFlash: true
}));

// Log-out
app.get('/logout', (req, res) => {
  req.logout();
  req.flash('success', 'Logged out successfully');
  res.redirect('/');
});

function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

app.get('/dashboard', isAuthenticated, (req, res) => {
  res.send('Welcome to the dashboard!');
});

app.post('/checkDuplicates', async (req, res) => {
  const email = req.body.email;
  const employeeNum = req.body.employeeNum;

  if(email !== undefined){
    try {
      const isDuplicate = await checkForDuplicate(email, 'email');
      const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
      res.json({ isDuplicate: isDuplicate, emailRegex : emailRegex.test(email) });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred' });
    }
  }else if(employeeNum !== undefined){
    try {
      const isDuplicate = await checkForDuplicate(employeeNum, 'employeeNum');
      const isNumeric = /^\d+$/.test(employeeNum);
      res.json({ isDuplicate: isDuplicate, isNumeric : isNumeric });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred' });
    }
  }  
});


async function checkForDuplicate(itemValue, item) {
  return new Promise((resolve, reject) => {
    db.query(`SELECT * FROM users WHERE ${item} = ?`, [itemValue], (err, rows) => {
      if (err) {
        reject(err);
      } else {
        if (rows.length > 0) {
          resolve(true);
        } else {
          resolve(false);
        }
      }
    });
  });
}