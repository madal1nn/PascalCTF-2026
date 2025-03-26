const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();
const SERVER_PORT = process.env.PORT || 5005;

// Import headless functionalities
const {performHealthCheck} = require('./headless.js')

// Import user and auth functionalities
const {createUser, SECRET} = require('./user.js')

// Import cache functionalities
const {addResultsToCache, getResultsFromCache} = require('./cache.js');

const app = express();

// template engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'templates'));

// Middleware setup
app.use(express.static(path.join(__dirname, ''))); // If something works, why change it?
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Auth system
function auth(req, res, next){
  const sessionCookie = req.cookies.session;
  if (!sessionCookie) {
    return res.redirect('/');
  }

  try{
    const payload = jwt.verify(sessionCookie, SECRET);
    req.user = payload.id;
  } catch (err) {
    res.clearCookie('session');
    return res.redirect('/');
  }

  next();
}

// Routes
app.get('/', async function(req, res) {
  if (!req.cookies.session) {
    res.cookie('session', jwt.sign({ id: createUser() }, SECRET));
  }
  res.redirect('/home');
});

app.get('/home', auth, async function(req, res) {
  res.render('index');
});

app.get('/search', auth, async function(req, res) {
  if (!req.query.q){
    // if user didn't provide a search query, show last results
    const previousResults = getResultsFromCache(req.user);
    if (previousResults) {
      return res.render('search', { results: previousResults });
    }
  }

  res.render('search');
});

// APIs
app.get('/api/search', auth, async function(req, res) {
  const query = req.query.q;

  const songs_db = (await axios.get('http://localhost:5005/public/songs.json')).data;
  const results = songs_db.filter(song => song.title.toLowerCase().includes(query.toLowerCase()));

  addResultsToCache(req.user, results.length === 0 ? {message: 'No songs found for ' + query} : results);

  if (results.length === 0) {
    return res.status(404).json({ message: 'No songs found for ' + query });
  }

  res.json(results);
});

app.get('/api/test', (req, res) => {
  res.json({message: "API is working"});
});

app.get('/api/healthcheck', auth, async function(req, res) {
  if (await performHealthCheck()) {
      res.json({ message: 'OK' });
  } else {
      res.status(500).json({ message: 'Health check failed' });
  }
});

app.listen(SERVER_PORT, () => {
    console.log(`Server is up on http://localhost:${SERVER_PORT}`);
});
