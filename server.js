const express = require('express');
const bodyParser = require('body-parser');
const passport = require('passport');
const authJwtController = require('./auth_jwt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const User = require('./Users');
const Movie = require('./Movies');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.use(passport.initialize());

const router = express.Router();

// Signup route
router.post('/signup', async (req, res) => {
  if (!req.body.username || !req.body.password) {
    return res.status(400).json({ success: false, msg: 'Please include both username and password to signup.' });
  }

  try {
    const user = new User({
      name: req.body.name,
      username: req.body.username,
      password: req.body.password,
    });

    await user.save();

    res.status(201).json({ success: true, msg: 'Successfully created new user.' });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ success: false, message: 'A user with that username already exists.' });
    } else {
      console.error(err);
      return res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
    }
  }
});

// Signin route
router.post('/signin', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username }).select('name username password');

    if (!user) {
      return res.status(401).json({ success: false, msg: 'Authentication failed. User not found.' });
    }

    const isMatch = await user.comparePassword(req.body.password);

    if (isMatch) {
      const userToken = { id: user._id, username: user.username };
      const token = jwt.sign(userToken, process.env.SECRET_KEY, { expiresIn: '24h' });
      res.json({ success: true, token: 'JWT ' + token });
    } else {
      res.status(401).json({ success: false, msg: 'Authentication failed. Incorrect password.' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
  }
});

// Import movie routes
const movieRoutes = require('./Movies');

// Use routes
app.use('/', router);
app.use('/movies', movieRoutes);

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app; // for testing only
