//===============================================================================================================
//INITIAL SETUP AND REQUIREMENTS
//===============================================================================================================

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');
app.use(
	bodyParser.urlencoded({
		extended : true
	})
);
app.use(express.static('public'));

//INITIALIZING EXPRESS SESSION
app.use(
	session({
		secret            : process.env.SECRET,
		resave            : false,
		saveUninitialized : false
	})
);

//TELLING OUR APP TO USE PASSPORT
app.use(passport.initialize());

//TELLING OUR APP TO INCORPORATE SESSION AND PASSPORT
app.use(passport.session());

//ESTABLISH MONGOOSE CONNECTION
mongoose.connect('mongodb://localhost:27017/secretUser', {
	useNewUrlParser    : true,
	useUnifiedTopology : true,
	useCreateIndex     : true
});

//CREATE NEW  MONGOOSE STRUTURE
const userSchema = mongoose.Schema({
	email      : String,
	password   : String,
	googleId   : String,
	secret     : String,
	facebookId : String
});

//ADDING PASSPORT LOCAL MONGOOSE TO THE SCHEMA
userSchema.plugin(passportLocalMongoose);
//ADDING FINDORCREATE TO THE SCHEMA
userSchema.plugin(findOrCreate);

//STORE THE SCHEMA INTO A USER OBJECT
const User = new mongoose.model('User', userSchema);

//TELLING PASSPORT TO CREATE A LOCAL STRATEGY TO SAVE USERS
passport.use(User.createStrategy());

//SETTING UP PASSPORT TO SERIALIZE AND DE-SERIALIZE USERS
passport.serializeUser(function(user, done) {
	done(null, user.id);
});

passport.deserializeUser(function(id, done) {
	User.findById(id, function(err, user) {
		done(err, user);
	});
});

//SETTING UP GOOGLE STRATERGY AND TELLING OUR APP TO CREATE AND STORE THEIR GOOGLE ID
passport.use(
	new GoogleStrategy(
		{
			clientID       : process.env.CLIENT_ID,
			clientSecret   : process.env.CLIENT_SECRET,
			callbackURL    : 'http://localhost:5000/auth/google/secrets',
			userProfileURL : 'https://www.googleapis.com/oauth2/v3/userinfo'
		},
		function(accessToken, refreshToken, profile, cb) {
			console.log('Google', profile);

			User.findOrCreate(
				{
					googleId : profile.id
				},
				function(err, user) {
					return cb(err, user);
				}
			);
		}
	)
);

//SETTING UP FACEBOOK STRATERGY AND TELLING OUR APP TO CREATE AND STORE THEIR FACEBOOK ID
passport.use(
	new FacebookStrategy(
		{
			clientID     : process.env.FACEBOOK_APP_ID,
			clientSecret : process.env.FACEBOOK_APP_SECRET,
			callbackURL  : 'http://localhost:5000/auth/facebook/secrets'
		},
		function(accessToken, refreshToken, profile, cb) {
			console.log('Facebook', profile);
			User.findOrCreate(
				{
					facebookId : profile.id
				},
				function(err, user) {
					return cb(err, user);
				}
			);
		}
	)
);

//===============================================================================================================
//ROUTES
//==============================================================================================================

//ROOT ROUTE
//---------------------------------------------------------------------------------------------------------------
app.get('/', (req, res) => {
	res.render('home');
});
//---------------------------------------------------------------------------------------------------------------

//GOOGLE AUTH ROUTES
//---------------------------------------------------------------------------------------------------------------
app.get(
	'/auth/google',
	passport.authenticate('google', {
		scope : [ 'profile' ]
	})
);

app.get(
	'/auth/google/secrets',
	passport.authenticate('google', {
		failureRedirect : '/login'
	}),
	function(req, res) {
		// Successful authentication, redirect to secrets.
		res.redirect('/secrets');
	}
);

//---------------------------------------------------------------------------------------------------------------

//FACEBOOK AUTH ROUTES
//---------------------------------------------------------------------------------------------------------------
app.get(
	'/auth/facebook',
	passport.authenticate('facebook', {
		scope: [ 'user_friends', 'manage_pages' ]
	})
);

app.get(
	'/auth/facebook/secrets',
	passport.authenticate('facebook', { failureRedirect: '/login' }),
	function(req, res) {
		// Successful authentication, redirect home.
		res.redirect('/secrets');
	}
);

//---------------------------------------------------------------------------------------------------------------

//LOGIN ROUTE
//---------------------------------------------------------------------------------------------------------------
app.get('/login', (req, res) => {
	res.render('login');
});

app.post('/login', (req, res) => {
	const user = new User({
		username : req.body.username,
		password : req.body.password
	});

	req.login(user, err => {
		if (err) {
			console.log(err);
			return res.redirect('/login');
		}

		passport.authenticate('local')(req, res, () => {
			return res.redirect('/secrets');
		});
	});
});
//---------------------------------------------------------------------------------------------------------------

//REGISTER ROUTE
//---------------------------------------------------------------------------------------------------------------
app.get('/register', (req, res) => {
	res.render('register');
});

app.post('/register', (req, res) => {
	User.register(
		{
			username : req.body.username
		},
		req.body.password,
		(err, user) => {
			if (err) {
				console.log(err);
				return res.redirect('/register');
			}

			passport.authenticate('local')(req, res, () => {
				res.redirect('/secrets');
			});
		}
	);
});
//---------------------------------------------------------------------------------------------------------------

//SECRET ROUTE
//---------------------------------------------------------------------------------------------------------------
app.get('/secrets', (req, res) => {
	User.find(
		{
			secret : {
				$ne : null
			}
		},
		function(err, foundUser) {
			if (err) {
				console.log(err);
			} else {
				if (foundUser) {
					res.render('secrets', {
						usersWithSecrets : foundUser
					});
				}
			}
		}
	);
});
//---------------------------------------------------------------------------------------------------------------

//SUBMIT POUTE
//---------------------------------------------------------------------------------------------------------------
app.get('/submit', (req, res) => {
	if (req.isAuthenticated()) {
		return res.render('submit');
	}

	res.redirect('/login');
});

app.post('/submit', (req, res) => {
	const submittedSecret = req.body.secret;

	User.findById(req.user.id, (err, foundUser) => {
		if (err) {
			console.log(err);
			return res.redirect('/submit');
		}
		foundUser.secret = submittedSecret;
		foundUser.save(err => {
			if (err) {
				console.log(err);
			}

			res.redirect('/secrets');
		});
	});
});

//---------------------------------------------------------------------------------------------------------------

//LOGOUT ROUTE
//---------------------------------------------------------------------------------------------------------------
app.get('/logout', (req, res) => {
	req.logout();
	res.redirect('/');
});
//---------------------------------------------------------------------------------------------------------------

//OPENINIG THE SERVER TO PORT 5000
app.listen(5000, () => {
	console.log('Server started on Port 5000:');
});
