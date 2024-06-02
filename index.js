import express from 'express';
import dotenv from 'dotenv';
import pg from 'pg';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import bodyParser from 'body-parser';
import { Resend } from 'resend';
import session from 'express-session';

dotenv.config();

const app = express();
const saltRounds = 10;
const port = process.env.PORT || 5000;

const { Pool } = pg;
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false
});

app.use(cors({
    origin: "http://localhost:3000",
    credentials: true
}));

app.use(bodyParser.json());

app.use(session({
    secret: "TOPSECRETWORD",
    resave: false,
    saveUninitialized: true,
    rolling: true,
    cookie: { 
        secure: false,
        maxAge: 3600000,
        httpOnly: true,
     } // set to true if using https
}));

app.use(passport.initialize());
app.use(passport.session());

const resend = new Resend(process.env.RESEND_API_KEY);

// Configure Passport Local Strategy
passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, async (email, password, done) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return done(null, false, { message: 'Incorrect email.' });
        }

        const isValidPassword = bcrypt.compareSync(password, user.password);

        if (!isValidPassword) {
            return done(null, false, { message: 'Incorrect password.' });
        }

        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        const user = result.rows[0];
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

app.get('/api/checkAuth', (req, res) => {
    if (req.isAuthenticated()) {
        res.status(200).json({ authenticated: true });
    } else {
        res.status(401).json({ authenticated: false });
    }
});

app.post('/api/createAccount', async (req, res) => {
    const { email, firstName, lastName, userName, password } = req.body;

    try {
        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, userName]);

        if (existingUser.rows.length > 0) {
            return res.status(409).json({ message: "An account with this email or username already exists." });
        }

        const hashedPassword = bcrypt.hashSync(password, saltRounds);
        const verificationToken = bcrypt.hashSync(email, saltRounds);

        const result = await pool.query(
            'INSERT INTO users (email, firstname, lastname, username, password, verification_token) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [email, firstName, lastName, userName, hashedPassword, verificationToken]
        );

        const user = result.rows[0];

        // Send verification email
        const verificationLink = `http://localhost:3000/verifyEmail?token=${verificationToken}&email=${email}`;
        await resend.emails.send({
            to: email,
            from: 'notemaster@abiodunolaoluwa.com',
            subject: 'Welcome to NoteMaster',
            text: `Welcome to NoteMaster, ${firstName}. We are glad to have you onboard.`
        });

        res.status(201).json({ message: 'Account created successfully. Please check your email to verify your account.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return res.status(500).json({ message: 'Internal server error' });
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        req.logIn(user, (err) => {
            if (err) {
                return res.status(500).json({ message: 'Internal server error' });
            }
            return res.json({ message: 'Login successful', user });
        });
    })(req, res, next);
});

app.get('/api/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ message: 'Internal server error' });
        }
        res.json({ message: 'Logout successful' });
    });
});

app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});
