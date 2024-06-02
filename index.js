import express from 'express';
import dotenv from 'dotenv';
import pg from 'pg';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import bodyParser from 'body-parser';
import { Resend } from 'resend';

dotenv.config();

const app = express();
const saltRounds = 10;
const port = process.env.PORT || 5000;

const { Pool } = pg;
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false
});

const resend = new Resend(process.env.RESEND_API_KEY);

app.use(cors());
app.use(bodyParser.json());

app.post('/api/createAccount', async (req, res) => {
    const { email, firstName, lastName, userName, password } = req.body;

    try {

        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1 OR userName = $2', [email, userName]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ message: "An account with this email or username already exists." });
        }

        const hashedPassword = bcrypt.hashSync(password, saltRounds);
        const verificationToken = bcrypt.hashSync(email, saltRounds); // Simple token generation

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
            text: `Welcome to Notemaster ${firstName}, we are glad to have you onboard.`
        });

        res.status(201).json({ message: 'Account created successfully. Please check your email to verify your account.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal server error' });
    }
});


app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (user && bcrypt.compareSync(password, user.password)) {
            res.json({ message: 'Login successful', user });
        } else {
            res.status(401).json({ message: 'Invalid email or password' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});
