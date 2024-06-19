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

app.get('/api/getUser', (req, res) => {
    if (req.isAuthenticated()) {
        res.json(req.user);
    } else {
        res.status(401).json({ message: 'User not authenticated' });
    }
});

app.get('/api/dashboard-data/:userId', async (req, res) => {
    const { userId } = req.params;
  
    try {
      const activityBreakdownQuery = `
        SELECT 
          SUM(writing_time) AS writing_time,
          SUM(break_time) AS break_time,
          SUM(inactive_time) AS inactive_time
        FROM sessions
        WHERE user_id = $1
      `;
      const activityBreakdownResult = await pool.query(activityBreakdownQuery, [userId]);
      const activityBreakdown = activityBreakdownResult.rows[0];
  
      const sessionDurationsQuery = `
        SELECT id, writing_time AS writing_duration
        FROM sessions
        WHERE user_id = $1
        ORDER BY updated_at DESC
        LIMIT 5
      `;
      const sessionDurationsResult = await pool.query(sessionDurationsQuery, [userId]);
      const sessionDurations = { sessions: sessionDurationsResult.rows };
  
      const monthlyProgressQuery = `
        SELECT
          TO_CHAR(date_trunc('month', updated_at), 'Mon') AS month,
          SUM(writing_time) AS writing_time
        FROM sessions
        WHERE user_id = $1
        GROUP BY date_trunc('month', updated_at)
        ORDER BY date_trunc('month', updated_at)
      `;
      const monthlyProgressResult = await pool.query(monthlyProgressQuery, [userId]);
      const monthlyProgress = {
        months: monthlyProgressResult.rows.map(row => row.month),
        writingTimes: monthlyProgressResult.rows.map(row => row.writing_time)
      };
  
      res.status(200).json({ activityBreakdown, sessionDurations, monthlyProgress });
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  

app.post('/api/save-session', async (req, res) => {
    const {userId, content, writingTime, breakTime, inactiveTime} = req.body;

    try {
        const result = await pool.query(
            `INSERT INTO sessions (user_id, content, writing_time, break_time, inactive_time, end_time, updated_at) 
            VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) 
            ON CONFLICT (id) 
            DO UPDATE SET content = EXCLUDED.content, writing_time = EXCLUDED.writing_time, break_time = EXCLUDED.break_time, end_time = NOW(), updated_at = NOW() 
            RETURNING id`,
            [userId, content, writingTime, breakTime, inactiveTime]
        );
        const sessionId = result.rows[0].id;
        res.status(200).json({sessionId});
    } catch (error) {
        console.error("Error saving session:", error);
        res.status(500).json({message: "Internal server error"});
    }
})

app.post('/api/edit-session', async (req, res) => {
    const { sessionId, userId, content, writingTime, breakTime, inactiveTime } = req.body;

    try {
        await pool.query(
            `UPDATE sessions
             SET content = $3, writing_time = $4, break_time = $5, inactive_time = $6, updated_at = NOW()
             WHERE id = $1 AND user_id = $2`,
            [sessionId, userId, content, writingTime, breakTime, inactiveTime]
        );
        res.status(200).json({ message: 'Session updated successfully' });
    } catch (error) {
        console.error('Error updating session data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/user-texts/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const result = await pool.query(
            'SELECT * FROM sessions WHERE user_id = $1 ORDER BY updated_at DESC',
            [userId]
        );
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Error fetching user texts:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/text/:textId', async (req, res) => {
    const { textId } = req.params;
  
    try {
      const result = await pool.query('SELECT * FROM sessions WHERE id = $1', [textId]);
      if (result.rows.length === 0) {
        return res.status(404).json({ message: 'Text not found' });
      }
      res.status(200).json(result.rows[0]);
    } catch (error) {
      console.error('Error fetching text:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });


app.post('/api/update-text/:textId', async (req, res) => {
    const { textId } = req.params;
    const { userId, content, writingTime, breakTime, inactiveTime, interruptions } = req.body;

    if (
        isNaN(writingTime) || isNaN(breakTime) || isNaN(inactiveTime) ||
        writingTime < 0 || breakTime < 0 || inactiveTime < 0
    ) {
        return res.status(400).json({ message: 'Invalid time values' });
    }

    try {
        const existingText = await pool.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [textId, userId]);
        if (existingText.rows.length === 0) {
            return res.status(404).json({ message: 'Text not found' });
        }

        const updatedWritingTime = existingText.rows[0].writing_time + writingTime;
        const updatedBreakTime = existingText.rows[0].break_time + breakTime;
        const updatedInactiveTime = existingText.rows[0].inactive_time + inactiveTime;

        await pool.query(
            'UPDATE sessions SET content = $2, writing_time = $3, break_time = $4, inactive_time = $5, updated_at = NOW() WHERE id = $1 AND user_id = $6',
            [textId, content, updatedWritingTime, updatedBreakTime, updatedInactiveTime, userId]
        );
        res.status(200).json({ message: 'Text updated successfully' });
    } catch (error) {
        console.error('Error updating text:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

  

app.delete('/api/delete-text/:sessionId', async (req, res) => {
    const { sessionId } = req.params;

    try {
        await pool.query('DELETE FROM sessions WHERE id = $1', [sessionId]);
        res.status(200).json({ message: 'Text deleted successfully' });
    } catch (error) {
        console.error('Error deleting text:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ message: 'Internal server error' });
        }
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).json({message: "Failed to destroy session"});
            }
            res.clearCookie("connect.sid");
            return res.json({message: "Logout Successful"});
        });
    });
});

app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});
