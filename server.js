/* 
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/ClientSide/javascript.js to edit this template
 */
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const winston = require('winston');

const app = express();
const dbPath = path.resolve(__dirname, 'db/wallet.sqlite');
const db = new sqlite3.Database(dbPath);

// Setup logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
    ],
});

// Middleware
app.use(bodyParser.json());
app.use(express.static('public'));

// Initialize database
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            balance INTEGER DEFAULT 0
        )
    `, (err) => {
        if (err) {
            logger.error("Error creating table:", err.message);
        } else {
            console.log("Database and table created successfully!");
            logger.info("Database and table created successfully!");
        }
    });
});

// Endpoint: Register User
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required." });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password, balance) VALUES (?, ?, ?)', [username, hashedPassword, 0], (err) => {
            if (err) {
                if (err.message.includes("UNIQUE constraint failed")) {
                    logger.error("Error registering user: Username already exists.");
                    return res.status(409).json({ error: "Username already exists." });
                }
                logger.error("Error registering user:", err.message);
                return res.status(500).json({ error: "Failed to register user." });
            }
            res.json({ success: true, message: "User registered successfully!" });
        });
    } catch (error) {
        logger.error("Error during registration:", error.message);
        res.status(500).json({ error: "Server error during registration." });
    }
});

// Endpoint: Login User
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required." });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
        if (err) {
            logger.error("Database error during login:", err.message);
            return res.status(500).json({ error: "Database error" });
        }
        if (!row || !(await bcrypt.compare(password, row.password))) {
            return res.status(404).json({ error: "Invalid username or password." });
        }
        res.json({ success: true, balance: row.balance, message: "Login successful!" });
    });
});

// Endpoint: Add Funds
app.post('/add-funds', (req, res) => {
    const { username, amount } = req.body;

    // Validate inputs
    if (!username || typeof username !== 'string' || !amount || isNaN(amount) || amount <= 0) {
        return res.status(400).json({ error: "Invalid username or amount. Please check your inputs." });
    }

    // Check if user exists
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
            logger.error("Database error during add-funds:", err.message);
            return res.status(500).json({ error: "Database error occurred." });
        }

        if (!row) {
            return res.status(404).json({ error: "User not found." });
        }

        // Update the balance
        db.run('UPDATE users SET balance = balance + ? WHERE username = ?', [amount, username], function (err) {
            if (err) {
                logger.error("Error updating balance:", err.message);
                return res.status(500).json({ error: "Failed to update balance." });
            }

            // Fetch the updated balance
            db.get('SELECT balance FROM users WHERE username = ?', [username], (err, updatedRow) => {
                if (err) {
                    logger.error("Error retrieving updated balance:", err.message);
                    return res.status(500).json({ error: "Failed to retrieve updated balance." });
                }

                res.json({ success: true, newBalance: updatedRow.balance });
            });
        });
    });
});

// Start the server
const PORT = 3000;

console.log("Preparing to start the server...");
app.listen(PORT, 'localhost', () => {
    console.log(`Server is running at http://localhost:${PORT}`);
    logger.info(`Server is running at http://localhost:${PORT}`);
});
