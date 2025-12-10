const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const connectToDatabase = require('../models/db');
const router = express.Router();
const dotenv = require('dotenv');
const pino = require('pino');  // Import Pino logger
dotenv.config();

const logger = pino();  // Create a Pino logger instance

//Create JWT secret
dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async (req, res) => {
    try {
      //Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`.
      const db = await connectToDatabase();

      //Access the `users` collection
      const collection = db.collection("users");

      //Check for existing email in DB
      const existingEmail = await collection.findOne({ email: req.body.email });

        if (existingEmail) {
            logger.error('Email id already exists');
            return res.status(400).json({ error: 'Email id already exists' });
        }

        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        const email=req.body.email;

        //Save user details
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });

        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };

        //Create JWT
        const authtoken = jwt.sign(payload, JWT_SECRET);
        logger.info('User registered successfully');
        res.json({ authtoken,email });
    } catch (e) {
        logger.error(e);
        return res.status(500).send('Internal server error');
    }
});

    //Login Endpoint
router.post('/login', async (req, res) => {
    console.log("\n\n Inside login")

    try {
        // const collection = await connectToDatabase();
        const db = await connectToDatabase();
        const collection = db.collection("users");
        const theUser = await collection.findOne({ email: req.body.email });

        if (theUser) {
            let result = await bcryptjs.compare(req.body.password, theUser.password)
            if(!result) {
                logger.error('Passwords do not match');
                return res.status(404).json({ error: 'Wrong pasword' });
            }
            let payload = {
                user: {
                    id: theUser._id.toString(),
                },
            };

            const userName = theUser.firstName;
            const userEmail = theUser.email;

            const authtoken = jwt.sign(payload, JWT_SECRET);
            logger.info('User logged in successfully');
            return res.status(200).json({ authtoken, userName, userEmail });
        } else {
            logger.error('User not found');
            return res.status(404).json({ error: 'User not found' });
        }
    } catch (e) {
        logger.error(e);
        return res.status(500).json({ error: 'Internal server error', details: e.message });
    }
});

//update endpoint
router.put('/update', [
    // Validation rules
    body('firstName').optional().isString(),
    body('lastName').optional().isString(),
    body('password').optional().isLength({ min: 6 })
], async (req, res) => {
    try {
        // Task 2: Validate input
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.error('Validation errors in update request', errors.array());
            return res.status(400).json({ errors: errors.array() });
        }

        // Task 3: Check if email is present in header
        const email = req.headers.email;
        if (!email) {
            logger.error('Email not found in the request headers');
            return res.status(400).json({ error: "Email not found in the request headers" });
        }

        // Task 4: Connect to MongoDB
        const db = await connectToDatabase();
        const collection = db.collection("users");

        // Task 5: Find user in DB
        const existingUser = await collection.findOne({ email });
        if (!existingUser) {
            logger.error('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        // Update fields
        if (req.body.firstName) existingUser.firstName = req.body.firstName;
        if (req.body.lastName) existingUser.lastName = req.body.lastName;
        if (req.body.password) {
            const salt = await bcryptjs.genSalt(10);
            existingUser.password = await bcryptjs.hash(req.body.password, salt);
        }
        existingUser.updatedAt = new Date();

        // Task 6: Update user in DB
        const updatedUser = await collection.findOneAndUpdate(
            { email },
            { $set: existingUser },
            { returnDocument: 'after' }
        );

        // Task 7: Create new JWT token
        const payload = { user: { id: updatedUser.value._id.toString() } };
        const authtoken = jwt.sign(payload, JWT_SECRET);

        logger.info('User updated successfully');
        res.json({ authtoken });
    } catch (e) {
        return res.status(500).send('Internal server error');
    }
});
module.exports = router;