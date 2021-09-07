const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const dotenvJSON = require('dotenv-json');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const model = require('./mongoSchema/mongoSchemas');


const env = process.env.NODE_ENV || 'dev';
const port = process.env.PORT || 3000;
dotenvJSON({ path: `./config.${env}.json` });
const { jwtSecret } = process.env;

app.use(bodyParser.json());
const { dbString } = process.env;

(async function () {
    const res = mongoose.connect(dbString, { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true }).then((val => {
        console.log("connection establish to the database");
        app.listen(port, () => {
            console.log('hello listening');
        });
    }));
})();

app.post('/registerUser', async function (req, res) {
    console.log(req.body);
    let { email, password, mobile } = req.body;
    password = await bcrypt.hash(password, 10);
    if (!email || !mobile) {
        // just performing the simple check , can also enable the OTP validation as well;
        res.status(400).json({
            "message": 'please enter valid mobile Id and email'
        })
    }
    try {
        const dbResponse = await model.credModel.create({
            email,
            mobile,
            password,
        })
        res.status(200).json(dbResponse);
    }
    catch (err) {
        if (err.code == 11000) {
            res.status(404).json({
                message: 'user exists'
            })
        }
        else {
            throw err;
        }
    }
})

app.post('/login', async function (req, res) {
    const { email, password } = req.body;
    const user = await model.credModel.findOne({ email }).lean();
    console.log(user);
    if (!user) {
        res.status(400).json({ message: 'this user doesnt exist' });
    }
    if (await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({
            // eslint-disable-next-line no-underscore-dangle
            id: user._id,
            username: user.email,
        }, jwtSecret, { expiresIn: '30m' });
        console.log('the token is ', token);
        res.status(200).json({
            message: "successfullyLoggedIn",
            token,
        });
    } else {
        res.status(400).json({
            message: 'inavlid  user credential',
        });
    }
})

app.post('/setUserProfile', async function (req, res) {
    try {
        let { token, name, age } = req.body;
        const user = jwt.verify(token, jwtSecret);
        console.log("the user is", user);
        const userId = user.id;
        const dbResponse = await model.profileModel.create({
            name,
            age,
            userId,
        })
        res.status(200).json({
            "message": "profile succesfully created"
        })
        console.log(dbResponse);
    }
    catch (err) {
        if (err.message === 'invalid signature') {
            res.status(400).json({
                message: 'in valid token'
            })
        }
        if (err.message === 'jwt expired') {
            res.status(400).json({
                message: 'token Expired'
            })
        } else {
            res.status(400).json({
                message: err
            })
        }
    }
})

app.get('/getUserProfile', async function (req, res) {

    const token = req.query.token;
    console.log(typeof (token));
    try {
        const user = jwt.verify(token, jwtSecret);
        const userId = user.id;
        // getting the user Profile 
        const userProfile = await model.profileModel.findOne({ userId }).lean();
        res.status(200).json({
            userProfile
        })
    }
    catch (err) {
        if (err.message === 'invalid signature') {
            res.status(400).json({
                message: 'in valid token'
            })
        }
        if (err.message === 'jwt expired') {
            res.status(400).json({
                message: 'token Expired'
            })
        } else {
            res.status(400).json({
                message: err
            })
        }
    }
})

app.post('/updateUserProfile', async function (req, res) {

    const { token, age, name } = req.body;
    const user = jwt.verify(token, jwtSecret);
    const userId = user.id
    try {
        const resp = await model.profileModel.updateOne({ userId }, {
            $set: {
                name, age
            }
        })
        res.status(200).json({
            message: "profile successfully updated"
        })
        console.log(resp);
    }
    catch (err) {
        res.status(400).json({
            message: err
        })
    }
})




























































