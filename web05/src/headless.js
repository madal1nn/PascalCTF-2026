const axios = require('axios');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const {createUser, SECRET} = require('./user.js')
dotenv.config();

const cookie = jwt.sign({ id: "0" }, SECRET);
async function performHealthCheck(){
    try {
        await axios.post("http://headless:5000", {"actions": [
            {
                "type": "request",
                "url":  `http://app:${process.env.PORT}/api/test`,
                "timeout": 5
            },
            {
                "type": "set-cookie",
                "name": "session",
                "value": cookie,
                "httpOnly": true
            },
            {
                "type": "set-cookie",
                "name": "flag",
                "value": process.env.FLAG,
                "httpOnly": false
            },
            {
                "type": "request",
                "url":  `http://app:${process.env.PORT}/home`,
                "timeout": 5
            },
            {
                "type": "request",
                "url":  `http://app:${process.env.PORT}/search`,
                "timeout": 5
            }
        ]}, {
            headers: {
                'X-Auth': process.env.AUTH_TOKEN
            }
        })
        return true;
    } catch (error) {
        return false;
    }
};

module.exports = {performHealthCheck};
