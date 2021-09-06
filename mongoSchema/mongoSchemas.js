const mongoose = require('mongoose');

const userCred = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    mobile: { type: Number, required: true },
    password: { type: String },
}, { collection: "usercredentials" });

const userProfile = new mongoose.Schema({
    name: { type: String, required: true },
    age: { type: Number, required: true },
    userId: { type: String, required: true, unique: true }
}, { collection: "userProfile" })

const credModel = mongoose.model('usercredential', userCred);
const profileModel = mongoose.model('userprofile', userProfile);

module.exports = {
    credModel, profileModel
}




