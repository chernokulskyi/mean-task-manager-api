import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import dotenv from 'dotenv';
import _ from 'lodash';

dotenv.config();

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    minlength: 1,
    trim: true,
    unique: true
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  sessions: [{
    token: {
      type: String,
      required: true
    },
    expiresAt: {
      type: Number,
      required: true
    }
  }]
});

UserSchema.methods.toJSON = function () {
  const user = this;
  const userObject = user.toObject();
  return _.omit(userObject, ['password', 'sessions']);
}

UserSchema.methods.generateAccessAuthToken = function () {
  const user = this;
  return new Promise((resolve, reject) => {
    jwt.sign(
      { _id: user._id.toHexString() },
      process.env.JWT_SECRET,
      { expiresIn: '30m' },
      (err, token) => {
        if (!err) resolve(token)
        else reject()
      }
    );
  });
}

UserSchema.methods.generateRefreshAuthToken = function () {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(64, (err, buf) => {
      if (!err) {
        const token = buf.toString('hex');
        return resolve(token);
      }
    })
  })
}

UserSchema.methods.createSession = function () {
  const user = this;
  return user.generateRefreshAuthToken().then((refreshToken) => {
    return saveSessionToDatabase(user, refreshToken);
  }).then((refreshToken) => {
    return refreshToken;
  }).catch((e) => {
    return Promise.reject('Failed to save session to database.\n' + e);
  })
}

UserSchema.statics.findByIdAndToken = function (_id, token) {
  const User = this;
  return User.findOne({
    _id,
    'sessions.token': token
  });
}

UserSchema.statics.findByCredentials = function (email, password) {
  const User = this;
  return User.findOne({ email }).then((user) => {
    if (!user) return Promise.reject();
    return new Promise((resolve, reject) => {
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) resolve(user)
        else reject()
      });
    });
  });
}

UserSchema.statics.hasRefreshTokenExpired = (expiresAt) => {
  const secondsSinceEpoch = Date.now() / 1000;
  return expiresAt <= secondsSinceEpoch;
}

UserSchema.pre('save', function (next) {
  const user = this;
  const costFactor = 10;
  if (user.isModified('password')) {
    bcrypt.genSalt(costFactor, (err, salt) => {
      bcrypt.hash(user.password, salt, (err, hash) => {
        user.password = hash;
        next();
      })
    })
  } else {
    next();
  }
});

const saveSessionToDatabase = (user, refreshToken) => {
  return new Promise((resolve, reject) => {
    const expiresAt = generateRefreshTokenExpiryTime();
    user.sessions.push({ 'token': refreshToken, expiresAt });
    user.save().then(() => {
      return resolve(refreshToken);
    }).catch((e) => {
      reject(e);
    });
  })
}

const generateRefreshTokenExpiryTime = () => {
  const daysUntilExpire = "10";
  const secondsUntilExpire = ((daysUntilExpire * 24) * 60) * 60;
  return ((Date.now() / 1000) + secondsUntilExpire);
}

export const User = mongoose.model('User', UserSchema);
