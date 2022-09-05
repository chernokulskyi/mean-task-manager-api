import express from 'express';
import { List, Task, User } from './models/index.js';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import jwt from 'jsonwebtoken';

const app = express();
dotenv.config();

const connect = async () => {
  try {
    await mongoose.connect(process.env.DB_URL);
    console.log('connected to mongodb!');
  } catch (err) {
    throw err;
  }
};

mongoose.connection.on('disconnected', () => {
  console.log('mongodb disconnected');
});

app.use(express.json());
app.use(cors());
app.use((req, res, next) => {
  res.header(
    'Access-Control-Expose-Headers',
    'x-access-token, x-refresh-token, _id'
  );
  next();
});

// Check whether the request has a valid JWT access token
const authenticate = (req, res, next) => {
  const token = req.header('x-access-token');
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      res.status(401).send(err);
    } else {
      req.user_id = decoded._id;
      next();
    }
  });
};

// Verify Refresh Token Middleware
const verifySession = (req, res, next) => {
  const refreshToken = req.header('x-refresh-token');
  const _id = req.header('_id');
  User.findByIdAndToken(_id, refreshToken)
    .then((user) => {
      if (!user) {
        return Promise.reject({ error: 'User not found' });
      }

      req.user_id = user._id;
      req.userObject = user;
      req.refreshToken = refreshToken;

      let isSessionValid = false;
      user.sessions.forEach((session) => {
        if (session.token === refreshToken) {
          if (!User.hasRefreshTokenExpired(session.expiresAt)) {
            isSessionValid = true;
          }
        }
      });
      if (isSessionValid) {
        next();
      } else {
        return Promise.reject({
          error: 'refresh token has expired or the session is invalid',
        });
      }
    })
    .catch((e) => {
      res.status(401).send(e);
    });
};

// List Route Handlers
app.get('/lists', authenticate, async (req, res) => {
  try {
    const lists = await List.find({ _userId: req.user_id });
    res.status(200).send(lists);
  } catch (e) {
    res.sendStatus(400);
  }
});
app.post('/lists', authenticate, async (req, res) => {
  try {
    const listDoc = await new List({
      title: req.body.title,
      _userId: req.user_id,
    }).save();
    res.status(201).send(listDoc);
  } catch (e) {
    res.sendStatus(400);
  }
});
app.patch('/lists/:id', authenticate, async (req, res) => {
  try {
    const updatedListDoc = await List.findOneAndUpdate(
      { _id: req.params.id, _userId: req.user_id },
      { $set: req.body },
      { new: true }
    );
    if (updatedListDoc) {
      res.status(200).send(updatedListDoc);
    } else {
      throw new Error();
    }
  } catch (e) {
    res.sendStatus(400);
  }
});
app.delete('/lists/:id', authenticate, async (req, res) => {
  try {
    const removedListDoc = await List.findOneAndDelete({
      _id: req.params.id,
      _userId: req.user_id,
    });
    if (removedListDoc) {
      res.status(200).send(removedListDoc);
      deleteTasksFromList(removedListDoc._id);
    } else {
      throw new Error();
    }
  } catch (e) {
    res.sendStatus(400);
  }
});

// Task Route Handlers
app.get('/lists/:listId/tasks', authenticate, async (req, res) => {
  try {
    const tasks = await Task.find({
      _listId: req.params.listId,
    });
    res.status(200).send(tasks);
  } catch (e) {
    res.sendStatus(400);
  }
});
app.get('/lists/:listId/tasks/:taskId', authenticate, async (req, res) => {
  try {
    const task = await Task.findOne({
      _id: req.params.taskId,
      _listId: req.params.listId,
    });
    res.status(200).send(task);
  } catch (e) {
    res.sendStatus(400);
  }
});
app.post('/lists/:listId/tasks', authenticate, async (req, res) => {
  try {
    const list = await List.findOne({
      _id: req.params.listId,
      _userId: req.user_id,
    });

    if (!list) throw new Error('not found');

    const newTask = new Task({
      title: req.body.title,
      _listId: req.params.listId,
    });
    const taskDoc = await newTask.save();
    res.status(201).send(taskDoc);
  } catch (e) {
    res.sendStatus(400);
  }
});
app.patch('/lists/:listId/tasks/:taskId', authenticate, async (req, res) => {
  try {
    const list = await List.findOne({
      _id: req.params.listId,
      _userId: req.user_id,
    });

    if (!list) throw new Error('not found');

    const updatedTask = await Task.findOneAndUpdate(
      {
        _id: req.params.taskId,
        _listId: req.params.listId,
      },
      { $set: req.body },
      { new: true }
    );
    if (updatedTask) {
      res.status(200).send(updatedTask);
    } else {
      throw new Error();
    }
  } catch (e) {
    res.sendStatus(400);
  }
});
app.delete('/lists/:listId/tasks/:taskId', authenticate, async (req, res) => {
  try {
    const list = await List.findOne({
      _id: req.params.listId,
      _userId: req.user_id,
    });

    if (!list) throw new Error('not found');

    const removedTaskDoc = await Task.findOneAndDelete({
      _id: req.params.taskId,
    });
    if (removedTaskDoc) {
      res.status(200).send(removedTaskDoc);
    } else {
      throw new Error();
    }
  } catch (e) {
    res.sendStatus(400);
  }
});

// User Route Handlers
app.post('/users/', (req, res) => {
  const newUser = new User(req.body);
  newUser
    .save()
    .then(() => {
      return newUser.createSession();
    })
    .then((refreshToken) => {
      return newUser.generateAccessAuthToken().then((accessToken) => {
        return { accessToken, refreshToken };
      });
    })
    .then((authTokens) => {
      res
        .header('x-refresh-token', authTokens.refreshToken)
        .header('x-access-token', authTokens.accessToken)
        .status(201)
        .send(newUser);
    })
    .catch((e) => {
      res.status(400).send(e);
    });
});
app.post('/users/login', (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  User.findByCredentials(email, password).then((user) => {
    return user
      .createSession()
      .then((refreshToken) => {
        return user.generateAccessAuthToken().then((accessToken) => {
          return { accessToken, refreshToken };
        });
      })
      .then((authTokens) => {
        res
          .header('x-refresh-token', authTokens.refreshToken)
          .header('x-access-token', authTokens.accessToken)
          .status(200)
          .send(user);
      })
      .catch((e) => {
        res.status(400).send(e);
      });
  });
});
app.get('/users/me/access-token', verifySession, (req, res) => {
  req.userObject
    .generateAccessAuthToken()
    .then((accessToken) => {
      res.header('x-access-token', accessToken).send({ accessToken });
    })
    .catch((e) => {
      res.status(400).send(e);
    });
});

// Helpers
const deleteTasksFromList = (_listId) => {
  Task.deleteMany({ _listId }).then(() => {
    console.log('tasks from list ' + _listId + ' were deleted');
  });
};

app.listen(process.env.PORT || 3000, () => {
  connect()
    .then(() => console.log('server is listening on port 3000'))
    .catch((e) => console.log('something went wrong', e));
});
