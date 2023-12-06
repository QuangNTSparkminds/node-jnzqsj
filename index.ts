const express = require('express');
const bcrypt = require('bcryptjs');
const joi = require('joi');
const app = express();
const port = 3000;
const bodyParser = require('body-parser');
const cors = require("cors");

import { Request, Response } from 'express';

interface UserDto {
  username: string;
  email: string;
  type: 'user' | 'admin';
  password: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

// Database mock where the username is the primary key of a user.
const MEMORY_DB: Record<string, UserEntry> = {};

// CODE HERE
//
// I want to be able to register a new unique user (username and password). After the user is created I
// should be able to login with my username and password. If a user register request is invalid a 400 error
// should be returned, if the user is already registered a conflict error should be returned.
// On login the users crendentials should be verified.
// Because we dont have a database in this environment we store the users in memory. Fill the helper functions
// to query the memory db.

const registerSchema = joi.object({
  username: joi.string().min(3).max(24).required(),
  email: joi.string().email().required(),
  type: joi.string().valid('user', 'admin').required(),
  password: joi
    .string()
    .min(5)
    .max(24)
    .regex(/^[a-zA-Z$&+,:;=?@#|'<>.^*()%!-]+$/)
    .regex(/[$&+,:;=?@#|'<>.^*()%!-]+/)
    .required(),
});

const loginSchema = joi.object({
  username: joi.string().required(),
  password: joi.string().required(),
});

function getUserByUsername(name: string): UserEntry | undefined {
  return MEMORY_DB[name];
}

function getUserByEmail(email: string): UserEntry | undefined {
  return Object.values(MEMORY_DB).filter((x) => x.email === email)[0];
}

const validator =
  (schema: any) => async (req: Request, res: Response, next: any) => {
    try {
      await schema.validateAsync(req.body);
      next();
    } catch (err) {
      res.status(400).send();
      return;
    }
  };

app.use(cors());
app.options('*', cors());
app.use(bodyParser.json());

// Request body -> UserDto
app.post(
  '/register',
  validator(registerSchema),
  async (req: Request, res: Response) => {
    // Validate user object using joi
    // - username (required, min 3, max 24 characters)
    // - email (required, valid email address)
    // - type (required, select dropdown with either 'user' or 'admin')
    // - password (required, min 5, max 24 characters, upper and lower case, at least one special character)
    const { username, email, type, password } = req.body;

    if (getUserByUsername(username)) {
      res.status(409).send();
      return;
    }

    const salt = bcrypt.genSaltSync(10);

    MEMORY_DB[username] = {
      email,
      type,
      salt,
      passwordhash: bcrypt.hashSync(password, salt),
    };
    res.status(204).send();
  }
);

// Request body -> { username: string, password: string }
app.post('/login', validator(loginSchema), (req: Request, res: Response) => {
  // Return 200 if username and password match
  // Return 401 else

  const { username, password } = req.body;

  const user = getUserByUsername(username);

  if (!user || !bcrypt.compareSync(password, user.passwordhash)) {
    res.status(401).send();
    return;
  }

  res.status(200).json({
    username,
    email: user.email,
    type: user.type,
  });
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
