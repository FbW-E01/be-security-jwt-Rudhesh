import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import bcrypt from "bcrypt";

// Setup Express application
const app = express();
app.use(express.json());
dotenv.config();

// This makes a very secure random secret with every app reboot
const secret = process.env.SECRET;

async function hash(password) {
  return await bcrypt.hash(password, 5);
}

async function checkHash(password, hash) {
  return await bcrypt.compare(password, hash);
}

const users = [{ username: "rudesh", password: await hash("123") }];

// This middleware can be used to check if a reqest contains a valid token
function checkTokenMiddleware(req, res, next) {
  const tokenRaw = req.headers.authorization;
  console.log(`Token raw is: "${tokenRaw}""`);
  if (!tokenRaw) {
    return res.sendStatus(401);
  }

  const tokenToCheck = tokenRaw.split(" ")[1];
  console.log(`Token to check is: "${tokenToCheck}"`);
  if (!tokenToCheck) {
    return res.sendStatus(401);
  }

  jwt.verify(tokenToCheck, secret, (error, payload) => {
    console.log({ error, payload });

    if (error) {
      return res.status(400).send(error.message);
    }

    req.userData = {
      userId: payload.userId,
      username: payload.username,
    };
    next();
  });
}

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);

  users.push({
    username,
    password: await hash(password),
  });
});

// This endpoint returns a fresh token
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(
    (u) => u.username === username && u.password === password
  );
  // TODO: Check login username / password somehow
  if (!user) {
    return res.sendStatus(401);
  }

  if (!checkHash(password, user.password)) {
    return res.sendStatus(401);
  }
  const payload = { username: user.username };
  const options = { expiresIn: process.env.JWT_EXPIRATION };
  const token = jwt.sign(payload, secret, options);
  res.send(token);
});

// This endpoint is secured; only requests with a valid token can access ot
app.get("/secure", checkTokenMiddleware, (req, res) => {
  // check token and return something
  res.send(`Hooray, ${req.userData.username}, you have access`);
});

const port = process.env.PORT || 5050;
app.listen(port, () => {
  console.log("Listening on http://localhost:" + port);
});
