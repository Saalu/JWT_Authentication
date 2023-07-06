require("dotenv/config");

const express = require("express");
const jwt = require("jsonwebtoken");
const { compare, hash } = require("bcrypt");
const cookieParser = require("cookie-parser");
const { createAccessToken, createRefreshToken } = require("./src/token.js");

const { fakeDB } = require("./src/fakeDB");
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

app.get("/", async (req, res) => {
  res.send("Welcome home");
  console.log({ msg: "Welcome home" });
});

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const user = await fakeDB.find((user) => user.email === email);
    if (user) res.status(401).json("User already exist");
    const hashedPassword = await hash(password, 10);

    fakeDB.push({
      id: fakeDB.length,
      username,
      email,
      password: hashedPassword,
    });
    console.log({ user: fakeDB });
    res.json({ msg: "User Created", user: fakeDB });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

const port = process.env.PORT;

app.listen(port, () => {
  console.log(`Server on Port:${port}`);
});
