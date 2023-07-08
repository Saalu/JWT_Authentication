require("dotenv/config");

const express = require("express");
const jwt = require("jsonwebtoken");
const { compare, hash } = require("bcrypt");
const cookieParser = require("cookie-parser");
const {
  createAccessToken,
  createRefreshToken,
  sendAccessToken,
  sendRefreshToken,
} = require("./src/token.js");

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
    if (user) res.status(401).json({ msg: "User already exist" });
    const hashedPassword = await hash(password, 10);

    fakeDB.push({
      id: fakeDB.length,
      username,
      email,
      password: hashedPassword,
    });
    // console.log({ user: fakeDB });
    res.json({ msg: "User Created", user: fakeDB });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // check if user exist in database
    const user = await fakeDB.find((user) => user.email === email);
    if (!user) res.status(401).json("User does not exist");
    // 2. compare crypted password
    const valid = await compare(password, user.password);
    if (!valid) res.status(401).json("User already exist");
    // 3. create refresh & accesstoken
    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    //4. put refreshtoken in the database
    user.refreshtoken = refreshtoken;
    console.log(fakeDB);
    // 5. send token: resfreshtoken as cookie & accesstoken as response
    sendRefreshToken(res, refreshtoken);
    sendAccessToken(req, res, accesstoken);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// 3. Logout user
app.post("/logout", (req, res) => {
  res.clearCookie("resfreshtoken");
  return res.send({ msg: "Logged out" });
});

// =============Server Port Running ==============
const port = process.env.PORT;

app.listen(port, () => {
  console.log(`Server on Port:${port}`);
});
