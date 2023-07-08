require("dotenv/config");

const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { compare, hash } = require("bcrypt");
const cookieParser = require("cookie-parser");
const { isAuth } = require("./src/isAuth.js");
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
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

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
  res.clearCookie("resfreshtoken", { path: "/refresh_token" });
  return res.send({ msg: "Logged out" });
});

//4. Protected routes
app.post("/protected", async (req, res) => {
  try {
    const userId = isAuth(req, res);
    if (userId !== null) {
      res.send({ msg: "This is protected data" });
    }
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

//5. Get a new access token with refresh token
app.post("/refresh_token", async (req, res) => {
  const token = req.cookies.refreshtoken;
  // if no token, request our token
  if (!token) return res.send({ accesstoken: "" });
  // we have a token, verify it
  let payload = null;

  try {
    payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch (err) {
    return res.status(500).json({ accesstoken: "" });
  }

  // Token is valid, check if user exist
  const user = fakeDB.find((user) => user.id === payload.userId);
  if (!user) return res.send({ accesstoken: "" });
  // user exist, check if refreshtoken exist on user
  if (user.refreshtoken !== token) {
    return res.send({ accesstoken: "" });
  }
  // Token exist, create new refresh and accesstoken
  const accesstoken = createAccessToken(user.id);
  const refreshtoken = createRefreshToken(user.id);
  user.refreshtoken = refreshtoken;

  sendRefreshToken(res, refreshtoken);
  return res.send({ accesstoken });
});
// =============Server Port Running ==============
const port = process.env.PORT;

app.listen(port, () => {
  console.log(`Server on Port:${port}`);
});
