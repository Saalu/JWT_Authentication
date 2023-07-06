require("dotenv/config");

const express = require("express");
const { bcrypt, hash } = require("jsonwebtoken");

const app = express();

app.use(express.json());

app.get("/", (req, res) => {
  res.send("Welcome home");
  console.log({ msg: "Welcome home" });
});

const port = process.env.PORT;

app.listen(port, () => {
  console.log(`Server on Port:${port}`);
});
