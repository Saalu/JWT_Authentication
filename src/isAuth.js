const { verify } = require("jsonwebtoken");

const isAuth = (req, res) => {
  const token = req.header("Authorization");
  if (!token) res.status(401).json({ msg: "You need to login" });
  //   //   const token = authorization.split(" ")[1];
  const { userId } = verify(token, process.env.ACCESS_TOKEN_SECRET);

  return userId;
};

module.exports = { isAuth };
