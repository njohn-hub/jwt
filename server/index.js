import express from "express";
import bodyParser from "body-parser";
import Jwt from "jsonwebtoken";
import cors from "cors"

const app = express();
app.use(express.json());
app.use(bodyParser.json());
app.use(cors())

const users = [
  {
    id: "1",
    username: "john",
    password: "john4752",
    isAdmin: "true",
  },
  {
    id: "2",
    username: "jane",
    password: "jane4752",
    isAdmin: "false",
  },
];

let refreshTokens = [];

app.post("/refresh", (req, res) => {
  // take the token from the user
  const refreshToken = req.body.token;

  // no token // invalid token
  if (!refreshToken) return res.status(401).json("Not authenticated");
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json("Refresh token is invalid");
  }

  Jwt.verify(refreshToken, "refreshKey", (err, user) => {
    err && console.log(err);

    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
  // all is Well, create new token
});

const generateAccessToken = (user) => {
  return Jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "key", {
    expiresIn: "30m",
  });
};
const generateRefreshToken = (user) => {
  return Jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "refreshKey");
};

app.post("/users/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });

  if (user) {
    // access token

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);
    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
  } else {
    res.status(404).json("User not found");
  }
});

const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];

    Jwt.verify(token, "key", (err, data) => {
      if (err) {
        return res.status(403).json("Invalid token");
      }

      req.user = data;
      next();
    });
  } else {
    res.status(401).json("Not authenticated");
  }
};

app.post("/user/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(200).json("logged out successfully");
});

app.delete("/users/delete/:id", verify, (req, res) => {
  if (req.user.id === req.params.id || req.user.isAdmin) {
    res.status(200).json("User deleted");
  } else {
    res.status(403).json("Not allowed to delete this user");
  }
});

const PORT = 8003;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
