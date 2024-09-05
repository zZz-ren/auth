const express = require("express");
const bcrypt = require("bcryptjs");
const Datastore = require("nedb-promises");
const jwt = require("jsonwebtoken");
const qrcode = require("qrcode");
const { authenticator } = require("otplib");
const NodeCache = require("node-cache");

let app = express();

app.use(express.json());

const users = Datastore.create("Users.db");
const cache = new NodeCache();
const refreshTokens = Datastore.create("rt.db");
const invalidTokens = Datastore.create("invalid.db");
const accessTokenSecret = "SecretTokensecret";
const refreshTokenSecret = "RefreshSecretTokensecretRefresh";

app.get("/", (req, res) => {
  res.send("Working");
});

app.get("/auth/2fa/generate", ensureAuthenticated, async (req, res) => {
  try {
    const user = await users.findOne({ _id: req.user.id });

    const secret = authenticator.generateSecret();
    const url = authenticator.keyuri(user.email, "manfra.io", secret);

    const isupdate = await users.update(
      { _id: user._id },
      { $set: { "2fasecret": secret } }
    );
    await users.compactDatafile();
    console.log("dede", secret, isupdate);

    const qrCode = await qrcode.toBuffer(url, {
      type: "png",
      margin: 1,
    });

    res.setHeader("Content-Disposition", "attachment; filename=qrcode.png");
    res.status(200).type("image/png").send(qrCode);
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.post("/auth/2fa/validate", ensureAuthenticated, async (req, res) => {
  try {
    const { totp } = req.body;

    if (!totp) {
      return res.status(422).json({ message: "TOTP is required  " });
    }

    const user = await users.findOne({ _id: req.user.id });
    console.log(user);

    const verified = authenticator.check(totp, user["2fasecret"]);

    if (!verified) {
      return res.status(400).json({ message: "TOTP is invalid" });
    }

    await users.update({ _id: req.user.id }, { $set: { "2faEnable": true } });
    await users.compactDatafile();

    return res.status(200).json({ message: "Verified Successfully" });
  } catch (error) {
    console.log(error);

    return res.status(500).json({ message: error.message });
  }
});

app.post("/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      throw new Error("Please fill all the fields");
    }

    if (await users.findOne({ email })) {
      return res.status(409).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await users.insert({
      name,
      email,
      password: hashedPassword,
      role: role ?? "member",
      "2fasecret": null,
      "2faEnable": false,
    });
    res.status(201).json({ newUser });
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      throw new Error("Please fill all the fields");
    }

    const user = await users.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: "Email doesnt exists" });
    }

    const passwordmatch = await bcrypt.compare(password, user.password);

    if (!passwordmatch) {
      return res.status(401).json({ message: "PAssword doesnt match" });
    }

    if (user["2faEnable"]) {
      const tempToken = crypto.randomUUID();

      cache.set("temp_token:" + tempToken, user._id, 10);

      return res.status(200).json({ tempToken, expireIn: 10 });
    } else {
      const accessToken = jwt.sign({ userId: user._id }, accessTokenSecret, {
        subject: "accessApi",
        expiresIn: "30m",
      });

      const refreshToken = jwt.sign({ userId: user._id }, refreshTokenSecret, {
        subject: "refreshToken",
        expiresIn: "1w",
      });

      const refreshedToekn = await refreshTokens.insert({
        refreshToken,
        userId: user._id,
      });

      res.status(200).json({
        id: user._id,
        name: user.name,
        email: user.email,
        accessToken,
        refreshToken,
      });
    }
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
});

app.post("/auth/login/2fa", async (req, res) => {
  try {
    const { tempToken, totp } = req.body;

    if (!tempToken || !totp) {
      return res.status(422).json({ message: "Please fill all the fileds" });
    }

    const userId = cache.get("temp_token:" + tempToken);

    if (!userId) {
      return res
        .status(401)
        .json({ message: "Temporary token is invalid or expired" });
    }

    const user = await users.findOne({ _id: userId });

    const verified = authenticator.check(totp, user["2fasecret"]);

    if (!verified) {
      return res
        .status(401)
        .json({ message: "the provided otp is invalid or expired" });
    }

    const accessToken = jwt.sign({ userId: user._id }, accessTokenSecret, {
      subject: "accessApi",
      expiresIn: "30m",
    });

    const refreshToken = jwt.sign({ userId: user._id }, refreshTokenSecret, {
      subject: "refreshToken",
      expiresIn: "1w",
    });

    const refreshedToekn = await refreshTokens.insert({
      refreshToken,
      userId: user._id,
    });

    res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
});

app.post("/auth/logout", ensureAuthenticated, async (req, res) => {
  try {
    await refreshTokens.removeMany({ userId: req.user.id });
    await refreshTokens.compactDatafile();

    await invalidTokens.insert({
      userID: req.user.id,
      accessToken: req.accessToken.value,
      expirationTime: req.accessToken.exp,
    });

    res.status(200).send();
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.post("/auth/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token not found" });
    }

    const decodedRefreshToken = jwt.verify(refreshToken, refreshTokenSecret);

    const userRefreshToken = await refreshTokens.findOne({
      refreshToken,
      userId: decodedRefreshToken.userId,
    });
    if (!userRefreshToken) {
      return res.status(500).json({
        error: "Refresh Token Invalid or Expired ",
      });
    }

    await refreshTokens.remove({ userId: decodedRefreshToken.userId });
    await refreshTokens.compactDatafile();

    const accessToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      accessTokenSecret,
      {
        subject: "accessApi",
        expiresIn: "30m",
      }
    );

    const newRefreshToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      refreshTokenSecret,
      {
        subject: "refreshToken",
        expiresIn: "1w",
      }
    );

    await refreshTokens.insert({
      userId: decodedRefreshToken.userId,
      refreshToken: newRefreshToken,
    });
    return res.status(200).json({
      userId: decodedRefreshToken.userId,
      accessToken,
      newRefreshToken,
    });
  } catch (error) {
    if (
      error instanceof jwt.JsonWebTokenError ||
      error instanceof jwt.TokenExpiredError
    ) {
      return res.status(500).json({
        error: "Refresh Token Invalid or Expired ",
      });
    }
  }
});

app.get("/users/current", ensureAuthenticated, async (req, res) => {
  try {
    const user = await users.findOne({ _id: req.user.id });
    res.status(200).json(user);
  } catch (error) {
    return res.status(500).json({ message: "Server Error" });
  }
});

app.get(
  "/admin/current",
  ensureAuthenticated,
  authorized(["admin"]),
  async (req, res) => {
    try {
      const user = await users.findOne({ _id: req.user.id });
      res.status(200).json(user);
    } catch (error) {
      return res.status(500).json({ message: "Server Error" });
    }
  }
);

function authorized(role = []) {
  return async function (req, res, next) {
    const user = await users.findOne({ _id: req.user.id });
    if (!user || !role.includes(user.role)) {
      return res.status(403).json({ message: "Access Denied " });
    }
    next();
  };
}

async function ensureAuthenticated(req, res, next) {
  const accessToken = req.headers.authorization;

  if (!accessToken) {
    return res.status(401).json({ message: "API not sauthorizzed" });
  }

  if (await invalidTokens.findOne({ accessToken })) {
    return res.status(500).json({
      error: "Access Token Invalid or Expired ",
    });
  }
  try {
    const decodedAccessToken = jwt.verify(accessToken, accessTokenSecret);

    req.accessToken = { value: accessToken, exp: decodedAccessToken.exp };
    req.user = { id: decodedAccessToken.userId };
    next();
  } catch (error) {
    return res.status(401).json({ message: "API not sauthorizzed" });
  }
}

app.listen(3000, console.log("EWorking!!"));
