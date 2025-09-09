import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import { redis } from "../lib/redis.js";

const generateTokens = (userid) => {
  const accessToken = jwt.sign({ userid }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign({ userid }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });
  return { accessToken, refreshToken };
};

const saveRefreshToken = async (userid, refreshToken) => {
  await redis.set(
    `refresh_token:${userid}`,
    refreshToken,
    "EX",
    7 * 24 * 60 * 60 //expires in 7 days
  );
};

const setCookies = (res, accessToken, refreshToken) => {
  res.cookie("accessToken", accessToken, {
    httpOnly: true, //prevent xss attack- cross site script attack.
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict", //prevent csrf attack- cross site request forgery attack.
    maxAge: 15 * 60 * 1000, //15 minutes
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true, //prevent xss attack- cross site script attack.
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict", //prevent csrf attack- cross site request forgery attack.
    maxAge: 7 * 24 * 60 * 60 * 1000, //7 days
  });
};

export const signup = async (req, res) => {
  let { email, password, name } = req.body;

  try {
    let userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already existed" });
    }

    const user = await User.create({ name, email, password });
    const { accessToken, refreshToken } = generateTokens(user._id);
    await saveRefreshToken(user._id, refreshToken);
    setCookies(res, accessToken, refreshToken);

    res.status(200).json({
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      message: "User created Successfully",
    });
  } catch (error) {
    console.error("Error during Signup: ", error.message);
    res.status(500).json({ message: error.message });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && (await user.comparePassword(password))) {
      //comparePassword method is defined in user.model.js
      const { accessToken, refreshToken } = generateTokens(user._id);
      await saveRefreshToken(`refreshToken:${user._id}`, refreshToken);
      setCookies(res, accessToken, refreshToken);

      res.status(200).json({
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        message: "Logged-in Successfully",
      });
    } else {
      res.status(400).json({ message: "Wrong Credentials" });
    }
  } catch (error) {
    console.error("Error during Login: ", error.message);
    res.status(500).json({ message: error.message });
  }
};

export const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      const decoded = jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET
      );
      await redis.del(`refresh_token:${decoded.userid}`);
    }

    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
    });
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
    });

    res.json({ message: "Logged out Successfully" });
  } catch (error) {
    console.error("Error during Logout: ", error.message);
    res.status(500).json({ message: error.message });
  }
};
