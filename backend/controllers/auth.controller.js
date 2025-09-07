import User from "../models/user.model.js";

export const signup = async (req, res) => {
  let { email, password, name } = req.body;
  try {
    let userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already existed" });
    }

    const user = await User.create({ name, email, password });
    res.status(200).json(user, { message: "User created Successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const login = async (req, res) => {};

export const logout = async (req, res) => {};
