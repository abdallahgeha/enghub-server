const router = require("express").Router();
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const auth = require("../middleware/auth");
const bcrypt = require("bcryptjs");

router.get("/test", (req, res) => {
  return res.send("hello test working");
});

router.post("/register", async (req, res) => {
  try {
    let { email, password, passwordCheck, userName } = req.body;
    if (!email || !password || !passwordCheck) {
      return res.status(400).json({ msg: "Not all fields have been entered" });
    }
    if (password.length < 5) {
      return res
        .status(400)
        .json({ msg: "the Password needs to be longer than 5 char" });
    }
    if (password !== passwordCheck) {
      return res
        .status(400)
        .json({ msg: "Enter the same password twice for verification" });
    }

    const existingUser = await User.findOne({ email: email });

    if (existingUser) {
      return res
        .status(400)
        .json({ msg: "account with this email already exist " });
    }

    if (!userName) {
      userName = email;
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = new User({
      email,
      password: passwordHash,
      userName,
    });

    const savedUser = await newUser.save();

    res.json(savedUser);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ msg: "Not all fields have been enetered" });
    }

    const user = await User.findOne({ email: email });

    if (!user) {
      return res
        .status(400)
        .json({ msg: "No account with this email has been registered" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid logn Data" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({
      token,
      user: {
        id: user._id,
        userName: user.userName,
        email: user.email,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.delete("/delete", auth, async (req, res) => {
  try {
    const deletedUser =  await User.findByIdAndDelete(req.user);
    res.json(deletedUser)
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/tokenIsValid", async (req,res) => {
  try {
    const AuthHeader = req.header("Authorization") || '';
    const token = AuthHeader.split(" ")[1];
    if(!token) {
      return res.json(false);
    }
    const verified = jwt.verify(token, process.env.JWT_SECRET)
    if(!verified){
      return res.json(false);
    }
    const user = await User.findById(verified.id);
    if(!user){
      return res.json(false);
    }

    return res.json(true)
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
})

module.exports = router;
