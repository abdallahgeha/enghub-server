const jwt = require("jsonwebtoken");

const auth = async (req, res, next) => {
  try {
    const AuthHeader = req.header("Authorization") || '';
    const token = AuthHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ msg: "No auth, authorization denied" });
    }

    const verified = jwt.verify(token, process.env.JWT_SECRET);
    if(!verified) {
      return res.status(401).json({ msg: "token bad, authorization denied" });
    }

    req.user = verified.id;
    next();
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};

module.exports = auth
