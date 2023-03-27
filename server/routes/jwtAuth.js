const router = require("express").Router();
const pool = require("../db");
const bcrypt = require("bcrypt");
const jwtGen = require("../utils/jwtGen");
const validinfo = require("../middleware/validinfo");
const authorization = require("../middleware/authorization");

//registering
router.post("/register", validinfo, async (req, res) => {
  try {
    //1. Destructure the req.body(name, email, password)
    const { name, email, password } = req.body;
    //2. check if user exixts (if exist then throw error)

    const user = await pool.query("SELECT * FROM users WHERE user_email = $1", [
      email,
    ]);
    //401 is unauthenticated
    //403 is unauthorized
    //user.rows.length returns 0 if user not found
    //user.rows.length returns 1 if user found
    if (user.rows.length !== 0) {
      return res.status(401).send("User already exists");
    }
    //res.json(user.rows);
    //3. Bcrypt the new user password
    const saltRound = 10;
    const salt = await bcrypt.genSalt(saltRound);

    const bcryptPassword = await bcrypt.hash(password, salt);

    //4. Enter the new user inside our database
    const newUser = await pool.query(
      "INSERT INTO users (user_name, user_email, user_password) VALUES ($1, $2, $3) RETURNING *",
      [name, email, bcryptPassword]
    );
    //5. Generating our jwt token
    const token = jwtGen(newUser.rows[0].user_id);
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

//Login Route
router.post("/login", validinfo, async (req, res) => {
  try {
    //1. Destructure the req.body
    const { email, password } = req.body;
    //2. Check if user doesn't exist (if not then throw error)
    const user = await pool.query("SELECT * FROM users WHERE user_email = $1", [
      email,
    ]);
    //user.rows.length returns 0 if user not found
    //user.rows.length returns 1 if user found
    if (user.rows.length === 0) {
      return res.status(401).send("Email not found");
    }
    //3. Check if the incoming password is the same as database password
    const validPassword = await bcrypt.compare(
      password,
      user.rows[0].user_password
    );
    if (!validPassword) {
      return res.status(401).json("Password or email is incorrect");
    }
    //4. Give them jwt token
    const token = jwtGen(user.rows[0].user_id);
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

router.get("/is-verify", authorization, async (req, res) => {
  try {
    res.json(true);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

module.exports = router;
