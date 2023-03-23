const router = require("express").Router();
const pool = require("../db");
const bcrypt = require("bcrypt");
const jwtGen = require("../utils/jwtGen");

//registering
router.post("/register", async (req, res) => {
  try {
    //1. Destructure the req.body(name, email, password)
    const { name, email, password } = req.body;
    //2. check if user exixts (if exist then throw error)

    const user = await pool.query("SELECT * FROM users WHERE user_email = $1", [
      email,
    ]);
    //401 is unauthenticated
    //403 is unauthorized
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

module.exports = router;
