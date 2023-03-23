const Pool = require("pg").Pool;

const pool = new Pool({
  user: "yahya",
  host: "localhost",
  port: 5432,
  database: "jwtlogin",
});

module.exports = pool;
