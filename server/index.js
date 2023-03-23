const express = require("express");
const app = express();
const cors = require("cors");

//middleware
app.use(express.json()); //req.body
app.use(cors());

//ROUTES//

//Register and login route
app.use("/auth", require("./routes/jwtAuth"));

app.listen(4000, () => {
  console.log("Server is running on 4000");
});
