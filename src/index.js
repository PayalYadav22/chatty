import "./config/env.config.js";
import { server } from "./app/app.js";
import connectDB from "./config/db.config.js";
import { port, mongoUrl, mongoDb } from "./constants/constant.js";

connectDB(mongoUrl, mongoDb)
  .then(() => {
    server.listen(port, () => {
      console.log(`Server is running on port ${port}...`);
    });
  })
  .catch((error) => {
    console.log(error);
    process.exit(1);
  });
