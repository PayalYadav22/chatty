import "./config/env.config.js";
import { server } from "./app/app.js";
import connectDB from "./config/db.config.js";
import { port, mongoUrl, mongoDb } from "./constants/constant.js";
import logger from "./logger/logger.js";

connectDB(mongoUrl, mongoDb)
  .then(() => {
    server.listen(port, () => {
      logger.info(`Server is running on port ${port}...`);
    });
  })
  .catch((error) => {
    logger.error(error);
    process.exit(1);
  });
