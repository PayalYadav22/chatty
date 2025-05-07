import { config } from "dotenv";

config({ path: "./.env" });

const currentEnv = process.env.NODE_ENV || "development";

if (currentEnv === "test") {
  config({ path: "./.env.test", override: true });
}

export default process.env;
