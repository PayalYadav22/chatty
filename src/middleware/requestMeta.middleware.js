import { v4 as uuidv4 } from "uuid";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const geoip = require("geoip-lite");

const attachRequestMeta = (req, res, next) => {
  req.id = uuidv4();

  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.ip;

  const geo = geoip.lookup(ip);
  req.geo = geo || {};

  next();
};

export default attachRequestMeta;
