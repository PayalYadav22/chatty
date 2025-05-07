import { Server } from "socket.io";
import http from "http";
import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import session from "express-session";
import router from "../routes/routes.js";
import MongoStore from "connect-mongo";
import attachRequestMeta from "../middleware/requestMeta.middleware.js";
import notFound from "../middleware/notFound.middleware.js";
import errorHandler from "../middleware/errorHandler.middleware.js";
import { SessionSecretKey, mongoUrl, options } from "../constants/constant.js";

const app = express();
const server = http.createServer(app);

// Set security-related HTTP headers
app.use(helmet());

// Parse cookies before session middleware
app.use(cookieParser());

// Session middleware (after cookieParser)
app.use(
  session({
    secret: SessionSecretKey,
    resave: false,
    store: MongoStore.create({
      mongoUrl: mongoUrl,
      collectionName: "sessions",
      ttl: 60 * 60 * 24,
    }),
    saveUninitialized: false,
    cookie: options,
  })
);

// Optional: Custom Content Security Policy
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https://example.com"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);

// HSTS (Strict Transport Security)
app.use(
  helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true })
);

// Attach request metadata
app.use(attachRequestMeta);

// Parse JSON request bodies
app.use(express.json());

// Your API routes
app.use("/api/v1", router);

app.use(notFound);
app.use(errorHandler);

// Setup Socket.io with CORS
const io = new Server(server, {
  cors: {
    origin: [
      "http://localhost:3000",
      "http://localhost:5173",
      "http://localhost:5000",
    ],
    credentials: true, // If using cookies
  },
});

// Socket.io Events
io.on("connection", (socket) => {
  console.log(`${socket.id} user just connected`);

  socket.on("send_message", (data) => {
    console.log("Message Received:", data);
    io.to(data.receiverId).emit("receive_message", data);
  });

  socket.on("join_room", (roomId) => {
    socket.join(roomId);
    console.log(`User joined room ${roomId}`);
  });

  socket.on("disconnect", () => {
    console.log("A user disconnected");
  });
});

export { app, server };
