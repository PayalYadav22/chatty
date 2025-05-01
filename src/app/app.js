import { Server } from "socket.io";
import http from "http";
import express from "express";
import helmet from "helmet";
import router from "../routes/routes.js";
import cookieParser from "cookie-parser";

const app = express();

app.use(helmet());

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

// X-XSS-Protection header (enabled and block mode)
app.use(helmet.xssFilter({ setOnOldIE: true }));

// Strict-Transport-Security header
app.use(
  helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true })
);

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: [
      "http://localhost:3000",
      "http://localhost:5173",
      "http://localhost:5000",
    ],
  },
});

app.use(cookieParser());

app.use(express.json());

app.use("/api/v1", router);

io.on("connection", (socket) => {
  logger.info(`${socket.id} user just connected`);

  socket.on("send_message", (data) => {
    logger.info("Message Received:", data);
    io.to(data.receiverId).emit("receive_message", data);
  });

  socket.on("join_room", (roomId) => {
    socket.join(roomId);
    logger.info(`User joined room ${roomId}`);
  });

  socket.on("disconnect", () => {
    logger.error("A user disconnected");
  });
});

export { app, server };
