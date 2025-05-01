import { Server } from "socket.io";
import http from "http";
import express from "express";
import helmet from "helmet";
import router from "../routes/routes.js";
import cookieParser from "cookie-parser";

const app = express();

app.use(helmet());

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
