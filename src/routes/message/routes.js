import express from "express";
import MessageController from "../../controllers/message/message.controller.js";
import upload from "../../middleware/multer.middleware.js";

const router = express.Router();

// ==============================
// Route: /api/messages/
// Description: Handles message listing and creation
// ==============================
router
  .route("/")
  // GET: Fetch paginated conversation between users
  .get(MessageController.getMessage)
  // POST: Send a new message with optional image/video attachments
  .post(
    upload.fields([{ name: "image" }, { name: "video" }]),
    MessageController.sendMessage
  );

// ==============================
// Route: /api/messages/search
// Description: Search through messages
// ==============================
router.route("/search").get(MessageController.searchMessages);

// ==============================
// Route: /api/messages/unseen
// Description: Fetch unseen messages for the authenticated user
// ==============================
router.route("/unseen").get(MessageController.getUnseenMessages);

// ==============================
// Route: /api/messages/forward
// Description: Forward an existing message to another user
// ==============================
router.route("/forward").get(MessageController.forwardMessage);

// ==============================
// Route: /api/messages/react
// Description: Add or update emoji reaction to a message
// ==============================
router.route("/react").get(MessageController.reactToMessage);

// ==============================
// Route: /api/messages/:id
// Description: Update or delete a specific message
// ==============================
router
  .route("/:id")
  // PATCH: Update message content
  .patch(MessageController.updateMessageContent)
  // DELETE: Soft delete a message
  .delete(MessageController.deleteMessage);

// ==============================
// Route: /api/messages/:messageId
// Description: Pin or unpin a message (duplicate route needs fixing)
// ==============================
router
  .route("/:messageId")
  .patch(MessageController.pinMessage)
  .patch(MessageController.unpinMessage); // ⚠️ Issue: Only one .patch is allowed per route method!

// ==============================
// Route: /api/messages/seen/:id
// ==============================
router.route("/seen/:id").get(MessageController.markAsSeen);

// ==============================
// Route: /api/messages/:messageId/label
// ==============================
router
  .route("/:messageId/label")
  .get(MessageController.labelMessage)
  .delete(MessageController.removeLabelMessage);

export default router;
