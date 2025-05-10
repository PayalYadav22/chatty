// ==============================
// External Packages
// ==============================
import express from "express";

// ==============================
// Controllers
// ==============================
import GroupController from "../../controllers/group/group.controller";

// ==============================
// Middlewares
// ==============================
import authMiddleware from "../../middleware/auth/authMiddleware.middleware";

// ==============================
// Constant Routes
// ==============================
const router = express.Router();

// ==============================
// Secure Routes
// ==============================
router.use(authMiddleware);

/**
 * @route   /api/groups/
 * @desc    Create a new group, get all groups, update group, or delete group
 * @access  Varies (authenticated required)
 */
router
  .route("/")
  .post(GroupController.createGroup)
  .get(GroupController.getGroups)
  .put(GroupController.updateGroup)
  .delete(GroupController.deleteGroup);

/**
 * @route   /api/groups/join
 * @desc    Join a group
 * @access  Authenticated
 */
router.route("/join").post(GroupController.joinGroup);

/**
 * @route   /api/groups/leave
 * @desc    Leave a group
 * @access  Authenticated
 */
router.route("/leave").post(GroupController.leaveGroup);

/**
 * @route   /api/groups/:id
 * @desc    Get details of a specific group by ID
 * @access  Authenticated
 */
router.route("/:id").get(GroupController.getGroupById);

/**
 * @route   /api/groups/:id/messages
 * @desc    Get all messages in a group / Send a message to a group
 * @access  Authenticated
 */
router
  .route("/:id/messages")
  .get(GroupController.getGroupMessages)
  .post(GroupController.sendGroupMessage);

/**
 * @route   /api/groups/:id/add
 * @desc    Add users to the group
 * @access  Group Owner/Admin
 */
router.route("/:id/add").post(GroupController.addUsers);

/**
 * @route   /api/groups/:id/remove
 * @desc    Remove users from the group
 * @access  Group Owner/Admin
 */
router.route("/:id/remove").delete(GroupController.removeUsers);

/**
 * @route   /api/groups/:id/invite
 * @desc    Invite users to the group
 * @access  Group Owner/Admin
 */
router.route("/:id/invite").patch(GroupController.inviteUsers);

/**
 * @route   /api/groups/:id/roles
 * @desc    Update roles of group members
 * @access  Group Owner/Admin
 */
router.patch("/:id/roles").post(GroupController.updateGroupRoles);

/**
 * @route   /api/groups/:id/settings
 * @desc    Update group settings
 * @access  Group Owner/Admin
 */
router.patch("/:id/settings").post(GroupController.updateGroupSettings);
