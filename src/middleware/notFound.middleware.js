/**
 * @copyright 2025 Payal Yadav
 * @license Apache-2.0
 */

import { StatusCodes } from "http-status-codes";

const notFound = (req, res) => {
  res.status(StatusCodes.NOT_FOUND).json({
    success: false,
    message: `Route not found`,
  });
};

export default notFound;
