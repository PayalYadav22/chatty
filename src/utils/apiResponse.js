/**
 * @copyright 2025 Payal Yadav
 * @license Apache-2.0
 * @description Standardized API response formatter
 */

class ApiResponse {
  constructor(statusCode, data, message = "Success", metadata = {}) {
    this.statusCode = statusCode;
    this.data = data;
    this.message = message;
    this.success = statusCode < 400;
    this.metadata = metadata;
  }

  send(res) {
    return res.status(this.statusCode).json({
      success: this.success,
      message: this.message,
      data: this.data,
      ...(Object.keys(this.metadata).length && { meta: this.metadata }),
    });
  }
}

export default ApiResponse;
