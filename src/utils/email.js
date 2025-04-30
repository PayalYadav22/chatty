/**
 * @copyright 2025 Payal Yadav
 * @license Apache-2.0
 */

import nodemailer from "nodemailer";
import hbs from "nodemailer-express-handlebars";
import path from "path";
import { fileURLToPath } from "url";
import { emailId, emailPassword } from "../constants/constant.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: emailId,
    pass: emailPassword,
  },
});

// Configure handlebars
const handlebarOptions = {
  viewEngine: {
    extName: ".hbs",
    partialsDir: path.join(__dirname, "../../src/emails"),
    defaultLayout: false,
  },
  viewPath: path.join(__dirname, "../../src/emails"),
  extName: ".hbs",
};

transporter.use("compile", hbs(handlebarOptions));

const sendEmail = async ({ to, subject, template, context, attachments }) => {
  try {
    if (!to) throw new Error("Recipient email address (to) is required");
    if (!subject) throw new Error("Email subject is required");
    if (!template) throw new Error("Template name is required");

    const mailOptions = {
      from: `"Your App Name" <${emailId}>`,
      to: Array.isArray(to) ? to : [to],
      subject,
      template,
      context,
      attachments: attachments || [],
    };

    const info = await transporter.sendMail(mailOptions);
    return info;
  } catch (error) {
    console.error("Error sending email:", error);
    throw error;
  }
};

export default sendEmail;
