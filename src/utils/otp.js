/**
 * @copyright 2025 Payal Yadav
 * @license Apache-2.0
 */

import otpGenerator from "otp-generator";

const generateOTP = () => {
  const optGenerator = otpGenerator.generate(6, {
    upperCase: false,
    specialChars: false,
    digits: true,
  });
  return optGenerator;
};

export default generateOTP;
