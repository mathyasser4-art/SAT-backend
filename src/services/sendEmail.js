const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    // TODO: replace `user` and `pass` values from <https://forwardemail.net>
    user: process.env.SENDEREMAIL ,
    pass: process.env.PASSWORD
  },
  // Give up on a dead mail server in seconds instead of minutes
  connectionTimeout: 15000,
  greetingTimeout: 15000,
  socketTimeout: 30000
});

// Callers send emails without waiting for them, so this must never throw: a failed send
// (wrong Gmail credentials, quota, bad address) used to crash the whole server.
const sendEmail = async (sendTo, message, subject, senderName) =>  {
  try {
    await transporter.sendMail({
      from: {
          name: senderName,
          address: process.env.SENDEREMAIL
      },
      to: sendTo , // list of receivers
      subject, // Subject line
      html: message , // html body
    });
    return true;
  } catch (error) {
    console.error(`sendEmail to ${sendTo} failed:`, error.message);
    return false;
  }
}

module.exports = sendEmail