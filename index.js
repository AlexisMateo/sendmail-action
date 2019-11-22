const core = require('@actions/core');
const github = require('@actions/github');
const nodemailer = require("nodemailer");

try {
    const smtpServer = core.getInput('smtpserver');
    const smtpServerPort = core.getInput('smtpServerPort');
    const authUser = core.getInput('authUser');
    const authPassword = core.getInput('authPassword');
    const subject = core.getInput('subject');
    const body = core.getInput('body');
    const from = core.getInput('from');
    const isTLS = core.getInput('tls');
    const reciver = core.getInput('to');

    let transporter = nodemailer.createTransport({
        host: smtpServer,
        port: smtpServerPort,
        secure: isTLS, // upgrade later with STARTTLS
        auth: {
            user: authUser,
            pass: authPassword
        }
    });

    var message = {
        from,
        to: reciver,
        subject,
        text: body,
    };


    transporter.sendMail(message)

  const time = (new Date()).toTimeString();
  core.setOutput("time", time);

} catch (error) {

  core.setFailed(error.message);

}