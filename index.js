const core = require('@actions/core');
const github = require('@actions/github');
const nodemailer = require("nodemailer");

try {
    const smtpServer = core.getInput('smtp-server');
    const smtpServerPort = core.getInput('smtp-server-port');
    const authUser = core.getInput('auth-user');
    const authPassword = core.getInput('auth-password');
    const subject = core.getInput('subject');
    const body = core.getInput('body');
    const from = core.getInput('from');
    const reciver = core.getInput('to');
    const isTLS = core.getInput('tls');

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