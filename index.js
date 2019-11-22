const core = require('@actions/core');
const github = require('@actions/github');
const nodemailer = require("nodemailer");

try {

    let smtpServer = core.getInput('smtp-server');
    let smtpServerPort = core.getInput('smtp-server-port');
    let authUser = core.getInput('auth-user');
    let authPassword = core.getInput('auth-password');
    let subject = core.getInput('subject');
    let body = core.getInput('body');
    let from = core.getInput('from');
    let reciver = core.getInput('to');
    let isTLS = core.getInput('tls');
    core.setOutput("smtpServer", smtpServer);
    core.setOutput("smtpServerPort", smtpServerPort);
    core.setOutput("authUser", authUser);
    core.setOutput("authPassword", authPassword);
    core.setOutput("subject", subject);
    core.setOutput("body", body);
    core.setOutput("from", from);
    core.setOutput("reciver", reciver);
    core.setOutput("isTLS", isTLS);
    let transporter = nodemailer.createTransport({
        host: smtpServer,
        port: smtpServerPort,
        secure: isTLS, 
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