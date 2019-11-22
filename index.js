const core = require('@actions/core');
const github = require('@actions/github');
const nodemailer = require("nodemailer");
const smtps = require('./smtp-servers.json');

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

    if(!smtpServer){
        let smtp = authUser.match(/(?<=@)(.*)(?=\.)/g)[0];
        smtpServer = smtp.serverAddress;
        smtpServerPort= smtp.SSLPort
    }
    


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