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
    let isCommitMessage = core.getInput('commit-message');


    let transporter = nodemailer.createTransport({
        host: smtpServer,
        port: smtpServerPort,
        secure: isTLS, 
        auth: {
            user: authUser,
            pass: authPassword
        }
    });

    if(isCommitMessage){
        let payload = github.context.payload;
        let commits = payload.pull_request._links.commits;
        console.log(commits);

        var commitMessages=commits
        .map(a=>  a.message )
        .reduce((a,b)=>"* "+ a.message + "\n" + "* "+ b.message);

        body = commitMessages;
        console.log(commitMessages);
    }
    var message = {
        from,
        to: reciver,
        subject,
        text: body,
    };

    transporter.sendMail(message).then(function(res){
        core.setOutput("response", message);
    }).catch(function(error){
        core.setOutput("error", message);
    });

  const time = (new Date()).toTimeString();
  core.setOutput("time", time);

} catch (error) {

  core.setFailed(error.message);

}