const core = require('@actions/core');
const github = require('@actions/github');

try {
  const from = core.getInput('from');
  console.log(`Hello ${from}!`);


  const to = core.getInput('to');
  console.log(`Hello ${from}!`);

  const message = core.getInput('message');
  console.log(`Hello ${message}!`);

  const time = (new Date()).toTimeString();
  core.setOutput("time", time);
  
  const payload = JSON.stringify(github.context.payload, undefined, 2)
  console.log(`The event payload: ${payload}`);

} catch (error) {

  core.setFailed(error.message);

}