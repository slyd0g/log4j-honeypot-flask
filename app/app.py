from flask import Flask, redirect, url_for, request
import requests
import json
import os
from log4shell_regexes import *


tt = lambda s: [(k, list(v.keys())) for k, v in test_thorough(s).items()]
#### Set your Slack or Teams or Mattermost webhook here, or in environment variable WEBHOOK_URL ####
webhook_url = "<FILL_ME_IN>"
# For help setting up the webhook, see:
# Slack: https://api.slack.com/messaging/webhooks
# Teams: https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook
# Mattermost: https://docs.mattermost.com/developer/webhooks-incoming.html

#### Set the name of this honeypot instance here, or in environment variable HONEYPOT_NAME ####
# (use a descriptive name so you know when alerts come in where they were triggered)
honeypot_name = "My log4j honeypot"

#### Set the port you want this honeypot to listen on. Recommend 8080 or 80
#### you can also use environment variable HONEYPOT_PORT
honeypot_port = 8080

if "HONEYPOT_NAME" in os.environ and os.environ["HONEYPOT_NAME"].strip() != "":
    honeypot_name = os.environ["HONEYPOT_NAME"]

if "WEBHOOK_URL" in os.environ and os.environ["WEBHOOK_URL"].strip() != "":
    webhook_url = os.environ["WEBHOOK_URL"].strip()

if "HONEYPOT_PORT" in os.environ and os.environ["HONEYPOT_PORT"].strip() != "":
    try:
        honeypot_port = int(os.environ["HONEYPOT_PORT"].strip())
    except:
        print("Invalid port: " + os.environ["HONEYPOT_PORT"])
        print("Reverting to port 8080 default")
        honeypot_port = 8080

app = Flask(__name__)

def reportHit(request, regex):

    message = "Suspicious request received from IP: " + request.remote_addr + "\n"
    message += "Regex hit: " + str(regex) + "\n"
    message += "Refer to https://gist.github.com/karanlyons/8635587fd4fa5ddb4071cc44bb497ab6#file-usage-md for regex info\n"
    message += "Review HTTP headers for payloads:" + "\n"
    for header in request.headers:
        message += "    " + str(header) + "\n"
    for fieldname, value in request.form.items():
        message += "Review body for payloads:\n"
        message += "    " + str((fieldname, value)) + "\n"
    response = requests.post(
        webhook_url, data=message,
        headers={'Authorization': '<FILL_ME_IN>'}
    )
    if response.status_code != 200:
        print('Request to webhook returned an error %s, the response is:\n%s' % (response.status_code, response.text))

login_form = """<html>
<head><title>Secure Area Login</title></head>
<body>
<h1>Log in to Secure Area</h1>
<form method='post' action='/'>
  <b>Username:</b> <input name='username' type='text'/><br/>
  <b>Password:</b> <input name='password' type='password'/><br/>
  <input type='submit' name='submit'/>
</form>
</body></html>"""

@app.route("/", methods=['POST','GET','PUT','DELETE'])
def homepage():
    for header in request.headers:
        print(header)
        if tt(str(header)):
            regex = tt(str(header))
            reportHit(request, regex)
    if request.method == 'POST':
        for fieldname, value in request.form.items():
            if tt(str(value)):
                regex = tt(str(value))
                reportHit(request, regex)
            if tt(str(fieldname)):
                regex = tt(str(fieldname))
                reportHit(request, regex)
        return("<html><head><title>Login Failed</title></head><body><h1>Login Failed</h1><br/><a href='/'>Try again</a></body></html>")
    else:
        return(login_form)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=honeypot_port)
