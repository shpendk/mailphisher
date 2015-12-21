# mailphisher
## Description
This is a burp plugin written in python that will help detect email content injection vulnerabilities. If you don't know what an email content injection vulnerability looks like, please read the following (http://shpendk13.blogspot.nl/2015/12/email-content-html-injection.html)[blogpost]
The script checks all **requests** for the specified payload (see Configure below) and whenever it detects that you have sent it (yes you have to manually send it!) it will login to the configured email address and check the received emails for the payload. If it successfully detects the payload was sent to your email without being encoded, it'll raise a tenative report inside burp. 
-Warning: Make sure to use a test account as the script marks all emails it processes as read. 


## Installation
-Warning. See below how to configure the script before loading it.

This plugin requires jython to be configured inside burp. See (https://portswigger.net/burp/help/extender.html#options_pythonenv)[here] for more information on how to do that. Once jython is in place, go to Burp Extender and in the extensions tab, click "Add", select "Python" for the extension tab and find the script using "Select file". Click "next" and the you are ready to go. 

## Configure
The script needs to be configured with your email address, password and the imap hostname of your mail provider. You can set these values in the "constants" section at the top of the script. You can also chose the desired payload that will trigger the email lookup as mentioned in the description. note that it currently does **not** work with gmail, for google has some security settings which suck. Other providers should work fine


## Usage
As mentioned in the descriptin, you have to send the payload manually to trigger this plugin. The way i do it is by using the payload inside my XSS payload which i use to test XSS, as such i can catch this vulnerability on the way aswell.


## Version
This is just a script i hacked together and hasn't been tested thoroughly. It might miss some vulnerabilities and report some false positives. If you find a bug feel free to report it to me and i'll do my best to fix it

## The future
However time allows, i am going to implement some more features, do some proper testing and submit it to Burp to be included in their store. Features i would want to add:
-Allow multiple email accounts to be checked 
-Check emails only from @domains which are in scope
-Check only emails that come in later than when the injection was seen
-Active Scan: Ability to send request to mailphisher and it making injections and testing their validity
-Configuration UI: I hate to add another tab but i eventually will have to provide it for configuration. For now editing the script works.
