# coding=utf-8

#
# Slack GMail Screener
#
# Get mentioned in Slack when you receive email from noteworthy senders; don't
# be bothered with the rest.
#

import BaseHTTPServer
import ConfigParser
from email import message_from_string
from email.header import decode_header
import httplib
import imaplib
import json
import oauth2 # <http://google-mail-oauth2-tools.googlecode.com/svn/trunk/python/oauth2.py>
import os
import os.path
import re
import threading
import time
import urllib

config = ConfigParser.SafeConfigParser()
config.read(os.path.expanduser('~/.slack-gmail-screener.cfg'))
if not config.has_section('google') or not config.has_section('slack'):
    print('Welcome to the Slack GMail Screener!  Let’s get you setup to be '
          'mentioned in Slack when you receive email from noteworthy senders.')
if not config.has_section('google'):
    config.add_section('google')
if not config.has_option('google', 'email'):
    print('')
    config.set('google', 'email', raw_input('What’s your email address? '))
if not config.has_option('google', 'client_id') or not config.has_option('google', 'client_secret'):
    print('')
    print('You need to visit this URL in your browser  to create a project '
          'and create a client ID and secret.  Don’t forget to visit the '
          '"Consent screen" page to name your project.')
    print('')
    print('https://console.developers.google.com/project')
if not config.has_option('google', 'client_id'):
    print('')
    config.set('google', 'client_id', raw_input('Client ID: '))
if not config.has_option('google', 'client_secret'):
    print('')
    config.set('google', 'client_secret', raw_input('Client secret: '))
if not config.has_option('google', 'refresh_token'):
    print('')
    print('Now visit this URL in your browser to authorize the Slack GMail '
          'Screener to check your email automatically.  Copy your '
          'authorization code and bring it back here.')
    print('')
    print(oauth2.GeneratePermissionUrl(config.get('google', 'client_id'),
                                       'https://mail.google.com/'))
    time.sleep(5)
    print('')
    authorization_code = raw_input('What’s your authorization code? ')
    response = oauth2.AuthorizeTokens(config.get('google', 'client_id'),
                                      config.get('google', 'client_secret'),
                                      authorization_code)
    config.set('google', 'refresh_token', response['refresh_token'])
if not config.has_section('slack'):
    config.add_section('slack')
if not config.has_option('slack', 'team'):
    print('')
    config.set('slack',
               'team',
               raw_input('What’s your Slack team called (in your Slack URL)? '))
if not config.has_option('slack', 'username'):
    print('')
    config.set('slack', 'username', raw_input('What’s your Slack username? '))
if not config.has_option('slack', 'token'):
    print('')
    print('Now visit this URL in your browser and generate an incoming '
          'webhook token.  Copy the token from the left column and bring it '
          'back here.')
    print('')
    print('https://tinyspeck.slack.com/services/new/incoming-webhook')
    time.sleep(5)
    print('')
    config.set('slack', 'token', raw_input('What’s your token? '))
if not config.has_section('slack-gmail-screener'):
    config.add_section('slack-gmail-screener')
if config.has_option('slack-gmail-screener', 'emails'):
    emails = set(config.get('slack-gmail-screener', 'emails').split(','))
else:
    emails = set()
with open(os.path.expanduser('~/.slack-gmail-screener.cfg'), 'w') as f:
    config.write(f)
print('')
print('Using configuration in ~/.slack-gmail-screener.cfg')

class HTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def _204(self):
        global config, emails # FIXME
        if len(emails) == 0:
            config.remove_option('slack-gmail-screener', 'emails')
        else:
            config.set('slack-gmail-screener', 'emails', ','.join(emails))
        with open(os.path.expanduser('~/.slack-gmail-screener.cfg'), 'w') as f:
            config.write(f)
        self.send_response(204)
        self.end_headers()

    def _400(self):
        self.send_response(400)
        self.end_headers()

    def _body(self):
        return self.rfile.read(int(self.headers['Content-Length']))

    def do_DELETE(self):
        global emails # FIXME
        emails.discard(self._body())
        self._204()

    def do_GET(self):
        global emails # FIXME
        body = ''.join(('%s\n' % email for email in emails))
        self.send_response(200)
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        global emails # FIXME
        email = self._body()
        if not re.match(r'^[^@]+@[^@]+$', email):
            self._400()
            return
        emails.add(email)
        self._204()

class IMAPThread(threading.Thread):

    def __init__(self, config, event):
        threading.Thread.__init__(self)
        self.config = config
        self.event = event

    def _authenticate(self, *args):
        return oauth2.GenerateOAuth2String(self.config.get('google',
                                                           'email'),
                                           self.access_token(),
                                           base64_encode=False)

    def _last_uid(self):
        ok, data = self.imap.select('INBOX')
        if ok != 'OK':
            raise Exception(ok)
        ok, data = self.imap.fetch(data[0], '(UID)')
        if ok != 'OK':
            raise Exception(ok)
        self.last_uid = re.search(r'^\d+ \(UID (\d+)\)$', data[0]).group(1)

    def access_token(self):
        print('Refreshing OAuth access token...')
        response = oauth2.RefreshToken(self.config.get('google', 'client_id'),
                                       self.config.get('google',
                                                       'client_secret'),
                                       self.config.get('google',
                                                       'refresh_token'))
        return response['access_token']

    def run(self):
        global emails # FIXME
        print('Connecting to imap.gmail.com...')
        self.imap = imaplib.IMAP4_SSL('imap.gmail.com')
        #self.imap.debug = 4
        self.imap.authenticate('XOAUTH2', self._authenticate)
        self._last_uid()
        print('Connected and waiting patiently for new mail!')
        if len(emails) > 0:
            print('Eagerly awaiting mail from %s.' % ', '.join(emails))
        while not self.event.is_set():
            self.event.wait(1) # XXX 60
            ok, data = self.imap.select('INBOX')
            if ok != 'OK':
                raise Exception(ok)
            ok, data = self.imap.uid('search',
                                     None,
                                     '(UID %s:*)' % self.last_uid)
            if ok != 'OK':
                raise Exception(ok)
            for uid in data[0].split():
                if uid == self.last_uid:
                    continue
                self.last_uid = uid
                ok, data = self.imap.uid('fetch',
                                         uid,
                                         '(BODY.PEEK[HEADER] BODY.PEEK[TEXT])')
                if ok != 'OK':
                    raise Exception(ok)
                message = ''
                for part in data:
                    if 'BODY[HEADER]' in part[0]:
                        message = part[1] + message
                    if 'BODY[TEXT]' in part[0]:
                        message = message + part[1]
                message = message_from_string(message)
                header = decode_header(message['From'])
                match = re.search('<([^>]+)>', header[0][0])
                if match is None:
                    print('DEBUG header[0][0]: %s' % header[0][0])
                    continue
                email = match.group(1)
                if email in emails:
                    print('DEBUG uid: %s' % uid)
                    slack_dm(message)

def slack_dm(message):
    global config # FIXME
    from_ = decode_header(message['From'])[0][0]
    subject = decode_header(message['Subject'])[0][0]
    text = '@%s:  You’ve got mail from %s!' % (config.get('slack', 'username'),
                                               from_)
    query = urllib.urlencode({'token': config.get('slack', 'token')})
    parts = []
    for part in message.walk():
        if part.get_content_type() == 'text/plain':
            parts.append(part.get_payload(decode=True).replace('\r\n', '\n'))
    if len(parts) == 0:
        parts = ['(nothing was `Content-Type: text/plain`)']
    body = '\n\n'.join(parts)
    attachment = {'fallback': subject,
                  'mrkdwn_in': ['text'],
                  'text': '*From:*  %s\n*Subject:*  %s\n\n%s' % (from_,
                                                                 subject,
                                                                 body)}
    payload = json.dumps({'attachments': [attachment],
                          'channel': '@%s' % config.get('slack', 'username'),
                          'icon_emoji': ':email:',
                          'text': text})
    print(payload)
    body = urllib.urlencode({'payload': payload})
    conn = httplib.HTTPSConnection('%s.slack.com' % config.get('slack',
                                                               'team'))
    conn.request('POST',
                 '/services/hooks/incoming-webhook?%s' % query,
                 body,
                 {'Content-Type': 'application/x-www-form-urlencoded'})
    response = conn.getresponse()
    body = response.read()
    if response.reason != 'OK' or body != 'ok':
        print('Slack responded "%s"; something might be amiss.' % body)
    conn.close()

if __name__ == '__main__':
    try:
        print('Listening on %s:%d...' % ('127.0.0.1', 48879)) # FIXME
        http_server = BaseHTTPServer.HTTPServer(('127.0.0.1', 48879), # FIXME
                                                HTTPHandler)
        http_thread = threading.Thread(target=http_server.serve_forever)
        http_thread.start()
        print('Listening and waiting to learn about noteworthy senders!')
        event = threading.Event()
        imap_thread = IMAPThread(config, event)
        imap_thread.start()
        while http_thread.is_alive() and imap_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print('')
        print('Exiting in response to SIGINT...')
    finally:
        event.set()
        http_server.shutdown()
    http_thread.join()
    imap_thread.join()
    print('Goodbye!')
