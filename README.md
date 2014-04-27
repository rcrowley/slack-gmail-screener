Slack GMail Screener
--------------------

Get mentioned in Slack when you receive email from noteworthy senders; don't be bothered with the rest.

Usage
-----

```sh
bin/slack-gmail-screener
```

It'll have lots of questions for you.  Don't worry, you'll only have to answer them the first time; afterwards they'll be stored in `~/.slack-gmail-screener.cfg`.

Once it's running, you can manage the list of noteworthy senders:

```sh
bin/slack-gmail-screener-ls
```

```sh
bin/slack-gmail-screener-add "example@example.com"
```

```sh
bin/slack-gmail-screener-rm "example@example.com"
```

You'll be notified in Slack anytime you receive email from one of the noteworthy senders.

TODO
----

* Slack outgoing webhook for adding, removing, and listing noteworthy email addresses.
* Non-GMail IMAP support.
* Options for changing the HTTP listener.

TODONE
------

* Guided setup of Google OAuth client and Slack incoming webhook.
* IMAP client for receiving new mail.
* Slack incoming webhook for notifying you in Slack.
* HTTP API for adding, removing, and listing noteworthy email addresses.
* Command-line tools for adding, removing, and listing noteworthy email addresses.
