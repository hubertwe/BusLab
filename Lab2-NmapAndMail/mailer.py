#!/usr/bin/python

import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
import sys
import argparse
import socket

## Send e-mail
def send(sender='', fakeSender='', to='', subject='', text='', serverAddr='mail.pwr.wroc.pl'):
    message = MIMEMultipart()
    message['From'] = fakeSender
    message['To'] = to
    message['Subject'] = subject
    message.attach(MIMEText(text))
    try:
        server = smtplib.SMTP(serverAddr)
        server.sendmail(sender, [to], message.as_string())
    except smtplib.SMTPException as e:
        print >> sys.stderr, e
    except socket.error:
        print 'Incorrect server address!'
    else:
        print 'Mail sent!'
        print 'Sender: ' + sender
        print 'Fake: ' + fakeSender
        print 'Receiver: ' + to
        print 'Subject: ' + subject
        print 'Text: ' + text
        server.quit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', help='Server address [mail.pwr.wroc.pl]', action='store', dest='server', nargs=1)
    parser.add_argument('sender', help='Real email sender address', action='store', nargs=1)
    parser.add_argument('fake', help='Fake email sender address', action='store', nargs=1)
    parser.add_argument('receiver', help='Email receiver address', action='store', nargs=1)
    parser.add_argument('subject', help='Email subject.', action='store', nargs=1)
    parser.add_argument('text', help='Email text content', action='store', nargs=1)
    args = parser.parse_args()
    if not args.server:
        send(args.sender[0], args.fake[0], args.receiver[0], args.subject[0], args.text[0])
    else:
        send(args.sender[0], args.fake[0], args.receiver[0], args.subject[0], args.text[0], args.server[0])