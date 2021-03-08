"""
Email sender with attachment support
"""

import smtplib
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import encoders
import sys

COMMASPACE = ', '


def SendMessage(DictMsgAttr):
    if DictMsgAttr is None:
        return False

    username = DictMsgAttr["username"]
    password = DictMsgAttr["password"]
    SmtpHost = DictMsgAttr["host"]
    SmtpPort = int(DictMsgAttr["port"])
    SmtpSsl = bool(DictMsgAttr["ssl"])
    recipients = DictMsgAttr["recipients"]
    MessageBody = DictMsgAttr["MessageBody"]

    # Create the enclosing (outer) message
    outer = MIMEMultipart()
    outer['Subject'] = DictMsgAttr["subject"]
    outer['To'] = COMMASPACE.join(recipients)
    outer['From'] = DictMsgAttr["from"]
    outer.preamble = 'You will not see this in a MIME-aware mail reader.\n'

    # List of attachments, DictMsgAttr["attachments"] contains a list of strings.
    # each string will be encoded and attached as a file to the message.
    if 'attachments' in DictMsgAttr and  DictMsgAttr["attachments"] is not None:
        attachments = DictMsgAttr["attachments"]
        for TxtAttachments in attachments:
            # Add the attachments to the message
            try:
                msg = MIMEBase('application', "octet-stream")
                msg.SetPayload(bytes(TxtAttachments['text'], "utf-8"))
                encoders.encode_base64(msg)
                msg.AddHeader('Content-Disposition', 'attachment', filename=TxtAttachments['FileName'])
                outer.attach(msg)
            except:
                print("Unable to read one of the attachments. Error: ", sys.exc_info()[0])
                raise

    outer.attach(MIMEText(MessageBody, 'plain'))
    composed = outer.as_string()

    # send email
    try:
        if username is not username != "":
            with smtplib.SMTP('{}: {}'.format(SmtpHost, SmtpPort)) as server:
                server.ehlo()
                if SmtpSsl:
                    server.starttls()
                    server.ehlo()

                server.login(username, password)
                server.sendmail(DictMsgAttr["from"], recipients, composed)
                server.close()

                return True
        else:
            with smtplib.SMTP("localhost") as server:
                server.ehlo()
                server.sendmail(DictMsgAttr["from"], recipients, composed)
                server.close()
                return True

    except:
        print("Sending email failed. {}".format(sys.exc_info()[0]), sys.exc_info()[0])
        raise
