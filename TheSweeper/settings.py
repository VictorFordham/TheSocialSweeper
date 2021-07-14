################ Internal TheSweeperSettings, usually remains the same! ################
TmpDirectory = 'tmp'

# Compiled rules directory
YaraRulesDirectory = 'yara-rules'

# Uncompiled rules directory (Src). Yara rules in this diectory will be compiled automatically when start
YaraRulesSrcDirectory = 'yara-rules-src'

YaraRulesRepoUrl = 'https://github.com/Jistrokz/TheSweeper-Rules'
YaraRulesRepoDownloadUrl = YaraRulesRepoUrl + '/archive/main.zip'
YaraRulesZippedName = 'TheSweeper-Rules.zip'
YaraRulesDirectoryNameInZip = 'TheSweeper-Rules-main/yara'
YaraMatchingTimeout = 30 # timeout in seconds
MaxFileSize = 6777216 # Max file size 16 MB
DebugLogEnabled = False
DebugLogFilePath = 'debug.log'
LogFilePath = 'matches.log'
VerboseEnabled = False

# time format used across modules [logging, alerts]
DateTimeFormat = '%Y-%m-%d %H:%M:%S'

################ Email Alerts TheSweeperSettings ################
EmailAlertsEnabled = False
SmtpHost = ""
SmtpPort = 25

# default Mongo Database

MongoDB = "Sweeper-Test"

# SMTP server require SSL/TLS ?
SmtpSsl = True
SmtpUsername = ""
SmtpPassword = ""

# Message sender email to be included in message sender field
SmtpFrom = "TheSweeper <email@example.org>"

# Reports & alerts will be sent to this email(s)
EmailAlertRecipients = ["email@example.org"]


# Email body for scan report
EmailBodyScanComplete = """
TheSweeper has completed a scan process. The attached report contains scan process results.
"""

EmailBodyMatchFound = """
TheSweeper has found a pattern match, here's the details:
"""
