creator = "Kartavya Trivedi"
projectLocation = "https://github.com/Jistrokz/TheSweeper"

import argparse
import sys
import TheSweeperUpdater
import TheSweeperScanner
import TheSweeperSettings
import TheSweeperReportGenerator
import TheSweeperCommonFunctions
import TheSweeperEmailSender
from datetime import datetime

ArgParser = None

def RunScanner(args):
    IsRecursive = args["recursive"]
    try:
            if args["scan_dir"] is not None:
                match_result = TheSweeperScanner.ScanDirectory(args["scan_dir"].strip(), IsRecursive)
            elif args["scan_file"] is not None:
                match_result = TheSweeperScanner.ScanFile(args["scan_file"].strip())
            elif args["scan_access_logs"] is not None and args["www_path"] is not None:
                access_log_file_path = args["scan_access_logs"].strip()
                www_dir_path = args["www_path"].strip()
                match_result = TheSweeperScanner.ScanAccessLogs(access_log_file_path, www_dir_path, args["tail"])
            else:
                ArgParser.print_help()
                sys.exit(0)
            if match_result is None:
                raise Exception()
    except:
        sys.exit(0)
    # try:
    #     if args["ScanDir"] is not None:
    #         MatchResult = TheSweeperScanner.ScanDirectory(args["ScanDir"].strip(), IsRecursive)
    #     elif args["ScanFile"] is not None:
    #         MatchResult = TheSweeperScanner.ScanFile(args["ScanFile"].strip())
    #     elif args["ScanAccessLogs"] is not None and args["wwwPath"] is not None:
    #         AccessLogFilePath = args["ScanAccessLogs"].strip()
    #         wwwDirPath = args["wwwPath"].strip()
    #         MatchResult = TheSweeperScanner.ScanAccessLogs(AccessLogFilePath, wwwDirPath, args["tail"])
    #     else:
    #         ArgParser.PrintHelp()
    #         sys.exit(0)
    #     if MatchResult is None:
    #         raise Exception()
    # except:
    #     sys.exit(0)

    # Generate report
    ReportFileName = 'TheSweeperReport_{}.html'.format(datetime.now().strftime('%Y_%B_%d_%H_%M_%S'))
    if args['gen_report']:
        print('[+] Generating report...')

    if args['gen_report']:
        report = TheSweeperReportGenerator.GenerateReport(match_result)
        TheSweeperCommonFunctions.WriteToFile(ReportFileName, report)
        print('[+] Report saved to "{}"'.format(ReportFileName))

    # send report by email
    if args['gen_report'] and len(TheSweeperSettings.SmtpHost) > 0 and TheSweeperSettings.SmtpPort > 0:
        report = TheSweeperReportGenerator.GenerateReport(match_result)

        attachment = [{'text': report, 'FileName': ReportFileName}]
        SmtpMailerParam = TheSweeperCommonFunctions.BuildSmtpConfigDict()
        SmtpMailerParam['MessageBody'] = TheSweeperSettings.EmailBodyScanComplete
        SmtpMailerParam['subject'] = 'Scan Report {}'.format(TheSweeperCommonFunctions.GetDatetime())
        SmtpMailerParam['attachments'] = attachment

        print('[+] Delivering report to {}'.format(TheSweeperSettings.EmailAlertRecipients))
        TheSweeperEmailSender.SendMessage(SmtpMailerParam)
        print('[+] Report sent to {}'.format(TheSweeperSettings.EmailAlertRecipients))


def RunTheSweeperUpdater():
    TheSweeperUpdater.update()


def run(args):
    if args["verbose"]:
        TheSweeperSettings.VerboseEnabled = True

    if args["update"]:
        RunTheSweeperUpdater()
    else:
        RunScanner(args)


def GenerateArgparser():
    ascii_logo = """
 _______ _           _____                                  
 |__   __| |         / ____|                                 
    | |  | |__   ___| (_____      _____  ___ _ __   ___ _ __ 
    | |  | '_ \ / _ \\___ \ \ /\ / / _ \/ _ \ '_ \ / _ \ '__|
    | |  | | | |  __/____) \ V  V /  __/  __/ |_) |  __/ |   
    |_|  |_| |_|\___|_____/ \_/\_/ \___|\___| .__/ \___|_|   
                                            | |              
                                            |_|    

    https://github.com/Jistrokz/TheSweeper
    """
    ap = argparse.ArgumentParser(ascii_logo)

    ap.add_argument("--update", action='store_true',
                    help="Fetch latest Yara-Rules and update the current.")

    ap.add_argument("--scan-access-logs", action='store', type=str,
                    help="Path to a access logs file. Get list of accessed file paths from access logs and attempt to find a pattern matching with Yara Rules.")

    ap.add_argument("--www-path", action='store', type=str,
                    help="Path to public web directory ex; /var/www/html, /home/user/public_html' required for option '--scan-access-logs' ")

    ap.add_argument("--tail", action='store', type=int, default=0,
                    help="Number of lines to read from access logs file, starting from the end of the file. If not set then will read the entire file")

    ap.add_argument("--scan-dir", action='store', type=str,
                    help="Path to a directory to be scanned. Scan for file(s) in given directory path and attempt to find a pattern matching with Yara-Ruels.")

    ap.add_argument("-r", "--recursive", action='store_true',
                    help="Scan sub directories. Optional Used with option '--scan-dir' ")

    ap.add_argument("--scan-file", action='store', type=str,
                    help="Path to a file to be scanned. Attempt to find a pattern matching with given file.")

    ap.add_argument("--gen-report", action='store_true',
                    help="Generate an HTML report.")

    ap.add_argument("-v", "--verbose", action='store_true',
                    help="Show more information while processing.")

    ap.add_argument("--version", action="version", version='Yara-Scanner Version 1.0')
    return ap


def main():
    global ArgParser
    ArgParser = GenerateArgparser()
    args = vars(ArgParser.parse_args())
    run(args)


if __name__ == "__main__":
    main()


