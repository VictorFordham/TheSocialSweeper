creator = "Kartavya Trivedi"
projectLocation = "https://github.com/Jistrokz/TheSweeper"


import argparse
import sys
from datetime import datetime
from TheSweeper import updater, scanner, settings, reportGenerator, commonFunctions, emailSender


ArgParser = None

def RunScanner(args):
    IsRecursive = args.Recursive
    try:
            if args.Scan_Dir:
                match_result = TheSweeperScanner.ScanDirectory(args.Scan_Dir.strip(), IsRecursive)
            elif args.Scan_File:
                match_result = TheSweeperScanner.ScanFile(args.Scan_File.strip())
            elif args.Scan_Access_Logs and args.WWW_Path:
                access_log_file_path = args.Scan_Access_Logs.strip()
                www_dir_path = args.WWW_Path.strip()
                match_result = TheSweeperScanner.ScanAccessLogs(access_log_file_path, www_dir_path, args.Tail)
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
    if args.Gen_Report:
        print('[+] Generating report...')

        report = reportGenerator.GenerateReport(match_result)
        commonFunctions.WriteToFile(ReportFileName, report)
        print('[+] Report saved to "{}"'.format(ReportFileName))

        # send report by email
        if len(settings.SmtpHost) > 0 and settings.SmtpPort > 0:
            report = reportGenerator.GenerateReport(match_result)

            attachment = [{'text': report, 'FileName': ReportFileName}]
            SmtpMailerParam = commonFunctions.BuildSmtpConfigDict()
            SmtpMailerParam['MessageBody'] = settings.EmailBodyScanComplete
            SmtpMailerParam['subject'] = 'Scan Report {}'.format(commonFunctions.GetDatetime())
            SmtpMailerParam['attachments'] = attachment

            print('[+] Delivering report to {}'.format(settings.EmailAlertRecipients))
            emailSender.SendMessage(SmtpMailerParam)
            print('[+] Report sent to {}'.format(settings.EmailAlertRecipients))


def RunTheSweeperUpdater():
    updater.update()


def run(args):
    if args.Verbose:
        settings.VerboseEnabled = True

    if args.Update:
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

    ap.add_argument("--update", action='store_true', dest="Update",
                    help="Fetch latest Yara-Rules and update the current.")

    ap.add_argument("--scan-access-logs", action='store', type=str, dest="Scan_Access_Logs",
                    help="Path to a access logs file. Get list of accessed file paths from access logs and attempt to find a pattern matching with Yara Rules.")

    ap.add_argument("--www-path", action='store', type=str, dest="WWW_Path",
                    help="Path to public web directory ex; /var/www/html, /home/user/public_html' required for option '--scan-access-logs' ")

    ap.add_argument("--tail", action='store', type=int, default=0, dest="Tail",
                    help="Number of lines to read from access logs file, starting from the end of the file. If not set then will read the entire file")

    ap.add_argument("--scan-dir", action='store', type=str, dest="Scan_Dir",
                    help="Path to a directory to be scanned. Scan for file(s) in given directory path and attempt to find a pattern matching with Yara-Ruels.")

    ap.add_argument("-r", "--recursive", action='store_true', dest="Recursive",
                    help="Scan sub directories. Optional Used with option '--scan-dir' ")

    ap.add_argument("--scan-file", action='store', type=str, dest="Scan_File",
                    help="Path to a file to be scanned. Attempt to find a pattern matching with given file.")

    ap.add_argument("--gen-report", action='store_true', dest="Gen_Report",
                    help="Generate an HTML report.")

    ap.add_argument("-v", "--verbose", action='store_true', dest="Verbose",
                    help="Show more information while processing.")

    ap.add_argument("--version", action="version", version='Yara-Scanner Version 1.0')
    return ap


def main():
    global ArgParser
    ArgParser = GenerateArgparser()
    args = ArgParser.parse_args()
    run(args)