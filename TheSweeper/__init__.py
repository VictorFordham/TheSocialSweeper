creator = "Kartavya Trivedi"
projectLocation = "https://github.com/Jistrokz/TheSweeper"


import argparse
import sys
from datetime import datetime
from TheSweeper import knownFileDB, updater, scanner, settings, reportGenerator, reportToC2, reportToMongo, commonFunctions, emailSender


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

    ap.add_argument("--ignore-known-files", action='store_true', dest="Ignore_Known_Files",
                    help="Ignore known good files.")

    ap.add_argument("--update", action='store_true', dest="Update",
                    help="Fetch latest Yara-Rules and update the current.")

    ap.add_argument("--scan-access-logs", action='store', type=str, dest="Scan_Access_Logs",
                    help="Path to a access logs file. Get list of accessed file paths from access logs and attempt to find a pattern matching with Yara Rules.")

    ap.add_argument("--www-path", action='store', type=str, dest="WWW_Path",
                    help="Path to public web directory ex; /var/www/html, /home/user/public_html' required for option '--scan-access-logs' ")

    ap.add_argument("--tail", action='store', type=int, default=0, dest="Tail",
                    help="Number of lines to read from access logs file, starting from the end of the file. If not set then will read the entire file")

    ap.add_argument("--scan-all-drives", action="store_true", dest="Scan_All_Drives",
                    help="Scan all drives connected to the system.")

    ap.add_argument("--scan-dir", action='store', type=str, dest="Scan_Dir",
                    help="Path to a directory to be scanned. Scan for file(s) in given directory path and attempt to find a pattern matching with Yara-Ruels.")

    ap.add_argument("-r", "--recursive", action='store_true', dest="Recursive",
                    help="Scan sub directories. Optional Used with option '--scan-dir' ")
    
    ap.add_argument("--report-to-mongo", action='store', type=str, dest="Report_To_Mongo",
                    help="Specify a Mongo database URI to add reports to.")

    ap.add_argument("--scan-file", action='store', type=str, dest="Scan_File",
                    help="Path to a file to be scanned. Attempt to find a pattern matching with given file.")

    ap.add_argument("--gen-remote-report", action="store", type=str, dest="Gen_Remote_Report",
                    help="URL for Sweeper Server to collect report.")

    ap.add_argument("--gen-report", action='store_true', dest="Gen_Report",
                    help="Generate an HTML report.")

    ap.add_argument("-v", "--verbose", action='store_true', dest="Verbose",
                    help="Show more information while processing.")

    ap.add_argument("--version", action="version", version='Yara-Scanner Version 1.0')
    return ap


def run():
    ArgParser = GenerateArgparser()

    args = ArgParser.parse_args()
    
    IsRecursive = args.Recursive
    try:
        if args.Verbose:
            settings.VerboseEnabled = True

        if args.Update:
            updater.update()
        if args.Scan_All_Drives:
            if args.Ignore_Known_Files:
                scanner.ScanAllDrives(excludeSet=knownFileDB.loadDefaultFileDatabase())
            else:
                scanner.ScanAllDrives()
        elif args.Scan_Dir:
            if args.Ignore_Known_Files:
                match_result = scanner.ScanDirectory(args.Scan_Dir.strip(), IsRecursive, excludeSet=knownFileDB.loadDefaultFileDatabase())
            else:
                match_result = scanner.ScanDirectory(args.Scan_Dir.strip(), IsRecursive)
        elif args.Scan_File:
            match_result = scanner.ScanFile(args.Scan_File.strip())
        elif args.Scan_Access_Logs and args.WWW_Path:
            access_log_file_path = args.Scan_Access_Logs.strip()
            www_dir_path = args.WWW_Path.strip()
            match_result = scanner.ScanAccessLogs(access_log_file_path, www_dir_path, args.Tail)
        else:
            ArgParser.print_help()
            sys.exit(0)
        if not match_result:
            if args.Report_To_Mongo:
                reportToMongo.reportAllClear(args.Report_To_Mongo)
            sys.exit(0)
    except Exception as e:
        print(e)
        sys.exit(0)
    
    if args.Report_To_Mongo:
        print('[+] Sending reports to database')
        reportToMongo.sendReport(args.Report_To_Mongo, match_result)

    if args.Gen_Remote_Report:
        print('[+] Sending report to "{}"'.format(args.Gen_Remote_Report))
        reportToC2.sendReport(args.Gen_Remote_Report, match_result)
    
    # Generate report
    
    if args.Gen_Report:
        print('[+] Generating report...')
        ReportFileName = 'TheSweeperReport_{}.html'.format(datetime.now().strftime('%Y_%B_%d_%H_%M_%S'))
        
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
