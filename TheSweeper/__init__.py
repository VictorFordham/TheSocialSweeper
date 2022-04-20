creator = "Kartavya Trivedi"
projectLocation = "https://github.com/Jistrokz/TheSweeper"


import argparse
import sys, time
from datetime import datetime
from TheSweeper.scanner import match
from TheSweeper import knownFileDB, scanner, settings, reportGenerator, reportToC2, reportToMongo, commonFunctions, emailSender, malarky


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

    ap.add_argument("--flash", action='store', type=str, dest="Flash", help="")

    ap.add_argument("--ignore-file-extensions", action="store", type=str, dest="Ignore_File_Extensions",
                    help="Ignore files with certain extensions")

    ap.add_argument("--ignore-known-files", action='store_true', dest="Ignore_Known_Files",
                    help="Ignore known good files.")

    ap.add_argument("--include-file-extensions", action="store", type=str, dest="Include_File_Extensions",
                    help="Specify the file extions to scan")

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
    
    ap.add_argument("--run-with-interval", action="store", type=int, dest="Run_Interval",
                    help="Runs the application in a persistent mode, additionally, you must specify an interval in minutes for scans to be performed.")

    ap.add_argument("--scan-file", action='store', type=str, dest="Scan_File",
                    help="Path to a file to be scanned. Attempt to find a pattern matching with given file.")

    ap.add_argument("--gen-known-file-db", action='store', type=str, dest="Gen_Known_File_DB",
                    help="Generate a known file database, from the files under a specified path (recursively scanned); must also specify either --known-file-db-raw-out or --known-file-db-py-out")
    
    ap.add_argument("--known-file-db-raw-out", action='store', type=str, dest="Known_File_DB_Raw_Out",
                    help="Provide a file path to store the generated known file database in the raw format")
    
    ap.add_argument("--known-file-db-py-out", action="store", type=str, dest="Known_File_DB_Py_Out",
                    help="Provide a file path to store the generated known file database in the python format")

    # ap.add_argument("--gen-remote-report", action="store", type=str, dest="Gen_Remote_Report",
    #                 help="URL for Sweeper Server to collect report.")

    # ap.add_argument("--gen-report", action='store_true', dest="Gen_Report",
    #                 help="Generate an HTML report.")

    ap.add_argument("-v", "--verbose", action='store_true', dest="Verbose",
                    help="Show more information while processing.")

    ap.add_argument("--version", action="version", version='Yara-Scanner Version 1.0')
    return ap


def performScan(args):
    match_result = None

    if args.Scan_File:
        match_result = scanner.ScanFile(args.Scan_File.strip())
    elif args.Scan_Access_Logs and args.WWW_Path:
        access_log_file_path = args.Scan_Access_Logs.strip()
        www_dir_path = args.WWW_Path.strip()
        match_result = scanner.ScanAccessLogs(access_log_file_path, www_dir_path, args.Tail)
    else:
        excludeExt = set(ext for ext in args.Ignore_File_Extensions.split(',')) if args.Ignore_File_Extensions else None
        includeExt = set(ext for ext in args.Include_File_Extensions.split(',')) if args.Include_File_Extensions else None
        excludeSet = knownFileDB.loadDefaultFileDatabase() if args.Ignore_Known_Files else None

        if args.Scan_All_Drives:
            match_result = scanner.ScanAllDrives(excludeExt=excludeExt, includeExt=includeExt, excludeSet=excludeSet)
        elif args.Scan_Dir:
            match_result = scanner.ScanDirectory(args.Scan_Dir.strip(), args.Recursive, excludeExt=excludeExt, includeExt=includeExt, excludeSet=excludeSet)
    
    return match_result


def executionLoop(args):
    numOfHits = 0

    while True:
        match_result = performScan(args)

        if len(match_result) <= numOfHits:
            time.sleep(args.Run_Interval * 60)
            continue

        numOfHits = len(match_result)

        uri = args.Report_To_Mongo
        if args.Flash:
            uri = malarky.flash(args.Flash)

        if not match_result and uri:
            reportToMongo.reportAllClear(uri)
        elif uri:
            print('[+] Sending reports to database')
            reportToMongo.sendReport(uri, match_result)        

        time.sleep(args.Run_Interval)


def run(arguments=None):
    ArgParser = GenerateArgparser()

    if arguments:
        args = ArgParser.parse_args(arguments)
    else:
        args = ArgParser.parse_args()
    
    match_result = None
    try:
        if args.Verbose:
            settings.VerboseEnabled = True

        if args.Gen_Known_File_DB:
            if not args.Known_File_DB_Raw_Out and not args.Known_File_DB_Py_Out:
                print("Must specify either --known-file-db-raw-out or --known-file-db-py-out when using --gen-known-file-db")
                sys.exit(0)
            
            fileDatabase = knownFileDB.generateDefaultFileDatabase(args.Gen_Known_File_DB)
            if args.Known_File_DB_Raw_Out:
                knownFileDB.storeKnownFilesRaw(args.Known_File_DB_Raw_Out, fileDatabase)
            else:
                knownFileDB.storeKnownFilesPy(args.Known_File_DB_Py_Out, fileDatabase)
        elif args.Scan_All_Drives or args.Scan_Dir or args.Scan_File:
            if args.Run_Interval != None:
                #this never returns
                executionLoop(args)

            match_result = performScan(args)
            
            # maybe gen reports afterward
        else:
            ArgParser.print_help()
            sys.exit(0)

        uri = args.Report_To_Mongo
        if args.Flash:
            uri = malarky.flash(args.Flash)

        if not match_result:
            if uri:
                reportToMongo.reportAllClear(uri)
            sys.exit(0)
    except Exception as e:
        print(e)
        sys.exit(0)
    
    if uri:
        print('[+] Sending reports to database')
        reportToMongo.sendReport(uri, match_result)

    # if args.Gen_Remote_Report:
    #     print('[+] Sending report to "{}"'.format(args.Gen_Remote_Report))
    #     reportToC2.sendReport(args.Gen_Remote_Report, match_result)
    
    # # Generate report
    
    # if args.Gen_Report:
    #     print('[+] Generating report...')
    #     ReportFileName = 'TheSweeperReport_{}.html'.format(datetime.now().strftime('%Y_%B_%d_%H_%M_%S'))
        
    #     report = reportGenerator.GenerateReport(match_result)
    #     commonFunctions.WriteToFile(ReportFileName, report)
    #     print('[+] Report saved to "{}"'.format(ReportFileName))

    #     # send report by email
    #     if len(settings.SmtpHost) > 0 and settings.SmtpPort > 0:
    #         report = reportGenerator.GenerateReport(match_result)

    #         attachment = [{'text': report, 'FileName': ReportFileName}]
    #         SmtpMailerParam = commonFunctions.BuildSmtpConfigDict()
    #         SmtpMailerParam['MessageBody'] = settings.EmailBodyScanComplete
    #         SmtpMailerParam['subject'] = 'Scan Report {}'.format(commonFunctions.GetDatetime())
    #         SmtpMailerParam['attachments'] = attachment

    #         print('[+] Delivering report to {}'.format(settings.EmailAlertRecipients))
    #         emailSender.SendMessage(SmtpMailerParam)
    #         print('[+] Report sent to {}'.format(settings.EmailAlertRecipients))
