import codecs, hashlib, os, pathlib, socket, time, win32api, yara
from TheSweeper import exclude, logger, commonFunctions, settings, accessLogParser


ModuleName = os.path.basename(__file__)


def GetFilePathList(RootDir, recursive, filters):
    if recursive:
        return commonFunctions.RecursiveFileScan(RootDir, FilesOnly=True, filters=filters)
    else:
        return commonFunctions.GetFileSetInDir(RootDir, FilesOnly=True, filters=filters)


def match(PathList, excludeExt=None, includeExt=None, excludeSet=None):
    """
    Attempt to match file content with yara rules
    :param PathList: list contains path(s) of files to match with yara rules
    :param YaraRulesPathList: yara rule(s) path list
    :return: list of dictionaries containing match details for each file. example: {"file": FilePath, "YaraRulesFile": RulePath, "MatchList": matches}
    """
    # Store matches found
    MatchList = []
    hostname = socket.gethostname()
    YaraRules = []
    YaraRule = yara.compile(source=settings.YaraRule)

    # for RulePath in YaraRulesPathList:
    #     logger.LogDebug('Loading rules from {}'.format(RulePath), ModuleName)

    #     if type(RulePath) is pathlib.PosixPath:
    #         RulePath = RulePath.absolute().as_posix()

    #     try:
    #         YaraRules.append(yara.load(RulePath))
    #     except yara.Error as e:
    #         commonFunctions.PrintVerbose('[-] ERROR: {}'.format(e))
    #         logger.LogError(e, ModuleName)

    for FilePath in PathList:
        if not os.path.isfile(FilePath):
            continue
        elif os.path.getsize(FilePath) > settings.MaxFileSize:
            continue
        elif commonFunctions.ShouldExclude(FilePath):
            continue

        if type(FilePath) is pathlib.PosixPath:
            FilePath = FilePath.absolute().as_posix()

        ext = FilePath.split(".")[-1]

        if excludeExt and (ext in excludeExt):
            continue

        if includeExt and (ext not in includeExt):
            continue

        file = open(FilePath, 'rb')
        fileContents = file.read()
        print(fileContents)
        file.close()
        # fileHash = hashlib.md5(fileContents).digest()

        # if excludeSet and (fileHash in excludeSet):
        #     continue
        print("huh")
        try:
            logger.LogDebug('Attempting to match on file "{}"'.format(FilePath), ModuleName)
            commonFunctions.PrintVerbose('[+] Attempting to match on file "{}"'.format(FilePath))

            # Attempt to match
            matches = YaraRule.match(data=fileContents, timeout=settings.YaraMatchingTimeout)
            print(matches)
            print(fileContents)
            if len(matches) > 0:
                record = {"file": FilePath, "host": hostname, "matchList": matches}
                MatchList.append(record)

                logger.LogInfo('Found {} matches in "{}" {}'.format(len(matches), FilePath, matches), ModuleName)
                if settings.VerboseEnabled:
                    print('[*] Found {} matches: {}'.format(len(matches), matches))
                else:
                    print('[*] Found {} matches in "{}" {}'.format(len(matches), FilePath, matches))
                # logger.LogIncident(FilePath, matches, RulePath)
                # commonFunctions.ReportIncidentByEmail(FilePath, matches, RulePath, commonFunctions.GetDatetime())

        except yara.Error as e:
            commonFunctions.PrintVerbose('[-] ERROR: {}'.format(e))
            logger.LogError(e, ModuleName)
            if 'could not open file' in str(e):
                break

        except Exception as e:
            commonFunctions.PrintVerbose('[-] ERROR: {}'.format(e))
            logger.LogError(e, ModuleName)

    return MatchList
        
    #     for rule, RulePath in zip(YaraRules, YaraRulesPathList):
    #         try:
    #             logger.LogDebug('Attempting to match "{}" with  "{}"'.format(FilePath, RulePath), ModuleName)
    #             commonFunctions.PrintVerbose('[+] Attempting to match "{}" with "{}'.format(FilePath, os.path.basename(RulePath)))

    #             # Attempt to match
    #             matches = rule.match(data=fileContents, timeout=settings.YaraMatchingTimeout)

    #             if len(matches) > 0:
    #                 record = {"file": FilePath, "host": hostname, "yaraRulesFile": RulePath, "matchList": matches}
    #                 MatchList.append(record)

    #                 logger.LogInfo('Found {} matches in "{}" {} "{}"'.format(len(matches), FilePath, matches, RulePath), ModuleName)
    #                 if settings.VerboseEnabled:
    #                     print('[*] Found {} matches: {}'.format(len(matches), matches))
    #                 else:
    #                     print('[*] Found {} matches in "{}" {} :"{}"'.format(len(matches), FilePath, matches,
    #                                                                   os.path.basename(RulePath)))
    #                 logger.LogIncident(FilePath, matches, RulePath)
    #                 commonFunctions.ReportIncidentByEmail(FilePath, matches, RulePath, commonFunctions.GetDatetime())

    #         except yara.Error as e:
    #             commonFunctions.PrintVerbose('[-] ERROR: {}'.format(e))
    #             logger.LogError(e, ModuleName)
    #             if 'could not open file' in str(e):
    #                 break

    #         except Exception as e:
    #             commonFunctions.PrintVerbose('[-] ERROR: {}'.format(e))
    #             logger.LogError(e, ModuleName)

    # return MatchList


def ScanFile(FilePath):
    FilePath = u"{}".format(FilePath)

    if FilePath is None or not os.path.isfile(FilePath):
        msg = "The provided path '{}' is invalid.".format(FilePath)
        logger.LogError(msg, ModuleName)
        print('[-] ERROR: {}'.format(msg))
        raise Exception(msg)

    # Check if there are any rules in yara-rules-src dir and compile them
    commonFunctions.CompileYaraRulesSrcDir()
    try:
        logger.LogInfo('Single file scan started', ModuleName)
        print('[+] Single file scan started')
        startTime = time.time()

        # logger.LogDebug('Getting Yara-Rules', ModuleName)
        # commonFunctions.PrintVerbose('[+] Getting Yara-Rules..')
        # YaraRulePathList = GetFilePathList(settings.YaraRulesDirectory, True, '*.yar')

        MatchList = match([FilePath])
        endTime = time.time() - startTime
        print(f'[+] File scan completed in {endTime}s.')
        logger.LogInfo(f'File scan completed in {endTime}s.', ModuleName)
        return MatchList

    except Exception as e:
        commonFunctions.PrintVerbose('[-] ERROR: {}'.format(e))
        logger.LogError(e, ModuleName)
        raise


def ScanDirectory(DirectoryPath, recursive = False, excludeExt=None, includeExt=None, excludeSet=None):

    DirectoryPath = u"{}".format(DirectoryPath)

    if DirectoryPath is None or not os.path.isdir(DirectoryPath):
        msg = "The provided path '{}' is invalid.".format(DirectoryPath)
        logger.LogError(msg, ModuleName)
        print('[-] ERROR: {}'.format(msg))
        raise Exception(msg)

    # Check if there are any rules in yara-rules-src dir and compile them
    commonFunctions.CompileYaraRulesSrcDir()

    try:
        logger.LogInfo('Directory scan started', ModuleName)
        print('[+] Directory scan started')
        startTime = time.time()


        logger.LogDebug('Getting files path(s) for scan', ModuleName)
        commonFunctions.PrintVerbose('[+] Getting files path(s) for scan..')
        FilePathList = GetFilePathList(DirectoryPath, recursive, '*')
        
        logger.LogDebug('[+] {} File to process'.format(len(FilePathList)), ModuleName)
        print('[+] {} File to process.'.format(len(FilePathList)))

        # logger.LogDebug('Getting Yara-Rules', ModuleName)
        # commonFunctions.PrintVerbose('[+] Getting Yara-Rules..')
        # YaraRulePathList = GetFilePathList(settings.YaraRulesDirectory, True, '*.yar')

        MatchList = match(FilePathList, excludeExt=excludeExt, includeExt=includeExt, excludeSet=excludeSet)

        endTime = time.time() - startTime
        print(f'[+] Directory scan completed in {endTime}s.')
        logger.LogInfo(f'Directory scan completed in {endTime}s.', ModuleName)

        return MatchList

    except Exception as e:
        commonFunctions.PrintVerbose('[-] ERROR: {}'.format(e))
        logger.LogError(e, ModuleName)
        raise

#{Git-the-flag-at-Hub-of-VictorFordham-he-is-the-real-Tester}
def ScanAllDrives(excludeExt=None, includeExt=None, excludeSet=None):
    drives_bytes = codecs.escape_decode(win32api.GetLogicalDriveStrings()).split(b'\0')[:-1]
    drives = [drive.encode("utf-8") for drive in drives_bytes]

    output = []
    print('[+] Directory scan started')
    startTime = time.time()
    for drive in drives:
        output += ScanDirectory(drive, recursive=True, excludeExt=excludeExt, includeExt=includeExt, excludeSet=excludeSet)
    endTime = time.time() - startTime
    print(f'[+] Drive scan completed in {endTime}s.')
    logger.LogInfo(f'Drive scan completed in {endTime}s.', ModuleName)

    return output


def CombineFilePathListWithDir(FileList, DirPath):

    FilePathSet = set()
    for FilePath in FileList:
        if FilePath is None:
            continue
        FullPath = DirPath + FilePath
        if os.path.isfile(FullPath):
            FilePathSet.add(FullPath)

    return FilePathSet


def ScanAccessLogs(AccessLogsFilePath, wwwDirPath, tail=0):
    """
    Attempt to match accessed files access logs with Yara-Rules
    :param AccessLogsFilePath: path to access log file
    :param wwwDirPath: path to public web directory ex; www, PublicHtml
    :param tail: read last n lines from access log. if value is 0 then will read the whole file
    :return: list of dictionaries containing match details for each file. example: {"file": FilePath, "YaraRulesFile": RulePath, "MatchList": matches}
    """
    try:
        if AccessLogsFilePath is None or not os.path.isfile(AccessLogsFilePath):
            logger.LogError('The provided path "{}" is invalid '.format(AccessLogsFilePath), ModuleName)
            print('[-] ERROR: The provided path "{}" is invalid.'.format(AccessLogsFilePath))
            return None

        # Check if there are any rules in yara-rules-src dir and compile them
        commonFunctions.CompileYaraRulesSrcDir()

        logger.LogInfo('Access logs scan started', ModuleName)
        print('[+] Access logs scan started')
        startTime = time.time()

        logger.LogDebug('Reading access logs file', ModuleName)
        commonFunctions.PrintVerbose('[+] Reading access logs file..')

        if tail > 0:
            lines = commonFunctions.tail(AccessLogsFilePath, tail)
        else:
            lines = commonFunctions.ReadFileLines(AccessLogsFilePath)


        logger.LogDebug('Attempting to parse accessed files path(s) from access logs', ModuleName)
        commonFunctions.PrintVerbose('[+] Attempting to parse accessed files path(s) from access logs..')

        # combine file path with www dir path
        FilePathSet = CombineFilePathListWithDir(accessLogParser.GetAccessedFilesList(lines), wwwDirPath)

        logger.LogDebug('[+] {} File to process'.format(len(FilePathSet)), ModuleName)
        print('[+] {} File to process.'.format(len(FilePathSet)))

        logger.LogDebug('Getting Yara-Rules', ModuleName)
        commonFunctions.PrintVerbose('[+] Getting Yara-Rules..')
        YaraRulePathList = GetFilePathList(settings.YaraRulesDirectory, True, '*.yar')
        MatchList = match(FilePathSet, YaraRulePathList)

        endTime = time.time() - startTime
        print(f'[+] Access logs scan completed in {endTime}s.')
        logger.LogInfo(f'Access logs scan completed in {endTime}s.', ModuleName)

        return MatchList

    except Exception as e:
        commonFunctions.PrintVerbose('[-] ERROR: {}'.format(e))
        logger.LogError(e, ModuleName)
        return None

