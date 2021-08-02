from TheSweeper import defaultFileDB, exclude, logger, commonFunctions, settings, accessLogParser
# need to add a variable to settings to be the
# path to the known hash file
# this will be a binary file of all known
# hashes concatenated together
# since we simply seek identification md5 should suffice


def loadFileDatabase(hashes: bytes) -> set:
    setOfHashes = set()

    for i in range(0, len(hashes), 16):
        setOfHashes.add(hashes[i:i + 16])
    
    return setOfHashes


def loadKnownFiles(filePath: str) -> set:
    file = open(filePath, "rb")
    setOfHashes = set()

    hash = file.read(16)
    
    while hash:
        setOfHashes.add(hash)
        hash = file.read(16)
    
    file.close()

    return setOfHashes


def storeKnownFiles(filePath: str, setOfHashes: set):
    file = open(filePath, "wb")

    for hash in setOfHashes:
        file.write(hash)
    
    file.close()


def generateDefaultFileDatabase(dirPath: str):
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

        logger.LogDebug('Getting Yara-Rules', ModuleName)
        commonFunctions.PrintVerbose('[+] Getting Yara-Rules..')
        YaraRulePathList = GetFilePathList(settings.YaraRulesDirectory, True, '*.yar')

        MatchList = match(FilePathList, YaraRulePathList, excludeSet=excludeSet)

        endTime = time.time() - startTime
        print(f'[+] Directory scan completed in {endTime}s.')
        logger.LogInfo(f'Directory scan completed in {endTime}s.', ModuleName)

        return MatchList

    except Exception as e:
        commonFunctions.PrintVerbose('[-] ERROR: {}'.format(e))
        logger.LogError(e, ModuleName)
        raise


def loadDefaultFileDatabase():
    return loadFileDatabase(defaultFileDB.database)