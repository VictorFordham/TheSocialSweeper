import hashlib, os, time
from TheSweeper import defaultFileDB, logger, commonFunctions, scanner, settings, accessLogParser
# need to add a variable to settings to be the
# path to the known hash file
# this will be a binary file of all known
# hashes concatenated together
# since we simply seek identification md5 should suffice

ModuleName = __name__


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


def storeKnownFilesRaw(filePath: str, setOfHashes: set):
    file = open(filePath, "wb")

    for hash in setOfHashes:
        file.write(hash)
    
    file.close()


def storeKnownFilesPy(filePath: str, setOfHashes: set):
    file = open(filePath, "w")

    byteString = b"".join(setOfHashes)
    file.write(f"database = {str(byteString)}")

    file.close()


def generateDefaultFileDatabase(dirPath: str, recursive=True) -> set:
    dirPath = u"{}".format(dirPath)

    if dirPath is None or not os.path.isdir(dirPath):
        msg = "The provided path '{}' is invalid.".format(dirPath)
        logger.LogError(msg, ModuleName)
        print('[-] ERROR: {}'.format(msg))
        raise Exception(msg)

    try:
        logger.LogInfo('Generating file database', ModuleName)
        print('[+] Generating file database')
        startTime = time.time()


        logger.LogDebug('Getting files path(s)', ModuleName)
        commonFunctions.PrintVerbose('[+] Getting files path(s)..')
        FilePathList = scanner.GetFilePathList(dirPath, recursive, '*')
        
        logger.LogDebug('[+] {} File to process'.format(len(FilePathList)), ModuleName)
        print('[+] {} File to process.'.format(len(FilePathList)))

        fileDatabase = set()
        for filePath in FilePathList:
            file = open(filePath, "rb")
            fileContents = file.read()
            file.close()

            fileDatabase.add(hashlib.md5(fileContents).digest())

        endTime = time.time() - startTime
        print(f'[+] Generating file database completed in {endTime}s.')
        logger.LogInfo(f'Generating file database completed in {endTime}s.', ModuleName)

        return fileDatabase

    except Exception as e:
        commonFunctions.PrintVerbose('[-] ERROR: {}'.format(e))
        logger.LogError(e, ModuleName)
        raise


def loadDefaultFileDatabase():
    return loadFileDatabase(defaultFileDB.database)