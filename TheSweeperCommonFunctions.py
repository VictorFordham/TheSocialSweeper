creator = "Kartavya Trivedi"
projectLocation = "https://github.com/Jistrokz/TheSweeper"

import os
import glob
import zipfile
import urllib.request
import shutil
import TheSweeperLogger
import yara
import TheSweeperSettings
from datetime import datetime
import TheSweeperEmailSender
import fnmatch
import TheSweeperExclude

ModuleName = os.path.basename(__file__)


def FindFiles(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            FullPath = u"{}".format(os.path.join(root, name))
            return FullPath


def PathIsParent(ParentPath, ChildPath):
    ParentPath = os.path.abspath(ParentPath)
    ChildPath = os.path.abspath(ChildPath)
    return os.path.commonpath([ParentPath]) == os.path.commonpath([ParentPath, ChildPath])


def IsAscii(s):
    return all(ord(c) < 128 for c in s)


def ShouldExclude(path):
    for p in TheSweeperExclude.ExcludedPathList:
        if PathIsParent(p, path):
            return True

    # Check file extension
    for ext in TheSweeperExclude.ExcludedFileExtensions:
        if path.lower().endswith(ext):
            return True

    return False

def GetFileSetInDir(DirPath, FilesOnly, filters = None):
    """
    Scan for files in a given directory path
    :param DirPath: directory path
    :param FilesOnly: If set to False then will get files and directories list. True will get only files list in given directory path
    :param filters: file extensions: example ['*', '*.*', '*.txt']
    :return: Set of files that matches given filters
    """

    RootDirPath = u"{}".format(DirPath)

    FilePathSet = set()
    if filters is None:
        filters = '*'

    for path in glob.glob(os.path.join(RootDirPath, filters)):
        path = u"{}".format(path)

        if FilesOnly:
            if os.path.isfile(path):
                FilePathSet.add(path)
        else:
            FilePathSet.add(path)

    return FilePathSet



def RecursiveFileScan(RootDirPath, FilesOnly, filters):
    """
    Scan for files and directories recursively in a given directory path
    :param RootDirPath: directory path
    :param FilesOnly: If set to False then will get files and directories list. True will get only files list in given directory path
    :param filters: file extensions: example ['*.txt']
    :return: Set of files that matches given filters
    """
    RootDirPath = u"{}".format(RootDirPath)
    FilePathSet = set()

    if filters is None or filters == "":
        filters = '*'

    for root, dirnames, filenames in os.walk(RootDirPath):
        for filename in fnmatch.filter(filenames, filters):
            FilePath = os.path.join(root, filename)
            FilePath = u"{}".format(FilePath)

            if FilesOnly:
                if not os.path.isfile(FilePath):
                    continue

            FilePathSet.add(FilePath)


    return FilePathSet



def DeleteDirectoryContent(DirPath):
    for file in os.listdir(DirPath):
        FilePath = os.path.join(DirPath, file)
        FilePath = u"{}".format(FilePath)

        try:
            if os.path.isfile(FilePath):
                os.unlink(FilePath)
            elif os.path.isdir(FilePath): shutil.rmtree(FilePath)
        except Exception as e:
            print('[-] ERROR {}'.format(e))
            TheSweeperLogger.LogError(e, ModuleName)


def download(url, path):
    with urllib.request.urlopen(url) as response, open(path, 'wb') as OutFile:
        shutil.copyfileobj(response, OutFile)


def ExtractZip(ZipFilePath, DirectoryToExtractTo):
    if not os.path.isfile(ZipFilePath):
        return

    with zipfile.ZipFile(ZipFilePath) as zf:
        zf.extractall(DirectoryToExtractTo)


def CompileYaraRules(YaraRulePathList, SaveDirectory):
    for path in YaraRulePathList:

        try:
            SavePath = os.path.join(SaveDirectory, os.path.basename(path))
            compiled = yara.compile(filepath=path, includes=True)
            compiled.save(SavePath)
        except Exception as e:
            if TheSweeperSettings.VerboseEnabled:
                print("[-] Could not compile the file {}. {}".format(path, e))


def CompileYaraRulesSrcDir():

    dir = os.path.abspath(TheSweeperSettings.YaraRulesSrcDirectory)
    PathList = GetFileSetInDir(dir, True, "*.yar")

    if GetFileSetInDir is None or len(PathList) < 1:
        return


    CompileYaraRules(PathList, TheSweeperSettings.YaraRulesDirectory)


def WriteToFile(FilePath, content):
    with open(FilePath, mode='w', encoding='utf8') as file:
        file.write(content)

def PrintVerbose(msg):
    if not TheSweeperSettings.VerboseEnabled:
        return
    print(msg)


def OpenFile(FilePath):
    try:
        return open(FilePath, "r")
    except IOError as e:
        print('[-] ERROR {}'.format(e))
        TheSweeperLogger.LogError(e, ModuleName)
        return None


def CloseFile(FileStream):
    try:
        FileStream.close()
        return True
    except IOError as e:
        print('[-] ERROR {}'.format(e))
        TheSweeperLogger.LogError(e, ModuleName)
        return False


def ReadFileLines(FilePath):
    with open(FilePath) as fp:
        return fp.readlines()


def GetDatetime():
    return datetime.now().strftime(TheSweeperSettings.DateTimeFormat)


def tail(FilePath, lines=1, _buffer=4098):
    """
    Tail a file and get X lines from the end
    Source: https://stackoverflow.com/a/13790289/5974057
    """

    # place holder for the lines found
    LinesFound = []

    # block counter will be multiplied by buffer
    # to get the block size from the end
    BlockCounter = -1

    f = OpenFile(FilePath)

    # loop until we find X lines
    while len(LinesFound) < lines:
        try:

            f.seek(BlockCounter * _buffer, os.SEEK_END)
        except IOError:  # either file is too small, or too many lines requested
            f.seek(0)
            LinesFound = f.readlines()
            break

        LinesFound = f.readlines()
        BlockCounter -= 1

    CloseFile(f)
    return LinesFound[-lines:]


def BuildSmtpConfigDict():
    t = {
        "host": TheSweeperSettings.SmtpHost,
        "port": TheSweeperSettings.SmtpPort,
        "ssl": TheSweeperSettings.SmtpSsl,
        "username": TheSweeperSettings.SmtpUsername,
        "password": TheSweeperSettings.SmtpPassword,
        "from": TheSweeperSettings.SmtpFrom,
        "recipients": TheSweeperSettings.EmailAlertRecipients,
    }
    return t


def ReportIncidentByEmail(FilePath, RulesMatched, YaraRulesFileName, EventTime):
    if not TheSweeperSettings.EmailAlertsEnabled:
        return

    try:
        FileName = os.path.basename(FilePath)
        ShortFileName = FileName
        if FileName is not None and len(FileName) > 40:
            ShortFileName = FileName[0 : 39]

        SmtpMailerParam = BuildSmtpConfigDict()
        SmtpMailerParam['MessageBody'] = BuildIncidentEmailMessageBody(FileName, FilePath, RulesMatched, YaraRulesFileName, EventTime)
        SmtpMailerParam['subject'] = 'Match Found: {}'.format(ShortFileName)

        print('[+] Sending incident info to {}'.format(TheSweeperSettings.EmailAlertRecipients))
        TheSweeperEmailSender.SendMessage(SmtpMailerParam)
        print('[+] Incident info sent to {}'.format(TheSweeperSettings.EmailAlertRecipients))
    except Exception as e:
        print('[-] ERROR: {}'.format(e))
        TheSweeperLogger.LogError(e, ModuleName)


def BuildIncidentEmailMessageBody(FileName, FilePath, RulesMatched, YaraRulesFileName, EventTime):
    message = TheSweeperSettings.EmailBodyMatchFound
    message += "\n\n"
    message += "Event time: {}".format(EventTime)
    message += "\n"
    message += "File name: {}".format(FileName)
    message += "\n"
    message += "File path: {}".format(FilePath)
    message += "\n"
    message += "Rules matches: {}".format(RulesMatched)
    message += "\n"
    message += "Yara rules file: {}".format(YaraRulesFileName)
    message += "\n\n"
    return message