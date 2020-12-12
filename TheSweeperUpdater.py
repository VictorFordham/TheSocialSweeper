creator = "Kartavya Trivedi"
projectLocation = "https://github.com/Jistrokz/TheSweeper"

import os
import TheSweeperCommonFunctions
import TheSweeperLogger
import TheSweeperSettings


ModuleName = os.path.basename(__file__)


# If rules cause undefined identifier error, please include the rule here.
ExcludedRulesFileList = [
    'generic_anomalies.yar',
    'general_cloaking.yar',
    'thor_inverse_matches.yar',
    'yara_mixed_ext_vars.yar'
]



def InitDirectories():
    """
    Please Create Yara rules & temp directories if it does not exist
    :return:
    """
    if not os.path.isdir(TheSweeperSettings.TmpDirectory):
        os.makedirs(TheSweeperSettings.TmpDirectory)

    if not os.path.isdir(TheSweeperSettings.YaraRulesDirectory):
        os.makedirs(TheSweeperSettings.YaraRulesDirectory)


def FindYaraFiles():
    """
    Search for Yara-Rules files path(s) defined in given list within directory $TmpDirectory/rules-master
    :return: List contains yara rules path(s)
    """
    RulePathList = []

    RulesDirAbsolutePath = os.path.abspath(os.path.join(TheSweeperSettings.TmpDirectory, TheSweeperSettings.YaraRulesDirectoryNameInZip))
    FileList = TheSweeperCommonFunctions.GetFileSetInDir(RulesDirAbsolutePath, True)

    for FilePath in FileList:
        FileName = os.path.basename(FilePath)
        if FileName in ExcludedRulesFileList:
            continue

        RulePathList.append(FilePath)

    return RulePathList



def CleanUp():
    TheSweeperCommonFunctions.DeleteDirectoryContent(TheSweeperSettings.TmpDirectory)



def update():
    """
    Update yara-rules in YaraRulesDirectory by downloading latest files from yara rules github repo YaraRulesRepoUrl
    :return: True on success, False on fail
    """
    try:
        TheSweeperLogger.LogInfo('Started Yara-Rules update', ModuleName)
        TheSweeperLogger.LogDebug('Initializing directories', ModuleName)
        print('[+] Started Yara-Rules update')
        print('[+] Initializing directories..')
        InitDirectories()

        TheSweeperLogger.LogDebug('Fetching latest Yara-Rules from {}'.format(TheSweeperSettings.YaraRulesRepoDownloadUrl), ModuleName)
        print('[+] Fetching latest Yara-Rules from {}'.format(TheSweeperSettings.YaraRulesRepoDownloadUrl))
        SavePath = os.path.join(TheSweeperSettings.TmpDirectory, TheSweeperSettings.YaraRulesZippedName)

        TheSweeperCommonFunctions.download(TheSweeperSettings.YaraRulesRepoDownloadUrl, SavePath)
        TheSweeperCommonFunctions.ExtractZip(SavePath, TheSweeperSettings.TmpDirectory)

        YaraRulePathList = FindYaraFiles()

        if YaraRulePathList is None or len(YaraRulePathList) <= 0:
            TheSweeperLogger.LogError('Could not find any yara files that matches the specified in $YaraRulesFileList', ModuleName)
            print('[-] ERROR: Could not find any yara files that matches the specified in $YaraRulesFileList')
            return False

        TheSweeperLogger.LogDebug('Compiling rules', ModuleName)
        print('[+] Compiling rules..')
        TheSweeperCommonFunctions.CompileYaraRules(YaraRulePathList, TheSweeperSettings.YaraRulesDirectory)

        TheSweeperLogger.LogDebug('Cleaning up', ModuleName)
        print('[+] Cleaning up..')
        CleanUp()
        TheSweeperLogger.LogInfo('Update complete', ModuleName)
        print('[+] Update complete.')
        return True
    except Exception as e:
        print('[-] ERROR: {}'.format(e))
        TheSweeperLogger.LogError(e, ModuleName)
        return False
