import os
from TheSweeper import commonFunctions, logger, settings


ModuleName = os.path.basename(__file__)


# If rules cause undefined identifier error, please include the rule here
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
    if not os.path.isdir(settings.TmpDirectory):
        os.makedirs(settings.TmpDirectory)

    if not os.path.isdir(settings.YaraRulesDirectory):
        os.makedirs(settings.YaraRulesDirectory)


def FindYaraFiles():
    """
    Search for Yara-Rules files path(s) defined in given list within directory $TmpDirectory/rules-master
    :return: List contains yara rules path(s)
    """
    RulePathList = []

    RulesDirAbsolutePath = os.path.abspath(os.path.join(settings.TmpDirectory, settings.YaraRulesDirectoryNameInZip))
    FileList = commonFunctions.GetFileSetInDir(RulesDirAbsolutePath, True)

    for FilePath in FileList:
        FileName = os.path.basename(FilePath)
        if FileName in ExcludedRulesFileList:
            continue

        RulePathList.append(FilePath)

    return RulePathList



def CleanUp():
    commonFunctions.DeleteDirectoryContent(settings.TmpDirectory)



def update():
    """
    Update yara-rules in YaraRulesDirectory by downloading latest files from yara rules github repo YaraRulesRepoUrl
    :return: True on success, False on fail
    """
    try:
        logger.LogInfo('Started Yara-Rules update', ModuleName)
        logger.LogDebug('Initializing directories', ModuleName)
        print('[+] Started Yara-Rules update')
        print('[+] Initializing directories..')
        InitDirectories()

        logger.LogDebug('Fetching latest Yara-Rules from {}'.format(settings.YaraRulesRepoDownloadUrl), ModuleName)
        print('[+] Fetching latest Yara-Rules from {}'.format(settings.YaraRulesRepoDownloadUrl))
        SavePath = os.path.join(settings.TmpDirectory, settings.YaraRulesZippedName)

        commonFunctions.download(settings.YaraRulesRepoDownloadUrl, SavePath)
        commonFunctions.ExtractZip(SavePath, settings.TmpDirectory)

        YaraRulePathList = FindYaraFiles()

        if YaraRulePathList is None or len(YaraRulePathList) <= 0:
            logger.LogError('Could not find any yara files that matches the specified in $YaraRulesFileList', ModuleName)
            print('[-] ERROR: Could not find any yara files that matches the specified in $YaraRulesFileList')
            return False

        logger.LogDebug('Compiling rules', ModuleName)
        print('[+] Compiling rules..')
        commonFunctions.CompileYaraRules(YaraRulePathList, settings.YaraRulesDirectory)

        logger.LogDebug('Cleaning up', ModuleName)
        print('[+] Cleaning up..')
        CleanUp()
        logger.LogInfo('Update complete', ModuleName)
        print('[+] Update complete.')
        return True
    except Exception as e:
        print('[-] ERROR: {}'.format(e))
        logger.LogError(e, ModuleName)
        return False
