import logging
from TheSweeper import commonFunctions
from TheSweeper.settings import DebugLogFilePath, DebugLogEnabled, LogFilePath, DateTimeFormat


logging.basicConfig(handlers=[logging.FileHandler(filename=DebugLogFilePath, encoding='utf-8', mode='a+')],
                    level=logging.DEBUG,
                    format="%(asctime)s  %(levelname)-8s %(message)s",
                    datefmt=DateTimeFormat)


def LogError(message, ModuleName):
    if not DebugLogEnabled:
        return

    logging.error("({}): {}".format(ModuleName, message))


def LogDebug(message, ModuleName):
    if not DebugLogEnabled:
        return
    logging.debug("({}): {}".format(ModuleName, message))


def LogCritical(message, ModuleName):
    if not DebugLogEnabled:
        return
    logging.critical("({}): {}".format(ModuleName, message))


def LogWarning(message, ModuleName):
    if not DebugLogEnabled:
        return
    logging.warning("({}): {}".format(ModuleName, message))


def LogInfo(message, ModuleName):
    if not DebugLogEnabled:
        return
    logging.info("({}): {}".format(ModuleName, message))


def LogIncident(FilePath, RulesMatched, YaraRulesFileName):
    try:
        # Log format: [%time%] "%file_path%" "%rules_matched%" "yara_rules_file_name"
        LogRow = "[{}] \"{}\" \"{}\" \"{}\"".format(commonFunctions.GetDatetime(), FilePath, RulesMatched, YaraRulesFileName)

        with open(LogFilePath, 'a+', encoding='utf8') as f:
            f.write(LogRow)
            f.write("\n")
    except Exception as e:
        LogCritical(e, "TheSweeperLogger.py")