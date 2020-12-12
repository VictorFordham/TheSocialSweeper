import os
import TheSweeperSettings

################ Exclude paths from scan ################
ExcludedPathList = []

# Use double backslash for windows path's
# Example: excluded_path_list.append("C:\\windows\\temp")

# Exclude yara rules directory path by default
YaraRulesDir = os.path.join(os.getcwd(), TheSweeperSettings.YaraRulesDirectory)
ExcludedPathList.append(YaraRulesDir)


# Recommended exclusions
ExcludedPathList.append('C:\\$Recycle.Bin\\')
ExcludedPathList.append('C:\\System Volume Information\\DFSR')

################ Exclude files by extension ################
ExcludedFileExtensions = [".yar", ".log", ".chk", ".sdb", ".jdb", ".pat", ".jrs", ".dit", ".pol", ".mdb", ".dns", ".admx", ".adml", ".adm", ".edb", ".db", ".evtx"]