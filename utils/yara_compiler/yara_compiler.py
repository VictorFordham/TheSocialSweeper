__author__ = "Moath Maharmeh"
__project_page__ = "https://github.com/iomoath/yara-scanner"

import os
from pathlib import Path
import glob
import yara


OutputDirectory = 'output'
SourceDirectory = 'source'


def RecursiveFileScan(RootDirPath, filters):
    """scans a directory recursively for files"""
    FilePathSet = set()

    for f in filters:
        for FilePath in Path(RootDirPath).glob('**/{}'.format(f)):
            if os.path.isfile(FilePath):
                FilePathSet.add(FilePath)
    return FilePathSet


def GetFileListInDir(DirPath, recursive, filters = None):
    FilePathList = []

    if filters is None:
        filters = ['*', '.*']

    if not recursive:
        for f in filters:
            FilePathList.extend(glob.glob(os.path.join(DirPath, f)))
        return FilePathList
    else:
        return RecursiveFileScan(DirPath, filters)

def CompileYaraRules(YaraRulePathList, SaveDirectory):
    for path in YaraRulePathList:

        try:
            SavePath = os.path.join(SaveDirectory, os.path.basename(path))
            compiled = yara.compile(filepath=path, includes=True)
            compiled.save(SavePath)
        except Exception as e:
            print("[-] Could not compile the file {}. {}".format(path, e))


FileList = GetFileListInDir(SourceDirectory, False, ['*.yar'])
CompileYaraRules(FileList, OutputDirectory)
