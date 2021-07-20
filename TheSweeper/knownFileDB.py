from TheSweeper import defaultFileDB
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


def loadDefaultFileDatabase():
    return loadFileDatabase(defaultFileDB.database)