#from TheSweeper import settings
# need to add a variable to settings to be the
# path to the known hash file
# this will be a binary file of all known
# hashes concatenated together
# since we simply seek identification md5 should suffice


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


if __name__ == "__main__":
    from hashlib import md5
    from time import time
    def genTestSet():
        setOfHashes = set()
        for i in range(200_000):
            r = md5(bytes(i))
            setOfHashes.add(r.digest())
    
        return setOfHashes
        
    #s = genTestSet()

    #print(s)

    path = "../test"
    #start = time()
    #storeKnownFiles(path, s)
    #print(time() - start)
    start = time()
    o = loadKnownFiles(path)
    print(time() - start)
    #print(o)
    
    #print(o == s)