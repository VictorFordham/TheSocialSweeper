import pymongo, socket
from TheSweeper.settings import MongoDB


def reportAllClear(uri):
    data = {
        "host": socket.gethostname(),
        "status": "SCAN_COMPLETE",
        "msg": "No malicious files found."
    }

    client = pymongo.MongoClient(uri)
    db = client[MongoDB]
    collection = db["status"]

    collection.insert_one(data)

    client.close()


def sendReport(uri, matches):
    for match in matches:
        match["matchList"] = [str(m) for m in match["matchList"]]

    client = pymongo.MongoClient(uri)
    db = client[MongoDB]
    collection = db["reports"]
    collection.insert_many(matches)

    collection = db[socket.gethostname()]
    collection.insert_many(matches)

    data = {
        "host": socket.gethostname(),
        "status": "SCAN_COMPLETE",
        "msg": "Malicious files found."
    }

    collection = db["status"]
    collection.insert_one(data)

    client.close()