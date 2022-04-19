import pymongo, socket
from pymongo.errors import PyMongoError
from TheSweeper import commonFunctions, logger
from TheSweeper.settings import MongoDB
#comment

def reportAllClear(uri):
    data = {
        "host": socket.gethostname(),
        "status": "SCAN_COMPLETE",
        "msg": "Scan Complete, no PII found"
    }

    client = pymongo.MongoClient(uri)
    db = client[MongoDB]
    collection = db["status"]

    try:
        collection.insert_one(data)
    except PyMongoError as e:
        commonFunctions.PrintVerbose(f"[-] ERROR: Failed to send report to database, {e}")
        logger.LogError(e, "reportToMongo")
        client.close()


def sendReport(uri, matches):
    data = {
        "host": socket.gethostname(),
        "status": "SCAN_COMPLETE",
        "msg": "PII Found"
    }

    for match in matches:
        match["matchList"] = [str(m) for m in match["matchList"]]

    client = pymongo.MongoClient(uri)
    db = client[MongoDB]
    reports_collection = db["reports"]
    host_collection = db[socket.gethostname()]
    status_collection = db["status"]

    try:
        reports_collection.insert_many(matches)
        host_collection.insert_many(matches)
        status_collection.insert_one(data)
    except PyMongoError as e:
        commonFunctions.PrintVerbose(f"[-] ERROR: Failed to send report to database, {e}")
        logger.LogError(e, "reportToMongo")
        client.close()
