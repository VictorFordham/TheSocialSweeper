import pymongo


def sendReport(uri, matches):
    for match in matches:
        match["matchList"] = [str(m) for m in match["matchList"]]

    client = pymongo.MongoClient(uri)
    db = client["Sweeper-Test"]
    collection = db["reports"]

    collection.insert_many(matches)

    client.close()