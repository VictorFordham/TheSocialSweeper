import requests as fetch


def sendReport(url, matches):
    for match in matches:
        match["matchList"] = [str(m) for m in match["matchList"]]

    data = { "results": matches }
    fetch.post(url, json=data)