from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient
import requests
import datetime
import config

app = Flask(__name__)
client = MongoClient(config.MONGO_URI)
db = client[config.DB_NAME]
queries = db.queries 
iocs = db.iocs 

VT_URL = "https://www.virustotal.com/api/v3"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

headers_vt = {"x-apikey": config.VIRUSTOTAL_API_KEY}
headers_abuse = {"Key": config.ABUSEIPDB_KEY, "Accept": "application/json"}

@app.route("/")
def home():
    recent = list(iocs.find().sort("ts", -1).limit(50))
    pipeline = [
        {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$ts"}}, "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]
    counts = list(iocs.aggregate(pipeline))
    return render_template("index.html", recent=recent, counts=counts)

@app.route("/lookup", methods=["POST"])
def lookup():
    data = request.json
    query = data.get("q")
    if not query:
        return jsonify({"error": "missing q"}), 400

    res = {"query": query, "ts": datetime.datetime.utcnow(), "results": {}}

    try:
        r = requests.get(ABUSE_URL, headers=headers_abuse, params={"ipAddress": query, "maxAgeInDays": 90})
        res_abuse = r.json()
        res["results"]["abuseipdb"] = res_abuse
    except Exception as e:
        res["results"]["abuseipdb_error"] = str(e)

    try:
        import re
        is_domain = bool(re.search(r"[a-zA-Z]", query))
        if is_domain:
            r = requests.get(f"{VT_URL}/domains/{query}", headers=headers_vt)
        else:
            r = requests.get(f"{VT_URL}/ip_addresses/{query}", headers=headers_vt)
        res_vt = r.json()
        res["results"]["virustotal"] = res_vt
    except Exception as e:
        res["results"]["virustotal_error"] = str(e)

    iocs.insert_one({"q": query, "ts": datetime.datetime.utcnow(), "data": res["results"]})
    queries.insert_one({"q": query, "ts": datetime.datetime.utcnow()})
    return jsonify(res)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
