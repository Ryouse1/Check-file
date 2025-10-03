from flask import Flask, request, jsonify, render_template
import requests
import time

API_KEY = "3136f2283c052466d83c13a6f20f95374dd3fbb3e05fea45031f4a198fa75dc2"
MAX_FILE_SIZE = 32 * 1024 * 1024

app = Flask(__name__)
analyses_cache = {}  # 簡易キャッシュ

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    if 'file' not in request.files:
        return jsonify({"error": "ファイル未選択"}), 400
    file = request.files['file']
    content = file.read()
    if len(content) > MAX_FILE_SIZE:
        return jsonify({"error": "ファイルが大きすぎます"}), 400

    files = {'file': (file.filename, content)}
    headers = {"x-apikey": API_KEY}
    response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers).json()
    file_id = response.get("data", {}).get("id")
    if not file_id:
        return jsonify({"error": "アップロード失敗", "data": response}), 500

    analyses_cache[file_id] = None
    return jsonify({"id": file_id})

@app.route("/result/<file_id>")
def result(file_id):
    headers = {"x-apikey": API_KEY}
    analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{file_id}", headers=headers).json()
    status = analysis.get("data", {}).get("attributes", {}).get("status")
    if status != "completed":
        return jsonify({"status": status})

    stats = analysis["data"]["attributes"]["stats"]
    results = analysis["data"]["attributes"].get("results", {})
    engines = {av: info.get("category") if info else None for av, info in results.items()}

    result_data = {
        "status": "completed",
        "detected": stats.get("malicious", 0),
        "total": sum(stats.values()),
        "engines": engines
    }
    analyses_cache[file_id] = result_data
    return jsonify(result_data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
