from flask import Flask, request, render_template
import requests
import time

API_KEY = "3136f2283c052466d83c13a6f20f95374dd3fbb3e05fea45031f4a198fa75dc2"
MAX_FILE_SIZE = 32 * 1024 * 1024  # 32MB

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    if 'file' not in request.files:
        return "ファイルが選択されていません"

    file = request.files['file']
    file_content = file.read()
    if len(file_content) > MAX_FILE_SIZE:
        return "ファイルが大きすぎます（最大32MB）"

    files = {'file': (file.filename, file_content)}
    headers = {"x-apikey": API_KEY}

    # ファイルアップロード
    response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)
    data = response.json()

    file_id = data.get("data", {}).get("id")
    if not file_id:
        return render_template("index.html", result={"error": "アップロード失敗", "data": data})

    # スキャン完了まで待機（ポーリング）
    for _ in range(10):
        analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{file_id}", headers=headers).json()
        status = analysis.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            break
        time.sleep(3)
    else:
        return "スキャン完了までタイムアウトしました"

    stats = analysis["data"]["attributes"]["stats"]
    engines = {}
    results = analysis["data"]["attributes"].get("results", {})
    for av, info in results.items():
        engines[av] = info.get("category") if info else None

    result_data = {
        "detected": stats.get("malicious", 0),
        "total": sum(stats.values()),
        "engines": engines
    }

    return render_template("index.html", result=result_data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
