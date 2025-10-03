const form = document.getElementById("uploadForm");
const fileInput = document.getElementById("fileInput");
const progressContainer = document.getElementById("progressContainer");
const progress = document.getElementById("progress");
const resultContainer = document.getElementById("resultContainer");
const summary = document.getElementById("summary");
const resultTable = document.getElementById("resultTable");

form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const file = fileInput.files[0];
    if (!file) return;

    progressContainer.style.display = "block";
    resultContainer.style.display = "none";
    progress.style.width = "0%";

    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch("/scan", { method: "POST", body: formData });
    const data = await response.json();

    // ポーリングでスキャン完了待機
    let analysisId = data.id;
    let attempts = 0;
    while (attempts < 10) {
        const res = await fetch(`/result/${analysisId}`);
        const result = await res.json();
        if (result.status === "completed") {
            displayResult(result);
            break;
        } else {
            progress.style.width = `${(attempts + 1) * 10}%`;
            await new Promise(r => setTimeout(r, 3000));
            attempts++;
        }
    }
});

function displayResult(result) {
    progress.style.width = "100%";
    summary.textContent = `検出率: ${result.detected} / ${result.total}`;
    resultTable.innerHTML = `<tr><th>アンチウイルス</th><th>判定</th></tr>`;
    for (const [av, res] of Object.entries(result.engines)) {
        const row = document.createElement("tr");
        row.innerHTML = `<td>${av}</td><td>${res || 'Clean'}</td>`;
        resultTable.appendChild(row);
    }
    resultContainer.style.display = "block";
}
