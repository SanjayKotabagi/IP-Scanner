<!DOCTYPE html>
<html>
<head>
    <title>SOC IP Intelligence Panel</title>

    <style>
        body { background:#0d1117; color:#c9d1d9; font-family:Consolas; margin:0; }
        .header { padding:15px 20px; background:#161b22; border-bottom:1px solid #30363d; }
        .container { padding:20px; }

        textarea {
            width:100%; height:120px;
            background:#0d1117; color:#c9d1d9;
            border:1px solid #30363d; padding:10px;
        }

        button {
            margin-top:10px; padding:10px 20px;
            background:#238636; border:none; color:white; cursor:pointer;
        }

        table { width:100%; margin-top:20px; border-collapse:collapse; }
        th, td { border:1px solid #30363d; padding:10px; }
        th { background:#161b22; }

        .malicious { color:#ff4d4d; font-weight:bold; }
        .suspicious { color:#ffa500; font-weight:bold; }
        .clean { color:#3fb950; font-weight:bold; }
    </style>
</head>

<body>

<div class="header">SOC Threat Intelligence Panel</div>

<div class="container">

    <textarea id="ips" placeholder="Enter IPs (one per line)"></textarea><br>
    <button onclick="scanIPs()">Run Scan</button>
    <button onclick="copyResults()">Copy Results</button>
    <table>
        <thead>
            <tr>
                <th>IP</th>
                <th>Verdict</th>
                <th>VT Score</th>
                <th>VT Status</th>
                <th>Abuse Score</th>
                <th>Abuse Details</th>
            </tr>
        </thead>
        <tbody id="results"></tbody>
    </table>

</div>

<script>
    
function copyResults() {
    let rows = document.querySelectorAll("#results tr");

    let output = "";

    for (let row of rows) {
        let cols = row.querySelectorAll("td");

        if (cols.length === 0) continue;

        let ip = cols[0].innerText;
        let verdict = cols[1].innerText;
        let vt_score = cols[2].innerText;
        let vt_status = cols[3].innerText;
        let abuse_score = cols[4].innerText;
        let abuse_details_raw = cols[5].innerText;

        let abuse_details = {};
        try {
            abuse_details = JSON.parse(abuse_details_raw);
        } catch {}

        let isp = abuse_details.ISP || "";

        output +=
`IP : ${ip}
Verdict : ${verdict}
VT Score : ${vt_score}
VT Status : ${vt_status}
Abuse Score : ${abuse_score}
Abuse Details : ${abuse_details_raw}
ISP : ${isp}
---------------------------
`;
    }

    navigator.clipboard.writeText(output);
}

async function scanIPs() {
    let ips = document.getElementById("ips").value.trim().split(/\s+/);
    let table = document.getElementById("results");

    table.innerHTML = "";

    for (let ip of ips) {

        let res = await fetch("scan_single.php", {
            method: "POST",
            headers: {"Content-Type": "application/x-www-form-urlencoded"},
            body: "ip=" + encodeURIComponent(ip)
        });

        let data = await res.json();

        let row = `
        <tr>
            <td>${data.ip}</td>
            <td class="${data.verdict.toLowerCase()}">${data.verdict}</td>
            <td>${data.vt_score}</td>
            <td>${data.vt_status}</td>
            <td>${data.abuse_score}</td>
            <td>${JSON.stringify(data.abuse_details)}</td>
        </tr>`;

        table.innerHTML += row;

        await new Promise(r => setTimeout(r, 16000)); // API rate limit
    }
}
</script>
<div style="
    margin-top:40px;
    padding:15px;
    text-align:center;
    border-top:1px solid #30363d;
    color:#8b949e;
    font-size:13px;
">
    Built after questioning life choices at 3AM.  
    Powered by APIs, caffeine, and questionable decisions.  
    <br><br>
    Dev: <a href="https://github.com/SanjayKotabagi/" target="_blank" style="color:#58a6ff; text-decoration:none;">
        github.com/SanjayKotabagi
    </a>
</div>
</body>
</html>