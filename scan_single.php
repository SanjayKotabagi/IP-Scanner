<?php
header('Content-Type: application/json');


$VT_API_KEY = "c0e98bb5e478ab006c5fdd2f2885716ba42a7bc702c562d3e52045d366555f8b";
$ABUSE_API_KEY = "7f9db76fcbbac17849fd0af6dfd53178dd473cf185585d2f42b2a88bfaee3d153ba3dca884e0570d";

$ip = $_POST['ip'] ?? '';

function checkVirusTotal($ip, $apiKey) {
    $url = "https://www.virustotal.com/api/v3/ip_addresses/" . $ip;

    $opts = [
        "http" => [
            "method" => "GET",
            "header" => "x-apikey: $apiKey"
        ]
    ];

    $res = file_get_contents($url, false, stream_context_create($opts));
    if (!$res) return ["Error", "Error", 0, 0];

    $data = json_decode($res, true);
    $stats = $data['data']['attributes']['last_analysis_stats'];

    $m = $stats['malicious'] ?? 0;
    $s = $stats['suspicious'] ?? 0;
    $h = $stats['harmless'] ?? 0;

    $score = "M:$m S:$s H:$h";

    // FIXED STATUS LOGIC (not overly aggressive)
    if ($m > 5) $status = "Malicious";
    elseif ($m > 0 || $s > 0) $status = "Suspicious";
    else $status = "Clean";

    return [$score, $status, $m, $s];
}

function checkAbuseIPDB($ip, $apiKey) {
    $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90";

    $opts = [
        "http" => [
            "method" => "GET",
            "header" => "Key: $apiKey\r\nAccept: application/json"
        ]
    ];

    $res = file_get_contents($url, false, stream_context_create($opts));
    if (!$res) return [0, []];

    $data = json_decode($res, true)['data'];

    return [
        $data['abuseConfidenceScore'],
        [
            "ISP" => $data['isp'] ?? "",
            "Country" => $data['countryCode'] ?? "",
            "Reports" => $data['totalReports'] ?? 0
        ]
    ];
}

function getVerdict($m, $s, $abuseScore) {

    // CONSISTENT SOC LOGIC
    if ($m > 5 || $abuseScore >= 75) return "Malicious";

    if ($m > 0 || $s > 0 || ($abuseScore >= 25 && $abuseScore < 75))
        return "Suspicious";

    return "Clean";
}

list($vt_score, $vt_status, $m, $s) = checkVirusTotal($ip, $VT_API_KEY);
list($abuse_score, $abuse_details) = checkAbuseIPDB($ip, $ABUSE_API_KEY);

echo json_encode([
    "ip" => $ip,
    "verdict" => getVerdict($m, $s, $abuse_score),
    "vt_score" => $vt_score,
    "vt_status" => $vt_status,
    "abuse_score" => $abuse_score,
    "abuse_details" => $abuse_details
]);