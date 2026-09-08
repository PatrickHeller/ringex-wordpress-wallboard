<?php
declare(strict_types=1);

ini_set('display_errors', '0'); // Für Live-Betrieb auf 0
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

date_default_timezone_set('Europe/Berlin');

// --- 1. AJAX Check ---
$isAjax = isset($_GET['ajax']) && $_GET['ajax'] === '1';

define('REFRESH_SECONDS', 300);
define('ANALYTICS_CACHE_TTL', 300);
define('SERVICE_LEVEL_THRESHOLD_SECONDS', 20); // Branchenüblicher Standard; bei Bedarf anpassen.

$config = parse_ini_file(__DIR__ . '/config_ex.ini', true, INI_SCANNER_TYPED);
if ($config === false || !isset($config['RingEX'])) {
    if ($isAjax) { echo json_encode(['error' => 'Config Fehler']); exit; }
    echo '<div style="color:red; padding:20px;">Config konnte nicht geladen werden. [RingEX]-Sektion fehlt.</div>';
    return;
}

$TOKEN_CACHE_FILE = __DIR__ . '/token_cache_ex.json';
$ANALYTICS_CACHE_FILE = __DIR__ . '/analytics_cache_today.json';

// --- DEINE ORIGINAL-FUNKTIONEN START ---

function format_duration($seconds): string {
    if ($seconds === null || $seconds === '') return '00:00:00';
    $seconds = max(0, (int)$seconds);
    $hours = floor($seconds / 3600);
    $minutes = floor(($seconds % 3600) / 60);
    $secs = $seconds % 60;
    return sprintf('%02d:%02d:%02d', $hours, $minutes, $secs);
}

function http_request(string $url, string $method = 'GET', array $headers = [], $data = null): array {
    $ch = curl_init();
    $headerLines = [];
    foreach ($headers as $key => $value) { $headerLines[] = $key . ': ' . $value; }
    $responseHeaders = [];
    curl_setopt_array($ch, [
        CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60,
        CURLOPT_HTTPHEADER => $headerLines, CURLOPT_CUSTOMREQUEST => strtoupper($method),
        CURLOPT_HEADERFUNCTION => function ($curl, $headerLine) use (&$responseHeaders) {
            $len = strlen($headerLine); $parts = explode(':', $headerLine, 2);
            if (count($parts) === 2) { $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]); }
            return $len;
        },
    ]);
    if (strtoupper($method) === 'POST') { curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, is_array($data) ? http_build_query($data) : $data); }
    $body = curl_exec($ch); $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $error = curl_error($ch);
    if ($body === false) { curl_close($ch); throw new RuntimeException('cURL-Fehler: ' . $error); }
    curl_close($ch);
    return ['status' => $status, 'body' => $body, 'json' => json_decode($body, true), 'headers' => $responseHeaders];
}

function load_token_cache(string $file): array {
    if (!file_exists($file)) return [];
    $json = file_get_contents($file); if ($json === false || trim($json) === '') return [];
    $data = json_decode($json, true); return is_array($data) ? $data : [];
}

function save_token_cache(string $file, array $data): void {
    $tmp = $file . '.tmp'; file_put_contents($tmp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX); rename($tmp, $file);
}

function load_json_cache(string $file, int $ttl): ?array {
    if (!file_exists($file)) return null;
    $raw = file_get_contents($file); if ($raw === false || trim($raw) === '') return null;
    $data = json_decode($raw, true); if (!is_array($data) || empty($data['created_at']) || !isset($data['records'])) return null;
    if ((time() - (int)$data['created_at']) > $ttl) return null;
    return $data['records'];
}

function save_json_cache(string $file, array $records): void {
    $payload = ['created_at' => time(), 'records' => $records];
    $tmp = $file . '.tmp'; file_put_contents($tmp, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX); rename($tmp, $file);
}

function build_basic_auth(string $clientId, string $clientSecret): string {
    return 'Basic ' . base64_encode($clientId . ':' . $clientSecret);
}

function login_with_jwt(array $ringex): array {
    $authUrl = $ringex['AUTH_URL'] ?? 'https://platform.ringcentral.com/restapi/oauth/token';
    $headers = ['Authorization' => build_basic_auth($ringex['CLIENT_ID'], $ringex['CLIENT_SECRET']), 'Accept' => 'application/json', 'Content-Type' => 'application/x-www-form-urlencoded'];
    $data = ['grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion' => $ringex['JWT_ASSERTION']];
    $response = http_request($authUrl, 'POST', $headers, $data);
    if ($response['status'] < 200 || $response['status'] >= 300 || empty($response['json']['access_token'])) { throw new RuntimeException('RingEX JWT Login Fehler: ' . $response['body']); }
    $json = $response['json'];
    return [
        'access_token' => $json['access_token'], 'token_type' => $json['token_type'] ?? 'Bearer', 'expires_at' => time() + (int)($json['expires_in'] ?? 3600) - 60,
        'refresh_token' => $json['refresh_token'] ?? null, 'refresh_token_expires_at' => isset($json['refresh_token_expires_in']) ? time() + (int)$json['refresh_token_expires_in'] - 60 : 0,
    ];
}

function refresh_token(array $ringex, array $cache): array {
    if (empty($cache['refresh_token'])) throw new RuntimeException('Kein Refresh-Token im Cache vorhanden.');
    if (!empty($cache['refresh_token_expires_at']) && time() >= (int)$cache['refresh_token_expires_at']) throw new RuntimeException('Refresh-Token ist abgelaufen.');
    $authUrl = $ringex['AUTH_URL'] ?? 'https://platform.ringcentral.com/restapi/oauth/token';
    $headers = ['Authorization' => build_basic_auth($ringex['CLIENT_ID'], $ringex['CLIENT_SECRET']), 'Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => 'application/json'];
    $data = ['grant_type' => 'refresh_token', 'refresh_token' => $cache['refresh_token']];
    $response = http_request($authUrl, 'POST', $headers, $data);
    if ($response['status'] < 200 || $response['status'] >= 300 || empty($response['json']['access_token'])) throw new RuntimeException('Refresh fehlgeschlagen: ' . $response['body']);
    $json = $response['json'];
    return [
        'access_token' => $json['access_token'], 'token_type' => $json['token_type'] ?? 'Bearer', 'expires_at' => time() + (int)($json['expires_in'] ?? 3600) - 60,
        'refresh_token' => $json['refresh_token'] ?? $cache['refresh_token'], 'refresh_token_expires_at' => isset($json['refresh_token_expires_in']) ? time() + (int)$json['refresh_token_expires_in'] - 60 : ($cache['refresh_token_expires_at'] ?? 0),
    ];
}

function refresh_or_login(array $ringex, string $cacheFile, array $cache): array {
    try {
        if (!empty($cache['refresh_token']) && !empty($cache['refresh_token_expires_at']) && time() < (int)$cache['refresh_token_expires_at']) {
            $newCache = refresh_token($ringex, $cache); save_token_cache($cacheFile, $newCache); return [$newCache['access_token'], $newCache['token_type']];
        }
    } catch (Throwable $e) {}
    $fresh = login_with_jwt($ringex); save_token_cache($cacheFile, $fresh);
    return [$fresh['access_token'], $fresh['token_type']];
}

function get_valid_token(array $ringex, string $cacheFile): array {
    $cache = load_token_cache($cacheFile);
    if (!empty($cache['access_token']) && !empty($cache['expires_at']) && time() < (int)$cache['expires_at']) { return [$cache['access_token'], $cache['token_type'] ?? 'Bearer']; }

    // Lock verhindert, dass parallele Requests (z.B. mehrere offene Wallboard-Tabs) gleichzeitig
    // denselben Refresh-Token einloesen und sich dabei gegenseitig invalidieren ("Token not found").
    $lockHandle = fopen($cacheFile . '.lock', 'c');
    if ($lockHandle === false) { return refresh_or_login($ringex, $cacheFile, $cache); }
    flock($lockHandle, LOCK_EX);
    try {
        $cache = load_token_cache($cacheFile);
        if (!empty($cache['access_token']) && !empty($cache['expires_at']) && time() < (int)$cache['expires_at']) { return [$cache['access_token'], $cache['token_type'] ?? 'Bearer']; }
        return refresh_or_login($ringex, $cacheFile, $cache);
    } finally {
        flock($lockHandle, LOCK_UN); fclose($lockHandle);
    }
}

function get_call_queues(array $ringex, string $cacheFile): array {
    [$token, $tokenType] = get_valid_token($ringex, $cacheFile);
    $baseUrl = rtrim($ringex['BASE_URL'], '/'); $accountId = $ringex['ACCOUNT_ID'] ?? '~';
    $headers = ['Authorization' => $tokenType . ' ' . $token, 'Accept' => 'application/json'];
    $url = $baseUrl . '/restapi/v1.0/account/' . $accountId . '/extension?extensionType=Department&status=Enabled&perPage=1000';
    $response = http_request($url, 'GET', $headers);
    if ($response['status'] === 401) {
        @unlink($cacheFile);
        [$token, $tokenType] = get_valid_token($ringex, $cacheFile);
        $headers['Authorization'] = $tokenType . ' ' . $token;
        $response = http_request($url, 'GET', $headers);
    }
    if ($response['status'] < 200 || $response['status'] >= 300 || !is_array($response['json'])) throw new RuntimeException('Queue-Liste Fehler: ' . $response['body']);
    $queues = [];
    foreach ($response['json']['records'] ?? [] as $q) {
        // RC haelt den 'extensionType=Department'-Filter nicht strikt ein und liefert auch
        // einzelne User- oder Voicemail-Extensions mit; nur echte Department-Extensions sind Queues.
        if ((string)($q['type'] ?? '') !== 'Department') continue;
        $id = (string)($q['id'] ?? ''); if ($id === '') continue;
        $queues[$id] = ['id' => $id, 'name' => (string)($q['name'] ?? 'Unbekannt'), 'ext' => (string)($q['extensionNumber'] ?? ''), 'offered' => 0, 'answered' => 0, 'missed' => 0, 'voicemail' => 0, 'total_duration' => 0, 'total_wait' => 0, 'sl_met' => 0, 'rc_sla_in' => 0, 'rc_sla_out' => 0];
    }
    return $queues;
}

function find_wait_time_seconds(array $record): int {
    // Wartezeit = Zeitpunkt, an dem der tatsächlich annehmende Leg zu klingeln beginnt, relativ zum
    // Anrufstart. Der 'master'-Leg und ein evtl. Queue-eigener Duplikat-Leg (Offset ~0) sind keine
    // echten Geräte-Legs; der späteste Leg mit result 'Accepted'/'Call connected' ist der richtige
    // (deckt auch extern weitergeleitete Anrufe ab, deren Leg-Result 'Call connected' statt 'Accepted' ist).
    $callStart = strtotime((string)($record['startTime'] ?? ''));
    if ($callStart === false) return 0;
    $bestOffset = null;
    foreach ($record['legs'] ?? [] as $leg) {
        if (!empty($leg['master'])) continue;
        $result = strtolower((string)($leg['result'] ?? ''));
        if ($result !== 'accepted' && $result !== 'call connected') continue;
        $legStart = strtotime((string)($leg['startTime'] ?? ''));
        if ($legStart === false) continue;
        $offset = $legStart - $callStart;
        if ($bestOffset === null || $offset > $bestOffset) { $bestOffset = $offset; }
    }
    return $bestOffset !== null ? max(0, $bestOffset) : 0;
}

function fetch_queue_sla(array $ringex, string $cacheFile, string $accountId, array $queueIds, string $todayStart, string $todayEnd): array {
    // RCs offizielles Queue-SLA-Feld (Business Analytics Aggregate API). Achtung: im Livetest entsprach
    // inSla+outOfSla durchgehend genau der Anzahl NICHT angenommener Anrufe (nicht der angenommenen) —
    // die genaue Definition (evtl. Abbruch-Timing statt Antwort-Timing) ist von RC nicht dokumentiert.
    // Bewusst separat von der eigenen, verifizierten Service-Level-Berechnung angezeigt.
    if (empty($queueIds)) return [];
    [$token, $tokenType] = get_valid_token($ringex, $cacheFile);
    $baseUrl = rtrim($ringex['BASE_URL'], '/');
    $headers = ['Authorization' => $tokenType . ' ' . $token, 'Accept' => 'application/json', 'Content-Type' => 'application/json'];
    $body = [
        'grouping' => ['groupBy' => 'Queues', 'keys' => array_values($queueIds)],
        'timeSettings' => ['timeZone' => 'Europe/Berlin', 'timeRange' => ['timeFrom' => $todayStart, 'timeTo' => $todayEnd]],
        'callFilters' => ['directions' => ['Inbound']],
        'responseOptions' => ['counters' => ['callsByQueueSla' => ['aggregationType' => 'Sum']]],
    ];
    $url = $baseUrl . '/analytics/calls/v1/accounts/' . $accountId . '/aggregation/fetch';
    $response = http_request($url, 'POST', $headers, json_encode($body));
    if ($response['status'] === 401) {
        @unlink($cacheFile); [$token, $tokenType] = get_valid_token($ringex, $cacheFile);
        $headers['Authorization'] = $tokenType . ' ' . $token;
        $response = http_request($url, 'POST', $headers, json_encode($body));
    }
    if ($response['status'] < 200 || $response['status'] >= 300 || !is_array($response['json'])) {
        return []; // Zusatz-KPI: bei Fehlern lieber weglassen statt das ganze Board zu blockieren.
    }
    $result = [];
    foreach ($response['json']['data']['records'] ?? [] as $rec) {
        $qid = (string)($rec['key'] ?? ''); if ($qid === '') continue;
        $sla = $rec['counters']['callsByQueueSla']['values'] ?? [];
        $result[$qid] = ['in' => (int)($sla['inSla'] ?? 0), 'out' => (int)($sla['outOfSla'] ?? 0)];
    }
    return $result;
}

function get_queue_call_stats(array $ringex, string $cacheFile, string $statsCacheFile, string $accountId, array $queues): array {
    $cached = load_json_cache($statsCacheFile, ANALYTICS_CACHE_TTL);
    if (is_array($cached)) return $cached;

    [$token, $tokenType] = get_valid_token($ringex, $cacheFile);
    $baseUrl = rtrim($ringex['BASE_URL'], '/');
    $headers = ['Authorization' => $tokenType . ' ' . $token, 'Accept' => 'application/json'];

    $tz = new DateTimeZone('Europe/Berlin');
    $utc = new DateTimeZone('UTC');
    $start = new DateTime('today', $tz); $end = new DateTime('now', $tz);
    $start->setTimezone($utc); $end->setTimezone($utc);
    $todayStart = $start->format('Y-m-d\TH:i:s.000\Z'); $todayEnd = $end->format('Y-m-d\TH:i:s.000\Z');

    // Die Analytics-API (dimension=Queues, hops[]) bildet extern weitergeleitete/eskalierte Anrufe
    // nicht vollständig ab (der erfolgreiche Ziel-Hop fehlt dort komplett, siehe z.B. Session
    // s-a3081172b493dz1a057766374z218763b0000: alle Hops 'NotAnswered', klassisches Call-Log aber
    // 'Accepted'). Das klassische Call-Log pro Queue-Extension liefert 'result'/'duration' direkt
    // und korrekt (Sekunden), daher hier statt Analytics verwendet.
    foreach ($queues as $queueId => &$queue) {
        $page = 1; $perPage = 250; $maxPages = 10;
        do {
            $url = $baseUrl . '/restapi/v1.0/account/' . $accountId . '/extension/' . $queueId
                . '/call-log?direction=Inbound&type=Voice&view=Detailed&dateFrom=' . $todayStart
                . '&dateTo=' . $todayEnd . '&page=' . $page . '&perPage=' . $perPage;
            $response = http_request($url, 'GET', $headers);
            if ($response['status'] === 429) {
                $retryAfter = (int)($response['headers']['retry-after'] ?? 60);
                throw new RuntimeException('Rate Limit erreicht. Bitte in ca. ' . $retryAfter . ' Sekunden erneut laden.');
            }
            if ($response['status'] === 401) {
                @unlink($cacheFile); [$token, $tokenType] = get_valid_token($ringex, $cacheFile);
                $headers['Authorization'] = $tokenType . ' ' . $token;
                $response = http_request($url, 'GET', $headers);
            }
            if ($response['status'] < 200 || $response['status'] >= 300 || !is_array($response['json'])) throw new RuntimeException('Call-Log Fehler: ' . $response['body']);
            foreach ($response['json']['records'] ?? [] as $record) {
                $queue['offered']++;
                $result = strtolower((string)($record['result'] ?? ''));
                $duration = (int)($record['duration'] ?? 0);
                if ($result === 'accepted') {
                    $queue['answered']++; $queue['total_duration'] += $duration;
                    $wait = find_wait_time_seconds($record);
                    $queue['total_wait'] += $wait;
                    if ($wait <= SERVICE_LEVEL_THRESHOLD_SECONDS) { $queue['sl_met']++; }
                }
                elseif ($result === 'voicemail') { $queue['voicemail']++; }
                else { $queue['missed']++; } // 'Missed', 'Callback requested' u.ä. gelten als nicht angenommen
            }
            $hasNext = isset($response['json']['navigation']['nextPage']);
            $page++; usleep(200000);
        } while ($hasNext && $page <= $maxPages);
    }
    unset($queue);

    $slaData = fetch_queue_sla($ringex, $cacheFile, $accountId, array_keys($queues), $todayStart, $todayEnd);
    foreach ($queues as $queueId => &$queue) {
        $queue['rc_sla_in'] = $slaData[$queueId]['in'] ?? 0;
        $queue['rc_sla_out'] = $slaData[$queueId]['out'] ?? 0;
    }
    unset($queue);

    uasort($queues, fn($a, $b) => strcasecmp((string)$a['name'], (string)$b['name']));
    save_json_cache($statsCacheFile, $queues);
    return $queues;
}
// --- DEINE ORIGINAL-FUNKTIONEN ENDE ---

$error = null;
$queues = [];
$recordsCount = 0;

try {
    $accountId = $config['RingEX']['ACCOUNT_ID'] ?? '~';
    $queues = get_call_queues($config['RingEX'], $TOKEN_CACHE_FILE);
    $queues = get_queue_call_stats($config['RingEX'], $TOKEN_CACHE_FILE, $ANALYTICS_CACHE_FILE, (string)$accountId, $queues);
    $recordsCount = array_sum(array_map(fn($q) => (int)$q['offered'], $queues));
} catch (Throwable $e) {
    $error = $e->getMessage();
}

$totalQueues = count($queues);
$totalOffered = array_sum(array_map(fn($q) => (int)$q['offered'], $queues));
$totalAnswered = array_sum(array_map(fn($q) => (int)$q['answered'], $queues));
$totalMissed = array_sum(array_map(fn($q) => (int)$q['missed'], $queues));
$totalVoicemail = array_sum(array_map(fn($q) => (int)$q['voicemail'], $queues));
$totalDuration = array_sum(array_map(fn($q) => (int)$q['total_duration'], $queues));
$avgDurationAll = $totalAnswered > 0 ? intdiv($totalDuration, $totalAnswered) : 0;
$totalWait = array_sum(array_map(fn($q) => (int)$q['total_wait'], $queues));
$avgWaitAll = $totalAnswered > 0 ? intdiv($totalWait, $totalAnswered) : 0;
$totalSlMet = array_sum(array_map(fn($q) => (int)$q['sl_met'], $queues));
$serviceLevel = $totalOffered > 0 ? round(($totalSlMet / $totalOffered) * 100, 1) : 0;
$totalRcSlaIn = array_sum(array_map(fn($q) => (int)$q['rc_sla_in'], $queues));
$totalRcSlaOut = array_sum(array_map(fn($q) => (int)$q['rc_sla_out'], $queues));
$rcSla = ($totalRcSlaIn + $totalRcSlaOut) > 0 ? round(($totalRcSlaIn / ($totalRcSlaIn + $totalRcSlaOut)) * 100, 1) : 0;
$answerRate = $totalOffered > 0 ? round(($totalAnswered / $totalOffered) * 100, 1) : 0;
$lastUpdate = date('H:i:s');


// --- 2. HTML BEREICH GENERIEREN ---
ob_start();

if ($error !== null): ?>
    <div class="error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
<?php else: ?>

    <!-- KPI Leiste -->
    <div class="kpi-bar">
        <div class="kpi"><span class="kpi__label">Queues</span><span class="kpi__value"><?= $totalQueues ?></span></div>
        <div class="kpi"><span class="kpi__label">Records heute</span><span class="kpi__value muted"><?= $recordsCount ?></span></div>
        <div class="kpi"><span class="kpi__label">Angeboten</span><span class="kpi__value"><?= $totalOffered ?></span></div>
        <div class="kpi"><span class="kpi__label">Angenommen</span><span class="kpi__value green"><?= $totalAnswered ?></span></div>
        <div class="kpi"><span class="kpi__label">Verpasst</span><span class="kpi__value red"><?= $totalMissed ?></span></div>
        <div class="kpi"><span class="kpi__label">Voicemail</span><span class="kpi__value yellow"><?= $totalVoicemail ?></span></div>
        <div class="kpi"><span class="kpi__label">Ø Gesprächszeit</span><span class="kpi__value"><?= format_duration($avgDurationAll) ?></span></div>
        <div class="kpi"><span class="kpi__label">Ø Wartezeit</span><span class="kpi__value"><?= format_duration($avgWaitAll) ?></span></div>
        <div class="kpi"><span class="kpi__label">Service Level (<?= SERVICE_LEVEL_THRESHOLD_SECONDS ?>s)</span><span class="kpi__value green"><?= number_format($serviceLevel, 1, ',', '.') ?>%</span></div>
        <div class="kpi"><span class="kpi__label">RC SLA</span><span class="kpi__value muted"><?= number_format($rcSla, 1, ',', '.') ?>%</span></div>
        <div class="kpi"><span class="kpi__label">Antwortquote</span><span class="kpi__value green"><?= number_format($answerRate, 1, ',', '.') ?>%</span></div>
    </div>
    <p style="margin: 4px 0 0; font-size: 0.75em; color: #94a3b8;">"RC SLA" = RingCentrals eigenes Queue-SLA-Feld (callsByQueueSla) — Definition von RC nicht dokumentiert, Zahlen weichen von "Service Level" oben ab.</p>

    <!-- Tabelle -->
    <div class="content">
        <h3 class="section-title">Queue Anrufvolumen heute</h3>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Queue</th><th>Durchwahl</th><th>Angeboten</th><th>Angenommen</th>
                        <th>Verpasst</th><th>Voicemail</th><th>Gesamt Gesprächszeit</th>
                        <th>Ø Gesprächszeit</th><th>Ø Wartezeit</th><th>Service Level</th><th>RC SLA</th><th>Antwortquote</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($queues as $q):
                        $avgDuration = ((int)$q['answered'] > 0) ? intdiv((int)$q['total_duration'], (int)$q['answered']) : 0;
                        $avgWait = ((int)$q['answered'] > 0) ? intdiv((int)$q['total_wait'], (int)$q['answered']) : 0;
                        $queueServiceLevel = ((int)$q['offered'] > 0) ? round(((int)$q['sl_met'] / (int)$q['offered']) * 100, 1) : 0;
                        $queueSlaTotal = (int)$q['rc_sla_in'] + (int)$q['rc_sla_out'];
                        $queueRcSla = ($queueSlaTotal > 0) ? round(((int)$q['rc_sla_in'] / $queueSlaTotal) * 100, 1) : 0;
                        $queueAnswerRate = ((int)$q['offered'] > 0) ? round(((int)$q['answered'] / (int)$q['offered']) * 100, 1) : 0;
                    ?>
                    <tr>
                        <td style="font-weight: 500; color: #2c3e50;"><?= htmlspecialchars($q['name'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td><?= htmlspecialchars($q['ext'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td class="num"><?= (int)$q['offered'] ?></td>
                        <td class="num num-green"><?= (int)$q['answered'] ?></td>
                        <td class="num num-red"><?= (int)$q['missed'] ?></td>
                        <td class="num num-yellow"><?= (int)$q['voicemail'] ?></td>
                        <td class="num"><?= format_duration($q['total_duration']) ?></td>
                        <td class="num"><?= format_duration($avgDuration) ?></td>
                        <td class="num"><?= format_duration($avgWait) ?></td>
                        <td class="num"><?= number_format($queueServiceLevel, 1, ',', '.') ?>%</td>
                        <td class="num" style="color: #94a3b8;"><?= number_format($queueRcSla, 1, ',', '.') ?>%</td>
                        <td class="num num-green"><?= number_format($queueAnswerRate, 1, ',', '.') ?>%</td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

<?php endif; 

$dynamicHtml = ob_get_clean();

// --- 3. AJAX ANTWORT ---
if ($isAjax) {
    header('Content-Type: application/json');
    echo json_encode(['html' => $dynamicHtml, 'lastUpdate' => $lastUpdate]);
    exit; 
}
?>

<!-- --- 4. INITIALER AUFBAU FÜR WORDPRESS --- -->
<div class="ringex-wrapper">
    <style>
        /* Helles Theme analog zum CX Dashboard */
        .ringex-wrapper {
            font-family: inherit;
            background: #ffffff;
            color: #333333;
            padding: 0; 
            margin: 20px 0;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
            border-radius: 8px;
            border: 1px solid #e2e8f0;
            overflow: hidden;
        }

        .ringex-wrapper *, .ringex-wrapper *::before, .ringex-wrapper *::after { box-sizing: border-box; }

        .ringex-wrapper .header-bar {
            background: #f8fafc; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; flex-wrap: wrap; gap: 8px;
        }

        .ringex-wrapper .header-title { color: #0f172a; font-size: 1.25rem; font-weight: 600; margin: 0; letter-spacing: -0.025em; }
        
        .ringex-wrapper .timer-stats { text-align: right; }
        .ringex-wrapper .timer-label { color: #64748b; font-size: 11px; text-transform: uppercase; font-weight: 600; }
        .ringex-wrapper .timer-val { color: #0f172a; font-family: inherit; font-size: 1.1em; font-weight: 700; margin-left: 4px; }

        /* KPI Cards Styling */
        .ringex-wrapper .kpi-bar { display: flex; flex-wrap: wrap; gap: 15px; padding: 20px 24px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; }
        .ringex-wrapper .kpi { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px 20px; min-width: 130px; text-align: center; box-shadow: 0 1px 2px rgba(0,0,0,0.02); flex: 1; }
        .ringex-wrapper .kpi__label { color: #64748b; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 8px; font-weight: 600; }
        .ringex-wrapper .kpi__value { font-family: inherit; font-size: 1.7em; font-weight: 700; color: #0f172a; }
        
        /* KPI Colors (Light Theme Adapted) */
        .ringex-wrapper .kpi__value.green, .ringex-wrapper .num-green { color: #166534; }
        .ringex-wrapper .kpi__value.yellow, .ringex-wrapper .num-yellow { color: #b45309; }
        .ringex-wrapper .kpi__value.red, .ringex-wrapper .num-red { color: #b91c1c; }
        .ringex-wrapper .kpi__value.muted { color: #94a3b8; }

        .ringex-wrapper .content { padding: 24px; }
        .ringex-wrapper .section-title { color: #334155; font-size: 1.1em; font-weight: 600; margin: 0 0 16px 0; text-transform: uppercase; letter-spacing: 0.05em; }

        .ringex-wrapper .error { margin: 20px; padding: 15px 20px; background: #fef2f2; border: 1px solid #f87171; border-radius: 6px; color: #b91c1c; }
        
        .ringex-wrapper .hint { margin: 20px 24px 0; padding: 12px 16px; background: #f1f5f9; color: #475569; border-radius: 6px; font-size: 0.9em; border-left: 4px solid #cbd5e1; }
        .ringex-wrapper .hint code { background: #e2e8f0; padding: 2px 4px; border-radius: 4px; color: #0f172a; font-family: monospace; font-size: 0.9em; }

        /* Tabelle */
        .ringex-wrapper .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
        .ringex-wrapper table { width: 100%; border-collapse: collapse; margin: 0; font-size: 14px; }
        .ringex-wrapper th { color: #64748b; font-size: 11px; text-transform: uppercase; font-weight: 600; padding: 12px 8px; text-align: left; white-space: nowrap; border-bottom: 2px solid #e2e8f0; background: #f8fafc; }
        .ringex-wrapper td { padding: 13px 8px; white-space: nowrap; border-bottom: 1px solid #e2e8f0; color: #475569; }
        .ringex-wrapper tr:hover td { background-color: #f8fafc; }
        .ringex-wrapper .num { font-family: inherit; font-size: 0.95em; }

    </style>

    <div class="header-bar">
        <h2 class="header-title">RingEX Queue Volume Dashboard</h2>
        <div class="timer-stats">
            <div class="timer-label">Last Data Sync: <span id="sync-time" class="timer-val"><?= htmlspecialchars($lastUpdate, ENT_QUOTES, 'UTF-8') ?></span></div>
            <div class="timer-label" style="margin-top: 4px;">Refresh in: <span id="sec-counter" class="timer-val"><?= REFRESH_SECONDS ?></span>s</div>
        </div>
    </div>

    <!-- Container für den AJAX-Austausch -->
    <div id="ringex-dynamic-content">
        <?= $dynamicHtml ?>
    </div>

    <script>
        // Der EX Code nutzt einen Countdown statt eines "Zählers hoch"
        let seconds = <?= REFRESH_SECONDS ?>;
        
        setInterval(function () {
            seconds--;
            if (seconds < 0) seconds = 0;
            document.getElementById('sec-counter').textContent = seconds;
        }, 1000);

        // Fetch alle X Sekunden (REFRESH_SECONDS in Millisekunden)
        setInterval(function() {
            // URL zur Datei inklusive ?ajax=1 im Theme-Ordner
            const ajaxUrl = '/wp-content/themes/twentyseventeen/ringex-app/dashboard_ex.php?ajax=1';
            
            fetch(ajaxUrl)
                .then(response => {
                    if (!response.ok) throw new Error('Netzwerkfehler');
                    return response.json();
                })
                .then(data => {
                    if (data.html) {
                        document.getElementById('ringex-dynamic-content').innerHTML = data.html;
                        document.getElementById('sync-time').textContent = data.lastUpdate;
                        // Countdown wieder zurücksetzen
                        seconds = <?= REFRESH_SECONDS ?>;
                        document.getElementById('sec-counter').textContent = seconds;
                    }
                })
                .catch(error => console.error('EX Dashboard Fetch Fehler:', error));
        }, <?= REFRESH_SECONDS * 1000 ?>);
    </script>
</div>
