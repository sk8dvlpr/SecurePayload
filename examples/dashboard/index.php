<?php

declare(strict_types=1);

/**
 * Dashboard Admin read-only SecurePayload  — READ-ONLY TOTAL.
 *
 * Menampilkan ringkasan event keamanan dari file JSONL yang ditulis
 * JsonlSecurityEventExporter: jumlah per tipe event, jumlah per client_id,
 * N event terakhir, dan panel umur KEK (hanya NAMA dari env).
 *
 * Jalankan:
 *   SP_EVENT_LOG=/absolute/path/events.jsonl php -S localhost:8080 examples/dashboard/index.php
 *
 * Buka: http://localhost:8080/
 */

/*
 * ============================================================
 *  PERINGATAN BESAR — WAJIB DIBACA SEBELUM DEPLOY
 * ============================================================
 *  Halaman ini menampilkan metrik keamanan internal (pola serangan,
 *  client_id aktif). JANGAN PERNAH ekspos ke publik. WAJIB di belakang
 *  auth produksi: VPN / reverse-proxy auth / SSO internal perusahaan.
 *
 *  Placeholder auth (contoh HTTP Basic Auth sederhana) — lepas komentar
 *  dan set env DASHBOARD_USER/DASHBOARD_PASS bila belum ada auth di
 *  web server/reverse proxy:
 *
 *      $__user = getenv('DASHBOARD_USER') ?: '';
 *      $__pass = getenv('DASHBOARD_PASS') ?: '';
 *      if ($__user === '' || $__pass === ''
 *          || !isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])
 *          || !hash_equals($__user, $_SERVER['PHP_AUTH_USER'])
 *          || !hash_equals($__pass, $_SERVER['PHP_AUTH_PW'])) {
 *          header('WWW-Authenticate: Basic realm="SecurePayload Dashboard"');
 *          http_response_code(401);
 *          exit("Unauthorized\n");
 *      }
 *
 *  Catatan: HTTP Basic Auth tanpa TLS mengirim credential nyaris polos —
 *  gunakan HTTPS, atau lebih baik lagi terapkan auth di reverse proxy.
 * ============================================================
 */

// Read-only TOTAL: tolak metode apa pun selain GET/HEAD (defense in depth;
// halaman ini memang tidak punya jalur tulis apa pun).
$__method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($__method !== 'GET' && $__method !== 'HEAD') {
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    exit("Method Not Allowed\n");
}

header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');

/** Escape HTML untuk SEMUA output — konteks event bisa berisi data tak tepercaya (client_id berasal dari request!). */
function e(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Potong teks panjang untuk tampilan tabel. */
function trunc(string $value, int $max = 160): string
{
    return mb_strlen($value) > $max ? mb_substr($value, 0, $max) . '…' : $value;
}

/**
 * Baca TAIL file agar memory tetap terkendali pada log besar.
 * Baris pertama setelah seek dibuang karena kemungkinan terpotong.
 *
 * @return array{lines: list<string>, truncated: bool}
 */
function tailLines(string $path, int $maxBytes = 8 * 1024 * 1024): array
{
    clearstatcache(true, $path);
    $size = @filesize($path);
    if ($size === false || $size <= 0) {
        return ['lines' => [], 'truncated' => false];
    }
    $fh = @fopen($path, 'rb');
    if ($fh === false) {
        return ['lines' => [], 'truncated' => false];
    }
    $truncated = false;
    if ($size > $maxBytes) {
        @fseek($fh, $size - $maxBytes);
        $truncated = true;
        fgets($fh); // buang sisa baris yang terpotong
    }
    $lines = [];
    while (($line = fgets($fh)) !== false) {
        $lines[] = $line;
    }
    fclose($fh);
    return ['lines' => $lines, 'truncated' => $truncated];
}

/**
 * Parse baris JSONL menjadi daftar event valid.
 *
 * @param list<string> $lines
 *
 * @return list<array{ts:int, event:string, ctx:array<string,mixed>}>
 */
function parseEvents(array $lines): array
{
    $out = [];
    foreach ($lines as $raw) {
        $line = trim($raw);
        if ($line === '') {
            continue;
        }
        $decoded = json_decode($line, true);
        if (!is_array($decoded) || !isset($decoded['event'], $decoded['ts']) || !is_string($decoded['event'])) {
            continue; // baris korup/asing: lewati, jangan gagalkan halaman
        }
        $ts = $decoded['ts'];
        $ctx = isset($decoded['ctx']) && is_array($decoded['ctx']) ? $decoded['ctx'] : [];
        $out[] = ['ts' => is_int($ts) ? $ts : (int) $ts, 'event' => $decoded['event'], 'ctx' => $ctx];
    }
    return $out;
}

/**
 * Ambil client_id dari ctx (dukung dua konvensi penamaan umum).
 *
 * @param array<string,mixed> $ctx
 */
function clientIdOf(array $ctx): ?string
{
    foreach (['clientId', 'client_id'] as $key) {
        if (isset($ctx[$key]) && is_scalar($ctx[$key])) {
            return trim((string) $ctx[$key]);
        }
    }
    return null;
}

/**
 * Panel umur KEK: HANYA membaca NAMA dari env SECURE_KEKS (konvensi
 * LocalKms::fromEnv()) dan timestamp opsional `<kek-id>_CREATED_AT`.
 * Nilai secret (SECURE_KEK_<id>_B64 dsb.) TIDAK PERNAH dibaca/ditampilkan.
 *
 * @return list<array{id:string, created:?string, ageDays:?int}>
 */
function kekPanel(): array
{
    $ids = array_filter(array_map('trim', explode(',', getenv('SECURE_KEKS') ?: '')));
    $out = [];
    foreach ($ids as $id) {
        // Konvensi created_at: <kek-id>_CREATED_AT, contoh kek-2026-01_CREATED_AT=2026-01-15T00:00:00Z
        $createdRaw = getenv($id . '_CREATED_AT');
        $created = is_string($createdRaw) && $createdRaw !== '' ? $createdRaw : null;
        $ageDays = null;
        if ($created !== null) {
            $ts = strtotime($created);
            if ($ts !== false) {
                $ageDays = (int) floor((time() - $ts) / 86400);
            }
        }
        $out[] = ['id' => $id, 'created' => $created, 'ageDays' => $ageDays];
    }
    return $out;
}

$logPath = getenv('SP_EVENT_LOG') ?: '';
$limit = max(10, min(500, (int) ($_GET['limit'] ?? 100)));

$totalEvents = 0;
$truncatedWindow = false;
$countByEvent = [];
$countByClient = [];
$latest = [];

if ($logPath !== '' && is_file($logPath)) {
    $tail = tailLines($logPath);
    $truncatedWindow = $tail['truncated'];
    $events = parseEvents($tail['lines']);
    $totalEvents = count($events);
    foreach ($events as $ev) {
        $countByEvent[$ev['event']] = ($countByEvent[$ev['event']] ?? 0) + 1;
        $cid = clientIdOf($ev['ctx']);
        $bucket = $cid !== null && $cid !== '' ? $cid : '(tanpa client_id)';
        $countByClient[$bucket] = ($countByClient[$bucket] ?? 0) + 1;
    }
    arsort($countByEvent);
    arsort($countByClient);
    $latest = array_reverse(array_slice($events, -$limit)); // terbaru dulu
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecurePayload — Dashboard Keamanan (read-only)</title>
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0 auto; max-width: 1080px; padding: 16px; color: #1c2430; background: #f7f8fa; }
  h1 { font-size: 20px; } h2 { font-size: 15px; margin: 28px 0 8px; color: #33404f; }
  .banner { border: 2px solid #b3261e; background: #fdecea; color: #7a1710; padding: 10px 14px; border-radius: 6px; font-weight: 600; margin-bottom: 16px; }
  .muted { color: #5a6673; font-size: 13px; }
  table { border-collapse: collapse; width: 100%; background: #fff; font-size: 13px; }
  th, td { border: 1px solid #d9dee4; padding: 6px 9px; text-align: left; vertical-align: top; }
  th { background: #eef1f4; } td.num { text-align: right; white-space: nowrap; }
  code { background: #eceff2; padding: 1px 5px; border-radius: 3px; font-size: 12px; word-break: break-all; }
  .grid { display: flex; gap: 18px; flex-wrap: wrap; } .grid > div { flex: 1 1 320px; }
</style>
</head>
<body>
<div class="banner">&#9888; READ-ONLY &mdash; WAJIB DI BELAKANG AUTH PRODUKSI. Jangan ekspos ke publik.</div>
<h1>SecurePayload &mdash; Dashboard Keamanan <span class="muted">(read-only)</span></h1>

<?php if ($logPath === '') : ?>
  <p><strong>Env <code>SP_EVENT_LOG</code> belum disetel.</strong></p>
  <p class="muted">Contoh menjalankan:
    <code>SP_EVENT_LOG=/var/log/securepayload/events.jsonl php -S localhost:8080 <?= e(basename(__FILE__)) ?></code>
    &mdash; path log hanya dibaca dari environment, tidak pernah dari query/URL (cegah file-read gadget).</p>
<?php elseif (!is_file($logPath)) : ?>
  <p>File log tidak ditemukan: <code><?= e($logPath) ?></code></p>
  <p class="muted">Pastikan <code>JsonlSecurityEventExporter</code> sudah dipasang pada opsi
    <code>onSecurityEvent</code> dan path-nya dapat ditulis proses PHP.</p>
<?php else : ?>
  <p class="muted">Log: <code><?= e($logPath) ?></code> &mdash;
    <?= $totalEvents ?> event valid<?= $truncatedWindow ? ' (jendela tail 8 MiB terakhir)' : '' ?>.
    Ringkasan dihitung atas jendela yang dimuat, bukan seluruh riwayat.</p>

  <div class="grid">
    <div>
      <h2>Jumlah per tipe event</h2>
      <table>
        <tr><th>Event</th><th class="num">Jumlah</th></tr>
        <?php foreach ($countByEvent as $name => $count) : ?>
          <tr><td><code><?= e($name) ?></code></td><td class="num"><?= e((string) $count) ?></td></tr>
        <?php endforeach; ?>
        <?php if ($countByEvent === []) : ?><tr><td colspan="2" class="muted">Belum ada event.</td></tr><?php endif; ?>
      </table>
    </div>
    <div>
      <h2>Jumlah per client_id <span class="muted">(dari context)</span></h2>
      <table>
        <tr><th>client_id</th><th class="num">Jumlah</th></tr>
        <?php foreach ($countByClient as $cid => $count) : ?>
          <tr><td><?= e(trunc($cid, 120)) ?></td><td class="num"><?= e((string) $count) ?></td></tr>
        <?php endforeach; ?>
        <?php if ($countByClient === []) : ?><tr><td colspan="2" class="muted">Belum ada event.</td></tr><?php endif; ?>
      </table>
    </div>
  </div>

  <div class="grid">
    <div>
      <h2>Umur KEK <span class="muted">(nama saja &mdash; nilai secret tidak pernah dirender)</span></h2>
      <?php $keks = kekPanel(); ?>
      <?php if ($keks === []) : ?>
        <p class="muted">Env <code>SECURE_KEKS</code> tidak disetel / kosong. Format:
          <code>SECURE_KEKS=kek-2026-01,kek-2026-08</code> plus opsional
          <code>kek-2026-01_CREATED_AT=2026-01-15T00:00:00Z</code>.</p>
      <?php else : ?>
        <table>
          <tr><th>Nama KEK</th><th>created_at</th><th class="num">Umur (hari)</th></tr>
          <?php foreach ($keks as $kek) : ?>
            <tr>
              <td><code><?= e($kek['id']) ?></code></td>
              <td><?= $kek['created'] !== null ? e($kek['created']) : '<span class="muted">&mdash;</span>' ?></td>
              <td class="num"><?= $kek['ageDays'] !== null ? e((string) $kek['ageDays']) : '&mdash;' ?></td>
            </tr>
          <?php endforeach; ?>
        </table>
        <p class="muted">Viewer hanya membaca nama KEK dan env <code>&lt;id&gt;_CREATED_AT</code>.
          Nilai material kunci (<code>SECURE_KEK_&lt;id&gt;_B64</code>) tidak pernah disentuh.</p>
      <?php endif; ?>
    </div>
  </div>

  <h2><?= min($limit, $totalEvents) ?> event terakhir <span class="muted">(&lt;= <?= e((string) $limit) ?>; urut terbaru)</span></h2>
  <table>
    <tr><th>#</th><th>Waktu (UTC)</th><th>Event</th><th>Context</th></tr>
    <?php foreach ($latest as $i => $ev) : ?>
      <tr>
        <td class="num"><?= e((string) ($i + 1)) ?></td>
        <td class="num"><?= e(gmdate('Y-m-d H:i:s', $ev['ts'])) ?></td>
        <td><code><?= e($ev['event']) ?></code></td>
        <td>
          <?php if ($ev['ctx'] === []) : ?><span class="muted">&mdash;</span><?php endif; ?>
          <?php foreach ($ev['ctx'] as $k => $v) : ?>
            <strong><?= e((string) $k) ?></strong>=<?= e(trunc(is_scalar($v) ? (string) $v : (json_encode($v) ?: ''))) ?><br>
          <?php endforeach; ?>
        </td>
      </tr>
    <?php endforeach; ?>
    <?php if ($latest === []) : ?><tr><td colspan="4" class="muted">Belum ada event.</td></tr><?php endif; ?>
  </table>
<?php endif; ?>

<p class="muted">Dashboard ini read-only total: tidak ada endpoint tulis, tidak ada parameter path,
dan seluruh output di-escape. Lihat <code>docs/DASHBOARD.md</code> untuk wiring lengkap.</p>
</body>
</html>
