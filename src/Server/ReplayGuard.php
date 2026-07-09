<?php

declare(strict_types=1);

namespace SecurePayload\Server;

use SecurePayload\Exceptions\SecurePayloadException;
use SecurePayload\Internal\SecurePayloadConfig;
use SecurePayload\SecurePayload;

/**
 * Proteksi anti-replay: cache nonce dan garbage collection file-based.
 */
final class ReplayGuard
{
    public function __construct(
        private SecurePayloadConfig $config,
    ) {
    }

    public function checkReplay(string $cid, string $kid, string $tsStr, string $nonceB64): void
    {
        // Sebuah nonce harus "diingat" selama request yang membawanya masih bisa
        // dianggap segar oleh validasi timestamp, yaitu replayTtl + clockSkew.
        // Jika hanya replayTtl, ada celah waktu di mana nonce sudah dilupakan
        // namun timestamp masih valid sehingga replay (dengan ts dimutasi) lolos.
        $memoryTtl = $this->config->getReplayTtl() + $this->config->getClockSkew();

        // Probabilistic Garbage Collection: ~0.2% chance per request
        // Wajib gunakan $replayStore kustom (Redis/Memcached) di lingkungan produksi.
        if (random_int(1, 500) === 1) {
            $this->cleanupNonceFiles();
        }

        // PENTING: timestamp TIDAK dimasukkan ke dalam kunci replay. Sebuah nonce
        // wajib sekali-pakai terlepas dari nilai timestamp. Pada mode 'aead'
        // timestamp tidak ditandatangani/terotentikasi, sehingga jika ts ikut
        // menjadi bagian kunci, penyerang cukup mengubah ts untuk memutar ulang
        // request dengan nonce yang sama (replay attack).
        $cacheKey = 'sp_' . substr(hash('sha256', "$cid|$kid|$nonceB64"), 0, 48);

        $replayStore = $this->config->getReplayStore();
        if ($replayStore) {
            $okNew = (bool) call_user_func($replayStore, $cacheKey, $memoryTtl);
            if (!$okNew) {
                $this->config->emitEvent(SecurePayload::EVENT_REPLAY_DETECTED, ['clientId' => $cid, 'keyId' => $kid, 'source' => 'store']);
                throw new SecurePayloadException('Replay detected (Store)', SecurePayloadException::UNAUTHORIZED);
            }
            return;
        }

        // Fallback file-based replay protection (dengan locking untuk mencegah race condition)
        $dir = sys_get_temp_dir();
        $f = $dir . DIRECTORY_SEPARATOR . $cacheKey;

        // Kita menggunakan file sebagai flag. Jika file ada dan umur < TTL, maka replay.
        // Race condition mitigation: Gunakan 'x' (create only) atau lock.

        // Strategi Sederhana dengan @touch + filemtime check
        // Perhatian: Ini tidak atomic sempurna di semua OS tanpa lock, tapi cukup untuk case moderat.
        // Untuk produksi high-concurrency, WAJIB gunakan Redis/Memcached via $replayStore.

        if (file_exists($f)) {
            $mtime = filemtime($f);
            $age = $mtime !== false ? time() - $mtime : $memoryTtl + 1;
            if ($age < $memoryTtl) {
                $this->config->emitEvent(SecurePayload::EVENT_REPLAY_DETECTED, ['clientId' => $cid, 'keyId' => $kid, 'source' => 'file']);
                throw new SecurePayloadException('Replay detected (File)', SecurePayloadException::UNAUTHORIZED, ['age' => $age]);
            }
        }

        // Update timestamp file (atau buat baru)
        // Menggunakan flock untuk memastikan tidak ada dua proses menulis bersamaan
        $fp = fopen($f, 'c+'); // c+ tidak truncate, open buat read/write
        if ($fp) {
            if (flock($fp, LOCK_EX)) { // Exclusive Lock
                // Cek lagi setelah lock didapat (double-checked locking)
                $stat = fstat($fp);
                $age = time() - $stat['mtime'];
                // Jika file sudah ada isinya/ukurannya 0 tapi mtime baru saja, reject?
                // Di sini kita asumsikan keberadaan file + mtime baru = key sudah terpakai

                // Jika baru saja disentuh oleh proses lain dalam durasi memory TTL
                if ($stat['size'] > 0 && $age < $memoryTtl) {
                    flock($fp, LOCK_UN);
                    fclose($fp);
                    $this->config->emitEvent(SecurePayload::EVENT_REPLAY_DETECTED, ['clientId' => $cid, 'keyId' => $kid, 'source' => 'file_locked']);
                    throw new SecurePayloadException('Replay detected (Locked)', SecurePayloadException::UNAUTHORIZED);
                }

                // Tandai terpakai
                ftruncate($fp, 0);
                fwrite($fp, "1"); // Tulis byte agar size > 0
                fflush($fp);
                flock($fp, LOCK_UN);
            }
            fclose($fp);
        } else {
            // Fallback jika gagal open file
            @touch($f);
        }
    }

    /**
     * Membersihkan file nonce cache yang sudah kedaluwarsa di direktori temp.
     * Dipanggil secara probabilistik untuk mencegah storage exhaustion.
     *
     * @internal
     */
    public function cleanupNonceFiles(): void
    {
        $dir = sys_get_temp_dir();
        $pattern = $dir . DIRECTORY_SEPARATOR . 'sp_*';
        $files = glob($pattern);

        if (!$files) {
            return;
        }

        $cutoff = time() - ($this->config->getReplayTtl() + $this->config->getClockSkew());

        foreach ($files as $file) {
            if (!is_file($file)) {
                continue;
            }
            $mtime = @filemtime($file);
            if ($mtime !== false && $mtime < $cutoff) {
                @unlink($file);
            }
        }
    }
}
