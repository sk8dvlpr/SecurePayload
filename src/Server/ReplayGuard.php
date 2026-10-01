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

        if ($this->config->isRequireReplayStore()) {
            throw new SecurePayloadException(
                'requireReplayStore aktif tetapi replayStore tidak dipasang — file-based store tidak diizinkan',
                SecurePayloadException::SERVER_ERROR
            );
        }

        // Fallback file-based replay protection (dengan locking untuk mencegah race condition)
        $dir = sys_get_temp_dir();
        $f = $dir . DIRECTORY_SEPARATOR . $cacheKey;

        // Kita menggunakan file sebagai flag. Jika file ada dan umur < TTL, maka replay.
        // Fail-closed: kegagalan fopen/flock → SERVER_ERROR (bukan lewati proteksi).

        if (file_exists($f)) {
            $mtime = filemtime($f);
            $age = $mtime !== false ? time() - $mtime : $memoryTtl + 1;
            if ($age < $memoryTtl) {
                $this->config->emitEvent(SecurePayload::EVENT_REPLAY_DETECTED, ['clientId' => $cid, 'keyId' => $kid, 'source' => 'file']);
                throw new SecurePayloadException('Replay detected (File)', SecurePayloadException::UNAUTHORIZED, ['age' => $age]);
            }
        }

        $fp = fopen($f, 'c+');
        if ($fp === false) {
            throw new SecurePayloadException(
                'Gagal membuka file nonce replay (fopen gagal) — fail-closed',
                SecurePayloadException::SERVER_ERROR,
                ['cacheKey' => $cacheKey]
            );
        }

        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            throw new SecurePayloadException(
                'Gagal mengunci file nonce replay (flock gagal) — fail-closed',
                SecurePayloadException::SERVER_ERROR,
                ['cacheKey' => $cacheKey]
            );
        }

        try {
            // Double-checked locking setelah exclusive lock
            $stat = fstat($fp);
            if ($stat === false) {
                throw new SecurePayloadException(
                    'Gagal membaca status file nonce replay — fail-closed',
                    SecurePayloadException::SERVER_ERROR
                );
            }
            $age = time() - (int) $stat['mtime'];

            if ($stat['size'] > 0 && $age < $memoryTtl) {
                $this->config->emitEvent(SecurePayload::EVENT_REPLAY_DETECTED, ['clientId' => $cid, 'keyId' => $kid, 'source' => 'file_locked']);
                throw new SecurePayloadException('Replay detected (Locked)', SecurePayloadException::UNAUTHORIZED);
            }

            ftruncate($fp, 0);
            fwrite($fp, '1');
            fflush($fp);
            // Pastikan permission ketat pada file nonce di /tmp bersama
            @chmod($f, 0600);
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
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

        // Batasi jumlah file yang diproses per GC untuk mencegah spike I/O.
        if (count($files) > 5000) {
            $files = array_slice($files, 0, 5000);
        }

        $cutoff = time() - ($this->config->getReplayTtl() + $this->config->getClockSkew());

        foreach ($files as $file) {
            if (!is_file($file)) {
                continue;
            }
            // Tolak symlink di shared temp
            if (is_link($file)) {
                @unlink($file);
                continue;
            }
            $mtime = @filemtime($file);
            if ($mtime !== false && $mtime < $cutoff) {
                @unlink($file);
            }
        }
    }
}
