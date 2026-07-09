<?php
declare(strict_types=1);

namespace SecurePayload\Laravel\Console;

use Illuminate\Console\Command;
use SecurePayload\KMS\KeyManager;

final class GenerateKeysCommand extends Command
{
    protected $signature = 'securepayload:generate-keys
        {clientId : Client ID}
        {keyId : Key ID}
        {--kek= : KEK ID untuk wrap AEAD key}
        {--ed25519 : Sertakan pasangan Ed25519 client}
        {--ed25519-server : Sertakan pasangan Ed25519 server}
        {--table=secure_keys : Nama tabel SQL}';

    protected $description = 'Generate HMAC/AEAD key pair dan cetak SQL INSERT';

    public function handle(): int
    {
        $manager = new KeyManager();
        $clientId = (string) $this->argument('clientId');
        $keyId = (string) $this->argument('keyId');
        $kek = $this->option('kek');
        $kekId = is_string($kek) && $kek !== '' ? $kek : null;

        $result = $manager->generateKeyPair($clientId, $keyId, $kekId);

        if ($this->option('ed25519')) {
            $ed = $manager->generateEd25519KeyPair();
            $this->line('Ed25519 client public (DB): ' . $ed['publicB64']);
            $this->line('Ed25519 client secret (client env): ' . $ed['secretB64']);
        }

        if ($this->option('ed25519-server')) {
            $edSrv = $manager->generateEd25519ServerKeyPair();
            $this->line('Ed25519 server public (client env): ' . $edSrv['publicB64']);
            $this->line('Ed25519 server secret (server DB): ' . $edSrv['secretB64']);
        }

        $table = (string) $this->option('table');
        $this->line($result->toSqlInsert($table));
        $this->info('HMAC secret (simpan aman): ' . $result->hmacSecret);
        if ($result->aeadKeyB64 !== null && $result->aeadKeyB64 !== '') {
            $this->info('AEAD key b64: ' . $result->aeadKeyB64);
        }

        return self::SUCCESS;
    }
}
