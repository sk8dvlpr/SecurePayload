<?php
declare(strict_types=1);

namespace SecurePayload\Laravel\Console;

use Illuminate\Console\Command;
use SecurePayload\KMS\KeyManager;

final class RotateKeyCommand extends Command
{
    protected $signature = 'securepayload:rotate-key
        {clientId : Client ID}
        {currentKeyId : Key ID yang akan di-retire}
        {--new-key-id= : Key ID baru (default auto)}
        {--grace=86400 : Grace period detik}
        {--kek= : KEK ID untuk wrap AEAD key baru}
        {--ed25519 : Sertakan Ed25519 client pada key baru}
        {--ed25519-server : Sertakan Ed25519 server pada key baru}
        {--table=secure_keys : Nama tabel SQL}';

    protected $description = 'Rotasi kunci: SQL UPDATE retiring + INSERT key baru';

    public function handle(): int
    {
        $manager = new KeyManager();
        $clientId = (string) $this->argument('clientId');
        $currentKeyId = (string) $this->argument('currentKeyId');
        $newKeyId = $this->option('new-key-id');
        $newKeyId = is_string($newKeyId) && $newKeyId !== '' ? $newKeyId : null;
        $grace = (int) $this->option('grace');
        $kek = $this->option('kek');
        $kekId = is_string($kek) && $kek !== '' ? $kek : null;
        $table = (string) $this->option('table');

        $rotation = $manager->rotateKey(
            $clientId,
            $currentKeyId,
            $newKeyId,
            $grace,
            $kekId,
            (bool) $this->option('ed25519'),
            (bool) $this->option('ed25519-server')
        );

        $this->line($rotation->toSqlUpdateRetiring($table));
        $this->line($rotation->toSqlInsertNew($table));
        $this->info('Grace ends at: ' . date('c', $rotation->graceEndsAt));
        $this->info('New key ID: ' . $rotation->newKeyId);
        if ($rotation->ed25519SecretKeyB64 !== null) {
            $this->line('Ed25519 client secret (distribusi ke client): ' . $rotation->ed25519SecretKeyB64);
        }

        return self::SUCCESS;
    }
}
