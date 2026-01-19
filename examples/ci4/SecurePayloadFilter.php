<?php
declare(strict_types=1);

namespace App\Filters;

use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Filters\FilterInterface;
use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;
// use SecurePayload\KMS\DbKeyProvider; // Jika ingin menggunakan database

/**
 * SecurePayloadFilter (CodeIgniter 4)
 * -----------------------------------
 * Filter ini memverifikasi setiap request yang masuk sebelum mencapai Controller.
 * Memastikan request memiliki tanda tangan valid (HMAC) dan/atau terdekripsi (AEAD).
 */
class SecurePayloadFilter implements FilterInterface
{
    public function before(RequestInterface $request, $arguments = null)
    {
        // 1. Setup Penyedia Kunci (Key Provider)
        // Gunakan EnvKeyProvider untuk development atau simple setup
        $provider = new EnvKeyProvider();

        // Contoh penggunaan DbKeyProvider (Database):
        // $db = \Config\Database::connect();
        // $provider = new DbKeyProvider($db->connID); // Pastikan connID adalah instance PDO

        // Callback keyLoader yang menghubungkan SecurePayload dengan provider
        $keyLoader = fn(string $cid, string $kid) => $provider->load($cid, $kid);

        // 2. Inisialisasi SecurePayload
        $sp = new SecurePayload([
            'mode' => 'both', // 'hmac', 'aead', atau 'both'
            'version' => '1',
            'keyLoader' => $keyLoader,
        ]);

        // 3. Ambil Header
        $headers = [];
        foreach ($request->headers() as $k => $header) {
            $headers[strtoupper($k)] = $header->getValueLine();
        }

        // 4. Verifikasi Request
        // PENTING: Gunakan method dan path asli dari framework untuk keamanan maksimal
        $vr = $sp->verify(
            $headers,
            (string) $request->getBody(),
            $request->getMethod(),
            $request->getUri()->getPath(),
            $request->getUri()->getQuery()
        );

        // 5. Cek Hasil Verifikasi
        if (!$vr['ok']) {
            // Jika gagal, kembalikan respon error JSON
            return service('response')
                ->setJSON(['error' => $vr['error']])
                ->setStatusCode($vr['status'] ?? 400);
        }

        // Opsional: Simpan hasil verifikasi (misal body yang sudah didekripsi)
        // CodeIgniter tidak memiliki atribut request standard seperti Laravel, 
        // tapi kita bisa menyimpannya di property global atau registry jika perlu.
        // $request->securePayload = $vr; 
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // Tidak ada aksi setelah request
    }
}
