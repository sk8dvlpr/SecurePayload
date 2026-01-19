<?php
declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;
// use SecurePayload\KMS\DbKeyProvider; 

/**
 * SecurePayloadMiddleware (Laravel)
 * ---------------------------------
 * Middleware untuk memvalidasi request masuk menggunakan SecurePayload.
 */
class SecurePayloadMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        // 1. Setup Key Provider
        $provider = new EnvKeyProvider();

        // Contoh jika menggunakan DB (Laravel PDO):
        // $pdo = \DB::connection()->getPdo();
        // $provider = new DbKeyProvider($pdo);

        $keyLoader = fn(string $cid, string $kid) => $provider->load($cid, $kid);

        // 2. Init Library
        $sp = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'keyLoader' => $keyLoader,
        ]);

        // 3. Normalisasi Header
        $headers = [];
        foreach ($request->headers->all() as $k => $vals) {
            // SecurePayload butuh header uppercase
            $headers[strtoupper($k)] = is_array($vals) ? implode(',', $vals) : (string) $vals;
        }

        // 4. Verifikasi
        // Menggunakan method dan path dari Request object Laravel untuk keamanan (Trust on First Use)
        $vr = $sp->verify(
            $headers,
            $request->getContent(),
            $request->getMethod(),
            $request->getPathInfo(),
            $request->getQueryString() ?? ''
        );

        // 5. Cek Hasil
        if (!$vr['ok']) {
            return response()->json(['error' => $vr['error']], $vr['status'] ?? 400);
        }

        // 6. Simpan hasil verifikasi ke atribut request
        // Controller bisa mengakses via $request->attributes->get('securepayload');
        // Isinya termasuk body yang sudah didekripsi (jika mode AEAD/BOTH)
        $request->attributes->set('securepayload', $vr);

        // Jika body terdekripsi ada, bisa overwrite input JSON Laravel?
        // $request->merge($vr['json'] ?? []);

        return $next($request);
    }
}
