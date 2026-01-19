<?php
declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;
// use SecurePayload\KMS\DbKeyProvider;

/**
 * SecurePayloadMiddleware (Lumen)
 * -------------------------------
 * Middleware validasi request untuk Lumen.
 */
class SecurePayloadMiddleware
{
    public function handle($request, Closure $next)
    {
        /** @var Request $request */

        // 1. Setup Key
        $provider = new EnvKeyProvider();
        // $provider = new DbKeyProvider(app('db')->connection()->getPdo()); // Contoh opsi DB

        $keyLoader = fn(string $cid, string $kid) => $provider->load($cid, $kid);

        // 2. Inisilisasi
        $sp = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'keyLoader' => $keyLoader,
        ]);

        // 3. Headers
        $headers = [];
        foreach ($request->headers->all() as $k => $vals) {
            $headers[strtoupper($k)] = is_array($vals) ? implode(',', $vals) : (string) $vals;
        }

        // 4. Verifikasi
        $vr = $sp->verify(
            $headers,
            (string) $request->getContent(),
            $request->getMethod(),
            $request->path(),
            $request->getQueryString() ?? ''
        );

        if (!$vr['ok']) {
            return response()->json(['error' => $vr['error']], $vr['status'] ?? 400);
        }

        // 5. Simpan context (hasil decrypt)
        $request->attributes->set('securepayload', $vr);

        return $next($request);
    }
}
