<?php
declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;

class SecurePayloadMiddleware
{
    public function handle($request, Closure $next)
    {
        /** @var Request $request */
        $provider  = new EnvKeyProvider();
        $keyLoader = fn(string $cid, string $kid) => $provider->load($cid, $kid);

        $sp = new SecurePayload([
            'mode'      => 'both',
            'version'   => '1',
            'keyLoader' => $keyLoader,
        ]);

        $headers = [];
        foreach ($request->headers->all() as $k => $vals) {
            $headers[strtoupper($k)] = is_array($vals) ? implode(',', $vals) : (string)$vals;
        }

        $vr = $sp->verify(
            $headers,
            (string)$request->getContent(),
            $request->getMethod(),
            $request->path(),
            $request->getQueryString() ?? ''
        );

        if (!$vr['ok']) {
            return response()->json(['error' => $vr['error']], $vr['status'] ?? 400);
        }

        // Optionally place verified data
        $request->attributes->set('securepayload', $vr);
        return $next($request);
    }
}
