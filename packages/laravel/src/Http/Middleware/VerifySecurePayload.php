<?php
declare(strict_types=1);

namespace SecurePayload\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use SecurePayload\Laravel\SecurePayloadFactory;
use SecurePayload\SecurePayload;
use Symfony\Component\HttpFoundation\Response;

final class VerifySecurePayload
{
    public function __construct(
        private readonly SecurePayload $server
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $headers = SecurePayloadFactory::normalizeHeaders($request->headers->all());

        $vr = $this->server->verify(
            $headers,
            $request->getContent(),
            $request->getMethod(),
            $request->getPathInfo(),
            $request->getQueryString() ?? ''
        );

        if (!$vr['ok']) {
            return response()->json(['error' => $vr['error']], $vr['status'] ?? 400);
        }

        $request->attributes->set(SecurePayloadFactory::REQUEST_ATTRIBUTE, $vr);

        return $next($request);
    }
}
