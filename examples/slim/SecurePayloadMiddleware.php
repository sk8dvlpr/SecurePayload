<?php
declare(strict_types=1);

namespace App\Middleware;

use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Psr\Http\Message\ResponseInterface as Response;
use Slim\Psr7\Response as SlimResponse;
use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;

final class SecurePayloadMiddleware
{
    public function __invoke(Request $request, RequestHandler $handler): Response
    {
        $provider  = new EnvKeyProvider();
        $keyLoader = fn(string $cid, string $kid) => $provider->load($cid, $kid);

        $sp = new SecurePayload([
            'mode'      => 'both',
            'version'   => '1',
            'keyLoader' => $keyLoader,
        ]);

        $headers = [];
        foreach ($request->getHeaders() as $k => $vals) {
            $headers[strtoupper($k)] = implode(',', $vals);
        }

        $body = (string) $request->getBody();
        $path = $request->getUri()->getPath();
        $query = $request->getUri()->getQuery();

        $vr = $sp->verify($headers, $body, $request->getMethod(), $path, $query);
        if (!$vr['ok']) {
            $resp = new SlimResponse($vr['status'] ?? 400);
            $resp->getBody()->write(json_encode(['error'=>$vr['error']], JSON_UNESCAPED_SLASHES));
            return $resp->withHeader('Content-Type', 'application/json');
        }

        // Pass along (you could also add to request attributes via PSR-7 implementation specifics)
        return $handler->handle($request);
    }
}
