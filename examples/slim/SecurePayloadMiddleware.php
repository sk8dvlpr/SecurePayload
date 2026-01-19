<?php
declare(strict_types=1);

namespace App\Middleware;

use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Psr\Http\Message\ResponseInterface as Response;
use Slim\Psr7\Response as SlimResponse;
use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;
// use SecurePayload\KMS\DbKeyProvider;

/**
 * SecurePayloadMiddleware (Slim 4)
 * --------------------------------
 * Contoh implementasi middleware untu framework berbasis PSR-15/PSR-7.
 */
final class SecurePayloadMiddleware
{
    public function __invoke(Request $request, RequestHandler $handler): Response
    {
        // 1. Setup
        $provider = new EnvKeyProvider();
        // $provider = new DbKeyProvider($myPdoInstance);

        $keyLoader = fn(string $cid, string $kid) => $provider->load($cid, $kid);

        $sp = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'keyLoader' => $keyLoader,
        ]);

        // 2. Baca Headers
        $headers = [];
        foreach ($request->getHeaders() as $k => $vals) {
            $headers[strtoupper($k)] = implode(',', $vals);
        }

        // 3. Ambil komponen Request PSR-7
        $body = (string) $request->getBody();
        $path = $request->getUri()->getPath();
        $query = $request->getUri()->getQuery();

        // 4. Verifikasi
        $vr = $sp->verify($headers, $body, $request->getMethod(), $path, $query);

        if (!$vr['ok']) {
            // Return error response PSR-7
            $resp = new SlimResponse();
            $resp->getBody()->write(json_encode(['error' => $vr['error']], JSON_UNESCAPED_SLASHES));
            return $resp
                ->withStatus($vr['status'] ?? 400)
                ->withHeader('Content-Type', 'application/json');
        }

        // 5. Teruskan request (bisa tambahkan attribut jika perlu)
        // $request = $request->withAttribute('securePayload', $vr);

        return $handler->handle($request);
    }
}
