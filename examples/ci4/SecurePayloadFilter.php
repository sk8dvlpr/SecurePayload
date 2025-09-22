<?php
declare(strict_types=1);

namespace App\Filters;

use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Filters\FilterInterface;
use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;

class SecurePayloadFilter implements FilterInterface
{
    public function before(RequestInterface $request, $arguments = null)
    {
        $provider  = new EnvKeyProvider();
        $keyLoader = fn(string $cid, string $kid) => $provider->load($cid, $kid);

        $sp = new SecurePayload([
            'mode'      => 'both',
            'version'   => '1',
            'keyLoader' => $keyLoader,
        ]);

        $headers = [];
        foreach ($request->getHeaders() as $k => $header) {
            $headers[strtoupper($k)] = $header->getValueLine();
        }

        $vr = $sp->verify($headers, (string) $request->getBody(), $request->getMethod(), $request->getUri()->getPath(), $request->getUri()->getQuery());
        if (!$vr['ok']) {
            return service('response')->setJSON(['error' => $vr['error']])->setStatusCode($vr['status'] ?? 400);
        }

        // Optionally store in request attribute (requires custom handling)
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // No-op
    }
}
