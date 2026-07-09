<?php
declare(strict_types=1);

namespace SecurePayload\Ci4\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Config\Database;
use SecurePayload\Ci4\Config\SecurePayload as SecurePayloadConfig;
use SecurePayload\Ci4\SecurePayloadFactory;
use SecurePayload\SecurePayload;

final class VerifySecurePayload implements FilterInterface
{
    private SecurePayload $server;

    public function __construct(?SecurePayloadConfig $config = null)
    {
        $cfg = $config ?? config('SecurePayload');
        $array = $cfg instanceof SecurePayloadConfig ? $cfg->toArray() : SecurePayloadFactory::defaultConfig();
        $pdo = null;
        if (($array['server']['key_provider'] ?? 'env') === 'db') {
            $pdo = Database::connect()->connID;
        }
        $this->server = SecurePayloadFactory::createServer($array, $pdo);
    }

    public function before(RequestInterface $request, $arguments = null)
    {
        $headers = [];
        foreach ($request->headers() as $k => $header) {
            $headers[strtoupper((string) $k)] = $header->getValueLine();
        }

        $vr = $this->server->verify(
            $headers,
            (string) $request->getBody(),
            $request->getMethod(),
            $request->getUri()->getPath(),
            $request->getUri()->getQuery()
        );

        if (!$vr['ok']) {
            return service('response')
                ->setJSON(['error' => $vr['error']])
                ->setStatusCode($vr['status'] ?? 400);
        }

        $request->{SecurePayloadFactory::REQUEST_PROPERTY} = $vr;

        return null;
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null): ?ResponseInterface
    {
        return null;
    }
}
