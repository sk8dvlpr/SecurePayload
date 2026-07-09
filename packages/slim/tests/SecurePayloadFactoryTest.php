<?php
declare(strict_types=1);

namespace SecurePayload\Slim\Tests;

use PHPUnit\Framework\TestCase;
use SecurePayload\SecurePayload;
use SecurePayload\Slim\Middleware\VerifySecurePayload;
use SecurePayload\Slim\SecurePayloadFactory;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;

final class SecurePayloadFactoryTest extends TestCase
{
    public function testCreateServer(): void
    {
        $config = SecurePayloadFactory::defaultConfig();
        $server = SecurePayloadFactory::createServer($config);
        $this->assertInstanceOf(SecurePayload::class, $server);
    }

    public function testMiddlewareRejectsUnsignedRequest(): void
    {
        $server = SecurePayloadFactory::createServer(SecurePayloadFactory::defaultConfig());
        $middleware = new VerifySecurePayload($server, new ResponseFactory());
        $request = (new ServerRequestFactory())->createServerRequest('POST', 'https://example.test/v1/pay');
        $request->getBody()->write('{}');

        $response = $middleware->process($request, new class implements \Psr\Http\Server\RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                return (new ResponseFactory())->createResponse(200);
            }
        });

        $this->assertGreaterThanOrEqual(400, $response->getStatusCode());
    }
}
