<?php
declare(strict_types=1);

namespace SecurePayload\Slim\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use SecurePayload\SecurePayload;
use SecurePayload\Slim\SecurePayloadFactory;

final class VerifySecurePayload implements MiddlewareInterface
{
    public function __construct(
        private readonly SecurePayload $server,
        private readonly ResponseFactoryInterface $responseFactory
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $headers = SecurePayloadFactory::normalizeHeaders($request->getHeaders());

        $vr = $this->server->verify(
            $headers,
            (string) $request->getBody(),
            $request->getMethod(),
            $request->getUri()->getPath(),
            $request->getUri()->getQuery()
        );

        if (!$vr['ok']) {
            $response = $this->responseFactory->createResponse($vr['status'] ?? 400);
            $response->getBody()->write(json_encode(['error' => $vr['error']], JSON_UNESCAPED_SLASHES));

            return $response->withHeader('Content-Type', 'application/json');
        }

        $request = $request->withAttribute(SecurePayloadFactory::REQUEST_ATTRIBUTE, $vr);

        return $handler->handle($request);
    }
}
