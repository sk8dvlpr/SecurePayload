<?php

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use SecurePayload\SecurePayload;

// Contoh Route handler Slim 4
$app->post('/secure/upload', function (Request $request, Response $response, $args) {

    $server = new SecurePayload(['mode' => 'both', /*...*/]);

    $headers = [];
    foreach ($request->getHeaders() as $name => $values) {
        $headers[$name] = implode(', ', $values);
    }

    $result = $server->verifyFilePayload(
        $headers,
        (string) $request->getBody(),
        $request->getMethod(),
        $request->getUri()->getPath()
    );

    if (!$result['ok']) {
        $response->getBody()->write(json_encode(['error' => $result['error']]));
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus($result['status']);
    }

    $response->getBody()->write(json_encode(['message' => 'File ok']));
    return $response->withHeader('Content-Type', 'application/json');
});
