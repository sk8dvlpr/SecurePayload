<?php
declare(strict_types=1);

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpFoundation\JsonResponse;
use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;

/**
 * Symfony Request Subscriber (pre-controller)
 * - Verifies SecurePayload headers/body before controller is executed.
 * - On failure: short-circuits the request with JSON error response.
 */
final class SecurePayloadSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [ KernelEvents::REQUEST => ['onKernelRequest', 10] ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();

        $provider  = new EnvKeyProvider();
        $keyLoader = fn(string $cid, string $kid) => $provider->load($cid, $kid);

        $sp = new SecurePayload([
            'mode'      => 'both',
            'version'   => '1',
            'keyLoader' => $keyLoader,
        ]);

        // Flatten headers to simple array<string,string>
        $headers = [];
        foreach ($request->headers->all() as $k => $vals) {
            $headers[strtoupper($k)] = is_array($vals) ? implode(',', $vals) : (string)$vals;
        }

        $vr = $sp->verify(
            $headers,
            $request->getContent(),
            $request->getMethod(),
            $request->getPathInfo(),
            $request->getQueryString() ?? ''
        );

        if (!$vr['ok']) {
            $resp = new JsonResponse(['error' => $vr['error']], $vr['status'] ?? 400);
            $event->setResponse($resp);
            return;
        }

        // Optionally attach the verified data for controllers
        $request->attributes->set('securepayload', $vr);
    }
}
