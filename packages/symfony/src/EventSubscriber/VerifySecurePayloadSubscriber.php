<?php
declare(strict_types=1);

namespace SecurePayload\Symfony\EventSubscriber;

use SecurePayload\SecurePayload;
use SecurePayload\Symfony\SecurePayloadFactory;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

final class VerifySecurePayloadSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly SecurePayload $server
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST => ['onKernelRequest', 10]];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$this->isMainRequest($event)) {
            return;
        }

        $request = $event->getRequest();
        $headers = SecurePayloadFactory::normalizeHeaders($request->headers->all());

        $vr = $this->server->verify(
            $headers,
            $request->getContent(),
            $request->getMethod(),
            $request->getPathInfo(),
            $request->getQueryString() ?? ''
        );

        if (!$vr['ok']) {
            $event->setResponse(new JsonResponse(['error' => $vr['error']], $vr['status'] ?? 400));

            return;
        }

        $request->attributes->set(SecurePayloadFactory::REQUEST_ATTRIBUTE, $vr);
    }

    private function isMainRequest(RequestEvent $event): bool
    {
        if (method_exists($event, 'isMainRequest')) {
            return $event->isMainRequest();
        }

        /** @phpstan-ignore method.notFound */
        return $event->isMasterRequest();
    }
}
