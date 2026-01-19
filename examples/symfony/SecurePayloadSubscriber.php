<?php
declare(strict_types=1);

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpFoundation\JsonResponse;
use SecurePayload\SecurePayload;
use SecurePayload\KMS\EnvKeyProvider;
// use SecurePayload\KMS\DbKeyProvider;

/**
 * SecurePayloadSubscriber (Symfony)
 * ---------------------------------
 * Menggunakan Event Subscriber untuk meng-intercept request di kernel.
 * Dijalankan sebelum Controller (Priority 10).
 */
final class SecurePayloadSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        // Subscribe ke kernel.request agar dieksekusi di awal
        return [KernelEvents::REQUEST => ['onKernelRequest', 10]];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        // Hanya cek request utama (bukan sub-request internal)
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();

        // 1. Setup Key
        $provider = new EnvKeyProvider();
        // $pdo = $this->doctrine->getConnection()->getNativeConnection(); // Contoh jika via Doctrine
        // $provider = new DbKeyProvider($pdo);

        $keyLoader = fn(string $cid, string $kid) => $provider->load($cid, $kid);

        // 2. Init
        $sp = new SecurePayload([
            'mode' => 'both',
            'version' => '1',
            'keyLoader' => $keyLoader,
        ]);

        // 3. Headers
        $headers = [];
        foreach ($request->headers->all() as $k => $vals) {
            $headers[strtoupper($k)] = is_array($vals) ? implode(',', $vals) : (string) $vals;
        }

        // 4. Verifikasi
        $vr = $sp->verify(
            $headers,
            $request->getContent(),
            $request->getMethod(),
            $request->getPathInfo(),
            $request->getQueryString() ?? ''
        );

        // 5. Handle Error
        if (!$vr['ok']) {
            // Stop propagasi request dan langsung return error
            $resp = new JsonResponse(['error' => $vr['error']], $vr['status'] ?? 400);
            $event->setResponse($resp);
            return;
        }

        // 6. Sukses: Simpan hasil ke attributes agar bisa dipakai Controller
        $request->attributes->set('securepayload', $vr);

        // Opsional: replace request data dengan decrypted json?
        /*
        if (isset($vr['json'])) {
            $request->request->replace($vr['json']); 
        }
        */
    }
}
