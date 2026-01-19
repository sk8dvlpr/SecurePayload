<?php

namespace App\Controller;

use SecurePayload\SecurePayload;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class UploadController extends AbstractController
{
    #[Route('/api/secure-upload', methods: ['POST'])]
    public function upload(Request $request): JsonResponse
    {
        $server = new SecurePayload(['mode' => 'both', /* keys... */]);

        $result = $server->verifyFilePayload(
            $request->headers->all(), // HeaderBag -> array
            $request->getContent(),
            $request->getMethod(),
            $request->getPathInfo()
        );

        if (!$result['ok']) {
            return new JsonResponse(['error' => $result['error']], $result['status']);
        }

        // Logic simpan file...

        return new JsonResponse(['status' => 'uploaded']);
    }
}
