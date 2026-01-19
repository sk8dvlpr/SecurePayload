<?php

namespace App\Controllers;

use CodeIgniter\Controller;
use SecurePayload\SecurePayload;

class UploadController extends Controller
{
    // Contoh untuk SISI SERVER (Receiver)
    public function receive()
    {
        $request = service('request');

        // Inisialisasi library (biasanya via Service/DI di BaseController)
        $server = new SecurePayload([
            'mode' => 'both',
            'keyLoader' => function ($c, $k) { /* Load dari DB/Env */}
        ]);

        $headers = [];
        foreach ($request->headers() as $k => $v) {
            $headers[$k] = $v->getValue();
        }

        $result = $server->verifyFilePayload(
            $headers,
            $request->getBody(),
            $request->getMethod(),
            $request->getUri()->getPath(),
            [
                'max_size' => 5 * 1024 * 1024,
                'allowed_exts' => ['png', 'jpg', 'pdf']
            ]
        );

        if (!$result['ok']) {
            return $this->response->setStatusCode($result['status'])->setJSON(['error' => $result['error']]);
        }

        // Proses file
        $file = $result['file'];
        // file_put_contents('uploads/' . $file['name'], $file['content_decoded']);

        return $this->response->setJSON([
            'status' => 'success',
            'file' => $file['name'],
            'data' => $result['data']
        ]);
    }

    // Contoh untuk SISI CLIENT (Sender) dari Controller CI4
    public function send()
    {
        $client = new SecurePayload([
            'mode' => 'both',
            'clientId' => 'my_app',
            'keyId' => 'v1',
            // ... credentials ...
        ]);

        try {
            $response = $client->sendFile(
                'https://api.partner.com/receive',
                'POST',
                WRITEPATH . 'uploads/report.pdf',
                ['type' => 'monthly_report']
            );

            return $this->response->setJSON($response);
        } catch (\Exception $e) {
            return $this->response->setJSON(['error' => $e->getMessage()]);
        }
    }
}
