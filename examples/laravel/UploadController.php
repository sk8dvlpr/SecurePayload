<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use SecurePayload\SecurePayload;

class UploadController extends Controller
{
    // Receiver (Server)
    public function store(Request $request)
    {
        $server = new SecurePayload([
            'mode' => 'both',
            // load key logic...
        ]);

        $result = $server->verifyFilePayload(
            $request->header(), // Laravel return array of headers
            $request->getContent(),
            $request->method(),
            $request->path(),
            ['allowed_exts' => ['jpg', 'png']]
        );

        if (!$result['ok']) {
            return response()->json(['error' => $result['error']], $result['status']);
        }

        // Simpan file menggunakan Storage Facade
        $file = $result['file'];
        // \Storage::put('secure_uploads/' . $file['name'], $file['content_decoded']);

        return response()->json(['message' => 'File received', 'meta' => $result['data']]);
    }

    // Sender (Client)
    public function sendToPartner()
    {
        $client = new SecurePayload([
            'mode' => 'both',
            // credentials match partner...
        ]);

        $res = $client->sendFile(
            'https://partner-api.com/upload',
            'POST',
            storage_path('app/invoice.pdf'),
            ['id' => 999]
        );

        return response()->json($res);
    }
}
