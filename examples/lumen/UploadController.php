<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use SecurePayload\SecurePayload;

class UploadController extends Controller
{
    // Lumen Receiver mirip Laravel
    public function receive(Request $request)
    {
        $server = new SecurePayload([
            'mode' => 'both',
            'keyLoader' => function ($cid, $kid) { /* ... */}
        ]);

        $result = $server->verifyFilePayload(
            $request->headers->all(), // Symfony HeaderBag
            $request->getContent(),
            $request->method(),
            $request->path()
        );

        if (!$result['ok']) {
            return response()->json(['error' => $result['error']], $result['status']);
        }

        return response()->json(['status' => 'ok', 'filename' => $result['file']['name']]);
    }
}
