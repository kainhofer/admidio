<?php


require_once('../../adm_program/system/common.php');

header('Content-Type: application/json');

$publicKeyPath = __DIR__ . '/../keys/public.pem'; // Adjust path to match key location

if (!file_exists($publicKeyPath)) {
    http_response_code(500);
    echo json_encode(["error" => "Public key not found"]);
    exit;
}

// Read public key
$publicKey = file_get_contents($publicKeyPath);
$details = openssl_pkey_get_details(openssl_pkey_get_public($publicKey));

if (!$details || !isset($details['rsa'])) {
    http_response_code(500);
    echo json_encode(["error" => "Invalid RSA public key"]);
    exit;
}

$jwks = [
    "keys" => [
        [
            "kty" => "RSA",
            "alg" => "RS256",
            "use" => "sig",
            "kid" => "admidio-key", // Key ID
            "n"   => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
            "e"   => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=')
        ]
    ]
];

echo json_encode($jwks, JSON_PRETTY_PRINT);
