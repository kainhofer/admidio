<?php

require_once('../../adm_program/system/common.php');

header('Content-Type: application/json');

$metadata = [
    "issuer" => ADMIDIO_URL,
    "authorization_endpoint" => ADMIDIO_URL . "/oauth/authorize.php",
    "token_endpoint" => ADMIDIO_URL . "/oauth/token.php",
    "userinfo_endpoint" => ADMIDIO_URL . "/oauth/userinfo.php",
    "jwks_uri" => ADMIDIO_URL . "/.well-known/jwks.json",
    "end_session_endpoint" => ADMIDIO_URL . "/oidc/logout.php",
    "response_types_supported" => ["code", "token", "id_token", "code token", "code id_token", "token id_token"],
    "subject_types_supported" => ["public"],
    "id_token_signing_alg_values_supported" => ["RS256"],
    "scopes_supported" => ["openid", "profile", "email"],
    "claims_supported" => ["sub", "name", "email", "groups"],
    "grant_types_supported" => ["authorization_code", "implicit", "refresh_token", "password", "client_credentials"],
];

echo json_encode($metadata, JSON_PRETTY_PRINT);
