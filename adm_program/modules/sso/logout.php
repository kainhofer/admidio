<?php

require_once('../../adm_program/system/common.php');
require_once('../../adm_program/system/login_valid.php');
require_once('../repositories/AccessTokenRepository.php');
require_once('../repositories/RefreshTokenRepository.php');
require_once('../repositories/ClientRepository.php');
require_once('../services/JwtService.php');

session_start();

header('Content-Type: application/json');

// Extract parameters
$idTokenHint = $_GET['id_token_hint'] ?? null;
$postLogoutRedirectUri = $_GET['post_logout_redirect_uri'] ?? null;

// Validate `id_token_hint` if provided
if ($idTokenHint) {
    $jwtService = new JwtService();
    $decodedToken = $jwtService->validateIdToken($idTokenHint);

    if (!$decodedToken) {
        http_response_code(400);
        echo json_encode(["error" => "Invalid id_token_hint"]);
        exit;
    }

    // Ensure the `sub` matches the logged-in user
    if ($decodedToken->sub !== (string)$gCurrentUser->getValue('usr_id')) {
        http_response_code(403);
        echo json_encode(["error" => "User ID does not match id_token_hint"]);
        exit;
    }
}

// Revoke all active access and refresh tokens for the user
$accessTokenRepo = new AccessTokenRepository($gDb);
$refreshTokenRepo = new RefreshTokenRepository($gDb);

$accessTokenRepo->revokeTokensForUser($gCurrentUser->getValue('usr_id'));
$refreshTokenRepo->revokeTokensForUser($gCurrentUser->getValue('usr_id'));

// Record logout timestamp
$accessTokenRepo->setLogoutTimestamp($gCurrentUser->getValue('usr_id'));

// Log out user
if ($gCurrentUser->getValue('usr_id')) {
    session_destroy();
    setcookie(session_name(), '', time() - 3600, '/'); // Delete session cookie
}

// Redirect if `post_logout_redirect_uri` is provided and valid
if ($postLogoutRedirectUri) {
    $clientRepo = new ClientRepository($gDb);
    if (!$clientRepo->isRedirectUriAllowed($postLogoutRedirectUri)) {
        http_response_code(400);
        echo json_encode(["error" => "Invalid post_logout_redirect_uri"]);
        exit;
    }

    header("Location: " . filter_var($postLogoutRedirectUri, FILTER_SANITIZE_URL));
    exit;
}

echo json_encode(["message" => "User logged out successfully"]);
