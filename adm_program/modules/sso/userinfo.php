<?php

require_once('../../adm_program/system/common.php');
require_once('../../adm_program/system/login_valid.php');
require_once('../repositories/AccessTokenRepository.php');

header('Content-Type: application/json');

// Get the Authorization header
if (!isset($_SERVER['HTTP_AUTHORIZATION'])) {
    http_response_code(401);
    echo json_encode(["error" => "Missing access token"]);
    exit;
}

$authHeader = trim($_SERVER['HTTP_AUTHORIZATION']);
if (!preg_match('/^Bearer\s+(.+)$/', $authHeader, $matches)) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid authorization header"]);
    exit;
}

$accessToken = $matches[1];

// Validate the access token
$tokenRepo = new AccessTokenRepository($gDb);
$userId = $tokenRepo->getUserIdByAccessToken($accessToken);

if (!$userId) {
    http_response_code(401);
    echo json_encode(["error" => "Invalid or expired token"]);
    exit;
}

// Get the user from Admidio's user management
$user = new User($gDb, $userId);

if (!$user->getValue('usr_id')) {
    http_response_code(404);
    echo json_encode(["error" => "User not found"]);
    exit;
}

// Prepare user claims
$response = [
    "sub"                => (string) $user->getValue('usr_id'), // Unique user ID
    "name"               => $user->getValue('usr_first_name') . ' ' . $user->getValue('usr_last_name'),
    "given_name"         => $user->getValue('usr_first_name'),
    "family_name"        => $user->getValue('usr_last_name'),
    "preferred_username" => strtolower($user->getValue('usr_login_name')),
    "email"              => $user->getValue('usr_email'),
    "email_verified"     => (bool) $user->getValue('usr_email_valid'),
    "locale"             => getUserLocale($user->getValue('usr_id')),
    "updated_at"         => strtotime($user->getValue('usr_timestamp')),
    "groups"             => getUserRoles($user->getValue('usr_id'))
];

// Return the claims as JSON
echo json_encode($response, JSON_PRETTY_PRINT);

/**
 * Retrieves the user's roles (groups) from Admidio.
 *
 * @param int $userId The user ID.
 * @return array The list of roles the user belongs to.
 */
function getUserRoles(int $userId): array {
    global $gDb;

    $sql = "SELECT rol_name FROM adm_roles
            JOIN adm_members ON mem_rol_id = rol_id
            WHERE mem_usr_id = ?";
    $stmt = $gDb->prepare($sql);
    $stmt->execute([$userId]);

    return $stmt->fetchAll(PDO::FETCH_COLUMN);
}

/**
 * Retrieves the user's locale from Admidio preferences.
 *
 * @param int $userId The user ID.
 * @return string The locale (e.g., "en", "de").
 */
function getUserLocale(int $userId): string {
    global $gDb;

    $sql = "SELECT pref_value FROM adm_preferences WHERE pref_name = 'default_language' AND pref_usr_id = ?";
    $stmt = $gDb->prepare($sql);
    $stmt->execute([$userId]);

    return $stmt->fetchColumn() ?: "en"; // Default to English if not set
}