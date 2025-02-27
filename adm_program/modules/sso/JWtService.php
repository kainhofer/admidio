<?php

require_once('../../adm_program/system/common.php');
require_once('../../adm_program/system/login_valid.php');
require_once('../repositories/KeyRepository.php');

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtService
{
    private $keyRepo;

    public function __construct()
    {
        $this->keyRepo = new KeyRepository($GLOBALS['gDb']);
    }

    public function validateIdToken($idToken)
    {
        $keys = $this->keyRepo->getSigningKey();
        if (!$keys) {
            return null;
        }

        try {
            return JWT::decode($idToken, new Key($keys['public'], 'RS256'));
        } catch (Exception $e) {
            return null;
        }
    }

    public function validateAccessToken($accessToken)
    {
        $keys = $this->keyRepo->getSigningKey();
        if (!$keys) {
            return null;
        }
    
        try {
            $decodedToken = JWT::decode($accessToken, new Key($keys['public'], 'RS256'));
    
            $accessTokenRepo = new AccessTokenRepository($GLOBALS['gDb']);
    
            // Check if the token is revoked
            if ($accessTokenRepo->isAccessTokenRevoked($decodedToken->jti)) {
                return null;
            }
    
            // Check for inactivity timeout
            if ($accessTokenRepo->isTokenExpiredDueToInactivity($decodedToken->jti)) {
                $accessTokenRepo->revokeToken($decodedToken->jti);
                return null;
            }
    
            // Update last activity timestamp
            $accessTokenRepo->updateLastActivity($decodedToken->jti);
    
            return $decodedToken;
        } catch (Exception $e) {
            return null;
        }
    }
    
}
