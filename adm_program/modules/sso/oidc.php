<?php
namespace Admidio\OAuth;

require_once(__DIR__ . '/../../system/common.php');


use Admidio\SSO\Entity\ClientEntity;


//require 'vendor/autoload.php';
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;   
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Grant\PasswordGrant;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use Psr\Http\Message\ServerRequestInterface;
//use Zend\Diactoros\Response;
// use DateInterval;

use Admidio\Infrastructure\Database;
use Admidio\Infrastructure\Entity\Entity;
use Admidio\SSO\Entity\AccessTokenEntity;
use Admidio\SSO\Repository\AccessTokenRepository;
use Admidio\SSO\Repository\ClientRepository;
use Admidio\SSO\Repository\AuthCodeRepository;
use Admidio\SSO\Repository\RefreshTokenRepository;



try {

// Initialisierung des OAuth2-Servers
$privateKey = new CryptKey(__DIR__ . '/keys/private.key', null, false);
$encryptionKey = 'encryption_key_here';

$server = new AuthorizationServer(
    new ClientRepository($gDb),
    new AccessTokenRepository($gDb),
    new ScopeRepository($gDb),
    $privateKey,
    $encryptionKey
);

// Authorization Code Grant Setup
$server->enableGrantType(
    new AuthCodeGrant(
        new AuthCodeRepository($gDb),
        new RefreshTokenRepository($gDb),
        new \DateInterval('PT10M') // 10 Minuten gültig
    ),
    new \DateInterval('PT1H') // Access Token Lebensdauer
);

// Password Grant Setup (falls benötigt)
$server->enableGrantType(
    new PasswordGrant(
        new UserRepository(),
        new RefreshTokenRepository($gDb)
    ),
    new \DateInterval('PT1H')
);

$server->setAccessTokenRepository(new AccessTokenRepository($gDb));
$server->setIdTokenRepository(new IdTokenRepository($gDb)); 


// Refresh Token Grant
$server->enableGrantType(
    new RefreshTokenGrant(new RefreshTokenRepository()),
    new DateInterval('PT1H')
);

// Authorization Endpoint Beispiel
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (!isset($_SESSION['user_id'])) {
        header('Location: /admidio/login.php');
        exit;
    }
    echo json_encode(["message" => "User authenticated."]);
}

// Token Endpoint Beispiel
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $server->respondToAccessTokenRequest(
            Request::createFromGlobals(),
            new Response()
        )->send();
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(["error" => $e->getMessage()]);
    }
}

} catch (Exception $e) {
    $gMessage->show($e->getMessage());
}
