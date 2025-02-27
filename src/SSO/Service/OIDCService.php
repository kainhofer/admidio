<?php
namespace Admidio\SSO\Service;

use Admidio\SSO\Repository\AccessTokenRepository;
use Admidio\SSO\Repository\ClientRepository;
use Admidio\SSO\Repository\AuthCodeRepository;
use Admidio\SSO\Repository\RefreshTokenRepository;
use Admidio\SSO\Repository\ScopeRepository;
use Admidio\SSO\Repository\UserRepository;


use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequestFactory;
use Psr\Http\Message\ServerRequestInterface; // Needed for PSR-7 compliance
use Psr\Http\Message\ResponseInterface; // Ensures correct return types for responses
use Psr\Http\Server\RequestHandlerInterface; // May be useful for middleware in the future

use Admidio\Infrastructure\Database;
use Admidio\Users\Entity\User;
use Admidio\Infrastructure\Entity\Entity;

class OIDCService {
    private \League\OAuth2\Server\AuthorizationServer $authServer;
    private ResourceServer $resourceServer;
    private Database $db;
    private User $currentUser;
    
    public function __construct($db, $currentUser) {//, ResourceServer $resourceServer) {
        $this->db = $db;
        $this->currentUser = $currentUser;
        // $this->resourceServer = $resourceServer;

        $this->setupService();
    }

    /**
     * Returns a PSR-7 request for the OAuth2 server while ensuring Admidio compatibility
     */
    private function getRequest() {
        // Ensure Admidio’s global request variables are used for internal logic
        $serverRequest = ServerRequestFactory::fromGlobals($_SERVER, $_GET, $_POST, $_COOKIE, $_FILES);
        return $serverRequest;
    }


    public function setupService() {
        // Init our repositories
        $clientRepository = new ClientRepository($this->db);            // instance of ClientRepositoryInterface
        $scopeRepository = new ScopeRepository($this->db);                        // instance of ScopeRepositoryInterface
        $accessTokenRepository = new AccessTokenRepository($this->db);  // instance of AccessTokenRepositoryInterface
        $authCodeRepository = new AuthCodeRepository($this->db);        // instance of AuthCodeRepositoryInterface
        $refreshTokenRepository = new RefreshTokenRepository($this->db); // instance of RefreshTokenRepositoryInterface

        $privateKey = 'file://path/to/private.key';
        //$privateKey = new CryptKey('file://path/to/private.key', 'passphrase'); // if private key has a pass phrase
        $encryptionKey = 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'; // generate using base64_encode(random_bytes(32))

        // Setup the authorization server
        $server = new \League\OAuth2\Server\AuthorizationServer(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKey,
            $encryptionKey
        );

        $grant = new \League\OAuth2\Server\Grant\AuthCodeGrant(
             $authCodeRepository,
             $refreshTokenRepository,
             new \DateInterval('PT10M') // authorization codes will expire after 10 minutes
         );
     
        $grant->setRefreshTokenTTL(new \DateInterval('P1M')); // refresh tokens will expire after 1 month
        // Enable the authentication code grant on the server
        $server->enableGrantType(
            $grant,
            new \DateInterval('PT1H') // access tokens will expire after 1 hour
        );


        $grant = new \League\OAuth2\Server\Grant\RefreshTokenGrant($refreshTokenRepository);
        $grant->setRefreshTokenTTL(new \DateInterval('P1M')); // new refresh tokens will expire after 1 month
        
        // Enable the refresh token grant on the server
        $server->enableGrantType(
            $grant,
            new \DateInterval('PT1H') // new access tokens will expire after an hour
        );


        $this->authServer = $server;
    }

    public function handleAuthorizationRequest() {
        $request = $this->getRequest();
        return $this->authServer->respondToAuthorizationRequest($request, new Response());
    }

    public function handleTokenRequest() {
        $request = $this->getRequest();
        return $this->authServer->respondToAccessTokenRequest($request, new Response());
    }

    public function handleUserInfoRequest($accessToken) {
        $token = $this->resourceServer->validateAuthenticatedRequest($accessToken);
        
        // Ensure Admidio's user object is used
        $userId = $token->getAttribute("user_id");
        if ($this->currentUser->getValue('usr_id') !== $userId) {
            return json_encode(["error" => "invalid_user"], JSON_UNESCAPED_SLASHES);
        }

        return json_encode([
            "sub"   => $this->currentUser->getValue("usr_id"),
            "name"  => $this->currentUser->getValue("usr_first_name") . " " . $this->currentUser->getValue("usr_last_name"),
            "email" => $this->currentUser->getValue("usr_email")
        ], JSON_UNESCAPED_SLASHES);
    }

    public function handleJWKSRequest() {
        return json_encode(["keys" => []], JSON_UNESCAPED_SLASHES);
    }

    public function handleDiscoveryRequest() {
        return json_encode([
            "issuer"                  => "https://example.com", 
            "authorization_endpoint"  => "/authorize", 
            "token_endpoint"          => "/token", 
            "userinfo_endpoint"       => "/userinfo",
            "jwks_uri"                => "/.well-known/jwks.json"
        ], JSON_UNESCAPED_SLASHES);
    }

    public function handleIntrospectionRequest() {
        return json_encode(["active" => true], JSON_UNESCAPED_SLASHES);
    }

    public function handleRevocationRequest() {
        return json_encode(["revoked" => true], JSON_UNESCAPED_SLASHES);
    }

    public function handleLogoutRequest() {
        // Properly destroy session and logout user
        if (isset($_SESSION)) {
            session_unset();
            session_destroy();
        }
        return json_encode(["logout" => true], JSON_UNESCAPED_SLASHES);
    }
}

