<?php
namespace Admidio\SSO\Repository;

use League\OAuth2\Server\Repositories\IdTokenRepositoryInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use Firebase\JWT\JWT;

use Admidio\Infrastructure\Database;
use DateTimeImmutable;


/**
 * Class AccessTokenRepository, implements AccessTokenRepositoryInterface
 *  - Handles access to the access tokens stored in adm_oauth2_access_tokens
 */

 class IdTokenRepository implements IdTokenRepositoryInterface
 {
     private Database $database;
     private string $privateKey;
 
     public function __construct(Database $database)
     {
         $this->database = $database;
         // TODO_RK
         $this->privateKey = file_get_contents(__DIR__ . '/keys/private.pem');
     }
 
     public function issueIdToken(UserEntityInterface $user, string $clientId, array $scopes, string $nonce = null): string
     {
         $claims = $user instanceof UserEntity ? $user->getClaims() : [];
 
         $payload = array_merge($claims, [
             'iss'  => ADMIDIO_URL, // Your Admidio base URL
             'aud'  => $clientId,
             'exp'  => (new DateTimeImmutable())->modify('+1 hour')->getTimestamp(),
             'iat'  => time(),
             'nonce' => $nonce
         ]);
 
         return JWT::encode($payload, $this->privateKey, 'RS256');
     }
 }
 
//  class IdTokenRepository implements IdTokenRepositoryInterface {
//     private $db;

//     public function __construct($db) {
//         $this->db = $db;
//     }

//     public function getNewToken($clientEntity, $userIdentifier, array $scopes) {
//         $idToken = new IdTokenEntity();
//         $idToken->setUserIdentifier($userIdentifier);
//         return $idToken;
//     }

//     public function issueIdToken($token, $userEntity, $scopes) {
//         $idToken = $this->getNewToken($token->getClient(), $userEntity->getIdentifier(), $scopes);
        
//         $idToken->addClaim('sub', $userEntity->getIdentifier());
//         $idToken->addClaim('name', $userEntity->getFullName());
//         $idToken->addClaim('email', $userEntity->getEmail());

//         return $idToken;
//     }
// }
