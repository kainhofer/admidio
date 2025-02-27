<?php

namespace Admidio\SSO\Repository;

use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use RuntimeException;

use Admidio\Infrastructure\Database;

class UserRepository implements UserRepositoryInterface
{
    protected $database;
    protected array $allowedRoles; // Roles that are permitted to use OIDC

    public function __construct($database, array $allowedRoles)
    {
        $this->database = $database; // Using Admidio's $gDb instance
        $this->allowedRoles = $allowedRoles;
    }

    /**
     * Get the user entity by user credentials or return the currently logged-in user.
     */
    public function getUserEntityByUserCredentials($username, $password, $grantType, $clientEntity): ?UserEntityInterface
    {
        global $gCurrentUser, $gDb;

        // 1️⃣ Check if the user is already logged in
        if ($gCurrentUser->getValue('usr_id')) {
            if ($this->userHasAllowedRole($gCurrentUser->getValue('usr_id'))) {
                return new UserEntity($gCurrentUser->getValue('usr_id'));
            }
            return null; // User doesn't have the required role
        }

        // 2️⃣ If no user is logged in, verify credentials
        $sql = "SELECT usr_id, usr_password FROM adm_users WHERE usr_login_name = ?";
        $statement = $gDb->prepare($sql);
        $statement->execute([$username]);

        $user = $statement->fetch(PDO::FETCH_ASSOC);

        if (!$user || !password_verify($password, $user['usr_password'])) {
            return null; // Invalid credentials
        }

        // 3️⃣ Check if the user has the required role
        if (!$this->userHasAllowedRole($user['usr_id'])) {
            return null;
        }

        return new UserEntity($user['usr_id']);
    }

    /**
     * Check if a user has an allowed role for OIDC authentication.
     */
    protected function userHasAllowedRole(int $userId): bool
    {
        global $gDb;

        // Fetch roles for the given user
        $sql = "SELECT mem_rol_id FROM adm_members WHERE mem_usr_id = ?";
        $statement = $gDb->prepare($sql);
        $statement->execute([$userId]);

        $userRoles = $statement->fetchAll(PDO::FETCH_COLUMN);

        // Check if any of the user's roles match the allowed roles
        return !empty(array_intersect($userRoles, $this->allowedRoles));
    }
}
