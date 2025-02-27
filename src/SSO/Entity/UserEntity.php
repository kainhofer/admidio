<?php

namespace Admidio\SSO\Repository;

use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\SerializableTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

use Admidio\Infrastructure\Database;
use Admidio\Users\Entity\User; // Use Admidio's User class
use Admidio\Roles\Entity\Role;

class UserEntity extends User implements UserEntityInterface 
{
    use EntityTrait, TokenEntityTrait, SerializableTrait;

    protected Database $database;
    private User $admidioUser; // Store Admidio user object

    /**
     * Create a UserEntity from an Admidio user ID.
     */
    public function __construct(Database $database, int $userId)
    {
        parent::__construct($database, $userId);
        global $gProfileFields;
        $this->database = $database;

        // Load Admidio user object
        $this->admidioUser = new User($this->database, $gProfileFields, $userId);

        if ($this->admidioUser || $this->admidioUser->isNewRecord()) {
            throw new \RuntimeException('User not found in Admidio.');
        }

        // Set the identifier for the OAuth2 entity (user_id)
        $this->setIdentifier($this->admidioUser->getValue('usr_id'));
    }

    /**
     * Get the username (login name) of the user.
     */
    public function getUsername(): string
    {
        if ($this->admidioUser && !$this->admidioUser->isNewRecord()) {
            return $this->admidioUser->getValue('usr_login_name');
        } else {
            return '';
        }
    }

    /**
     * Get the user's full name.
     */
    public function getFullName(): string
    {
        if ($this->admidioUser && !$this->admidioUser->isNewRecord()) {
            return trim($this->admidioUser->getValue('usr_first_name') . ' ' . $this->admidioUser->getValue('usr_last_name'));
        } else {
            return '';
        }
    }

    /**
     * Get the user's email address.
     */
    public function getEmail(): string
    {
        if ($this->admidioUser && !$this->admidioUser->isNewRecord()) {
            return $this->admidioUser->getValue('usr_email');
        } else {
            return '';
        }
    }

    /**
     * Get the user’s roles as an array of role IDs.
     */
    public function getRoles(): array
    {
        if ($this->admidioUser && !$this->admidioUser->isNewRecord()) {
            $roles = $this->admidioUser->getRoleMemberships();
            return array_keys($roles);
        } else {
            return [];
        }
    }

    /**
     * Get the user’s roles as a human-readable array.
     */
    public function getRoleNames(): array
    {
        $roleNames = [];
        if ($this->admidioUser && !$this->admidioUser->isNewRecord()) {
            $roles = $this->admidioUser->getRoleMemberships();
            foreach ($roles as $roleId => $roleRights) {
                $role = new Role($this->database, $roleId);
                if (!$role->isNewRecord()) {
                    $roleNames[$roleId] = $role->getValue('rol_name');
                }
            }
        }
        return $roleNames;
    }
}


<?php

namespace Admidio\OAuth;

use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\SerializableTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use User;

class UserEntity implements UserEntityInterface
{
    use EntityTrait, TokenEntityTrait, SerializableTrait;

    private User $admidioUser;

    public function __construct(int $userId)
    {
        global $gDb;

        $this->admidioUser = new User($gDb, $userId);

        if (!$this->admidioUser->getValue('usr_id')) {
            throw new \RuntimeException('User not found in Admidio.');
        }

        $this->setIdentifier($this->admidioUser->getValue('usr_id'));
    }

    public function getUsername(): string
    {
        return $this->admidioUser->getValue('usr_login_name');
    }

    public function getFullName(): string
    {
        return trim($this->admidioUser->getValue('usr_first_name') . ' ' . $this->admidioUser->getValue('usr_last_name'));
    }

    public function getEmail(): string
    {
        return $this->admidioUser->getValue('usr_email');
    }

    public function getRoles(): array
    {
        global $gDb;

        $sql = "SELECT mem_rol_id FROM adm_members WHERE mem_usr_id = ?";
        $statement = $gDb->prepare($sql);
        $statement->execute([$this->getIdentifier()]);

        return $statement->fetchAll(\PDO::FETCH_COLUMN);
    }

    public function getRoleNames(): array
    {
        global $gDb;

        $sql = "SELECT r.rol_name 
                FROM adm_roles r
                JOIN adm_members m ON r.rol_id = m.mem_rol_id
                WHERE m.mem_usr_id = ?";
        $statement = $gDb->prepare($sql);
        $statement->execute([$this->getIdentifier()]);

        return $statement->fetchAll(\PDO::FETCH_COLUMN);
    }

    /**
     * Returns OIDC claims for the user.
     */
    public function getClaims(): array
    {
        return [
            'sub'               => $this->getIdentifier(), // Subject (user ID)
            'preferred_username' => $this->getUsername(),
            'name'              => $this->getFullName(),
            'email'             => $this->getEmail(),
            'email_verified'    => true, // Assuming Admidio verifies emails
            'groups'            => $this->getRoleNames(), // User's roles as groups
            'locale'            => $this->getLocale()
        ];
    }

    /**
     * Gets the user's locale/language from Admidio.
     */
    public function getLocale(): string
    {
        global $gPreferences;

        return $gPreferences['system_language'] ?? 'de'; // Default to German if not set
    }
}
