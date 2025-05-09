<?php
namespace Admidio\Users\Entity;

use Admidio\Infrastructure\Database;
use Admidio\Infrastructure\Exception;
use Admidio\Infrastructure\Entity\Entity;
use Admidio\Changelog\Entity\LogChanges;

/**
 * @brief Class manages access to database table adm_user_relation_types
 *
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 */

class UserRelationType extends Entity
{
    public const USER_RELATION_TYPE_UNIDIRECTIONAL = 'unidirectional';
    public const USER_RELATION_TYPE_SYMMETRICAL    = 'symmetrical';
    public const USER_RELATION_TYPE_ASYMMETRICAL   = 'asymmetrical';

    /**
     * Constructor that will create an object of a recordset of the table adm_user_relation_types.
     * If the id is set than the specific message will be loaded.
     * @param Database $database Object of the class Database. This should be the default global object **$gDb**.
     * @param int $urtId The recordset of the relation type with this id will be loaded. If id isn't set than an empty object of the table is created.
     * @throws Exception
     */
    public function __construct(Database $database, int $urtId = 0)
    {
        parent::__construct($database, TBL_USER_RELATION_TYPES, 'urt', $urtId);
    }

    /**
     * Returns the inverse relation type.
     * @return null|self Returns the inverse relation type
     * @throws Exception
     */
    public function getInverse(): ?UserRelationType
    {
        if (empty($this->getValue('urt_id_inverse'))) {
            return null;
        }
        $inverse = new self($this->db, $this->getValue('urt_id_inverse'));

        if ($inverse->isNewRecord()) {
            return null;
        }

        return $inverse;
    }

    /**
     * Get the string of the current relationship type.
     * @return string The relationship type could be **asymmetrical**, **symmetrical** or **unidirectional**
     * @throws Exception
     */
    public function getRelationTypeString(): string
    {
        if (!$this->isNewRecord()) {
            if (empty($this->getValue('urt_id_inverse'))) {
                return self::USER_RELATION_TYPE_UNIDIRECTIONAL;
            } elseif ((int) $this->getValue('urt_id_inverse') === (int) $this->getValue('urt_id')) {
                return self::USER_RELATION_TYPE_SYMMETRICAL;
            }
        }

        return self::USER_RELATION_TYPE_ASYMMETRICAL;
    }

    /**
     * @return bool
     * @throws Exception
     */
    public function isAsymmetrical(): bool
    {
        return $this->getRelationTypeString() === self::USER_RELATION_TYPE_ASYMMETRICAL;
    }

    /**
     * @return bool
     * @throws Exception
     */
    public function isSymmetrical(): bool
    {
        return $this->getRelationTypeString() === self::USER_RELATION_TYPE_SYMMETRICAL;
    }

    /**
     * @return bool
     * @throws Exception
     */
    public function isUnidirectional(): bool
    {
        return $this->getRelationTypeString() === self::USER_RELATION_TYPE_UNIDIRECTIONAL;
    }

    /**
     * Adjust the changelog entry for this db record.
     *
     * For user relation types, we want to show the inverse relation as related.
     *
     * @param LogChanges $logEntry The log entry to adjust
     *
     * @return void
     */
    protected function adjustLogEntry(LogChanges $logEntry) {
        $inverse = $this->getInverse();
        if ($inverse) {
            $logEntry->setLogRelated($inverse->getValue('urt_uuid'), $inverse->getValue('urt_name'));
        }
    }
}
