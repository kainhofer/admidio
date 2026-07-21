<?php
/**
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 */

namespace Admidio\Requirements\Entity;

use Admidio\Components\Entity\Component;
use Admidio\Infrastructure\Database;
use Admidio\Infrastructure\Entity\Entity;
use Admidio\Infrastructure\Exception;

class Provider extends Entity
{
    /**
     * Constructor that will create an object of a provider record.
     *
     * @param Database   $database Object of the class Database.
     * @param int|string $rqpId    ID of the provider that should be loaded.
     *
     * @throws Exception
     */
    public function __construct(Database $database, int|string $rqpId = '')
    {
        parent::__construct($database, TBL_REQ_PROVIDERS, 'rqp', $rqpId);
    }

    /**
     * Check if the provider is visible to the current user.
     *
     * A provider is visible if:
     *   - it is set to public
     *   - current user is a requirements administrator, or
     *   - current user created the provider.
     *
     * @return bool
     */
    public function isVisible(): bool
    {
        global $gValidLogin, $gCurrentUserId;
        if (!$gValidLogin) {
            return false;
        }
        return ((bool) $this->getValue('rqp_public')
            || Component::isAdministrable('REQUIREMENTS')
            || $this->isEditable()
            || ((int) $this->getValue('rqp_usr_id_create') === $gCurrentUserId)
        );
    }

    /**
     * Check if the provider is editable by the current user.
     *
     * For now:
     * - globally editable providers are editable by logged-in users;
     * - otherwise only administrators may edit them.
     *
     * This should later be replaced or refined with a proper requirements
     * component permission.
     *
     * @return bool
     */
    public function isEditable(): bool
    {
        global $gCurrentUserId, $gValidLogin;

        if (!$gValidLogin) {
            return false;
        }
        return ((bool) $this->getValue('rqp_editable')
            || Component::isAdministrable('REQUIREMENTS')
            || ((int) $this->getValue('rqp_usr_id_create') === $gCurrentUserId)
        );
    }

    /**
     * Check if the provider may be deleted.
     *
     * Only requirements admins and the user who created the provider can delete it
     *
     * @return bool
     */
    public function isDeletable(): bool
    {
        global $gCurrentUserId, $gValidLogin;

        if (!$gValidLogin) {
            return false;
        }
        return Component::isAdministrable('REQUIREMENTS') 
            || ((int) $this->getValue('rqp_usr_id_create') === $gCurrentUserId);
    }



    public function canChangeVisibilityFlags(): bool
    {
        global $gValidLogin, $gCurrentUserId;
        if (!$gValidLogin) {
            return false;
        }
        return Component::isAdministrable('REQUIREMENTS')
           || (int) $this->getValue('rqp_usr_id_create') === $gCurrentUserId;
    }

    /**
     * Human-readable field names for changelog entries.
     *
     * @param string $field Database field name.
     *
     * @return string
     */
    public function getFieldTitle(string $field): string
    {
        return match ($field) {
            'rqp_name'          => 'SYS_NAME',
            'rqp_address'       => 'SYS_ADDRESS',
            'rqp_url'           => 'SYS_WEBSITE',
            'rqp_description'   => 'SYS_DESCRIPTION',
            'rqp_qualified'     => 'SYS_REQ_PROVIDER_QUALIFIED',
            'rqp_public'        => 'SYS_REQ_PROVIDER_PUBLIC',
            'rqp_editable'      => 'SYS_REQ_PROVIDER_EDITABLE',
            default             => parent::getFieldTitle($field)
        };
    }
}