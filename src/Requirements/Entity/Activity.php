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

class Activity extends Entity
{
    /**
     * Constructor that will create an object of an activity record.
     *
     * @param Database $database Object of the class Database.
     * @param int|string $rqaId ID of the activity that should be loaded.
     *
     * @throws Exception
     */
    public function __construct(Database $database, int|string $rqaId = '')
    {
        parent::__construct($database, TBL_REQ_ACTIVITIES, 'rqa', $rqaId);
    }

    /**
     * An activity is visible to requirements administrators and to the user who
     * owns the activity.
     *
     * @return bool
     *
     * @throws Exception
     */
    public function isVisible(): bool
    {
        global $gCurrentUser, $gValidLogin;
        return $gValidLogin
            && (
                Component::isAdministrable('REQUIREMENTS') ||
                (int) $this->getValue('rqa_user_id') === (int) $gCurrentUser->getValue('usr_id')
            );
    }

    /**
     * An activity is editable by requirements administrators and by the user who
     * owns the activity.
     *
     * @return bool
     *
     * @throws Exception
     */
    public function isEditable(): bool
    {
        return $this->isVisible();
    }

    /**
     * An activity is deletable by requirements administrators and by the user
     * who owns the activity.
     *
     * @return bool
     *
     * @throws Exception
     */
    public function isDeletable(): bool
    {
        return $this->isVisible();
    }

    /**
     * Return title of database fields for changelog display.
     *
     * @param string $field Database field name.
     *
     * @return string
     */
    public function getFieldTitle(string $field): string
    {
        return match ($field) {
            'rqa_user_id'          => 'SYS_USER',
            'rqa_provider_id'      => 'SYS_REQ_PROVIDER',
            'rqa_provider_name'    => 'SYS_REQ_PROVIDER',
            'rqa_provider_short_name' => 'SYS_REQ_PROVIDER_SHORT_NAME',
            'rqa_title'            => 'SYS_TITLE',
            'rqa_description'      => 'SYS_DESCRIPTION',
            'rqa_url'              => 'SYS_WEBSITE',
            'rqa_location'         => 'SYS_REQ_LOCATION',
            'rqa_begin_date'       => 'SYS_REQ_BEGIN_DATE',
            'rqa_begin_time'       => 'SYS_REQ_BEGIN_TIME',
            'rqa_end_date'         => 'SYS_REQ_END_DATE',
            'rqa_end_time'         => 'SYS_REQ_END_TIME',
            'rqa_attendance'       => 'SYS_REQ_ATTENDANCE',
            'rqa_comments'         => 'SYS_COMMENT',
            'rqa_status'           => 'SYS_REQ_STATUS',
            'rqa_review_comments'  => 'SYS_REQ_REVIEW_COMMENTS',
            'rqa_review_status'    => 'SYS_REQ_REVIEW_STATUS',
            default                => parent::getFieldTitle($field)
        };
    }
}