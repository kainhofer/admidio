<?php
/**
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 */

namespace Admidio\Requirements\Service;

use Admidio\Components\Entity\Component;
use Admidio\Infrastructure\Database;
use Admidio\Infrastructure\Exception;
use Admidio\Requirements\Entity\Activity;
use Admidio\Requirements\Entity\Provider;

class ActivityService
{
    protected Database $db;
    protected Activity $activity;

    /**
     * Constructor.
     *
     * @param Database $database Database object.
     * @param string $activityUuid UUID of the activity.
     *
     * @throws Exception
     */
    public function __construct(Database $database, string $activityUuid = '')
    {
        $this->db = $database;
        $this->activity = new Activity($database);

        if ($activityUuid !== '') {
            $this->activity->readDataByUuid($activityUuid);
        }
    }

    private function setDateAndTimeValues(array &$formValues): void
    {
        $isFullDay = !empty($formValues['rqa_full_day']);

        $formValues['rqa_begin_date'] = $formValues['rqa_begin'];
        $formValues['rqa_begin_time'] = $isFullDay ? null : ($formValues['rqa_begin_time'] ?? null);

        $formValues['rqa_end_date'] = $formValues['rqa_end'] !== '' ? $formValues['rqa_end'] : null;
        $formValues['rqa_end_time'] = !$isFullDay
            && $formValues['rqa_end_date'] !== null
            && ($formValues['rqa_end_time'] ?? '') !== ''
                ? $formValues['rqa_end_time']
                : null;
    }

    /**
     * Save data from the activity form into the database.
     *
     * @throws Exception
     */
    public function save(): void
    {
        global $gCurrentOrgId, $gCurrentSession, $gCurrentUser;

        $activityEditForm = $gCurrentSession->getFormObject($_POST['adm_csrf_token']);
        $formValues = $activityEditForm->validate($_POST);

        $this->setDateAndTimeValues($formValues);

        if (!empty($this->activity->getValue('rqa_id'))) {
            if (!$this->activity->isEditable()) {
                throw new Exception('SYS_NO_RIGHTS');
            }
        } else {
            $this->activity->setValue('rqa_org_id', $gCurrentOrgId);
            $this->activity->setValue('rqa_user_id', $gCurrentUser->getValue('usr_id'));
            $this->activity->setValue('rqa_status', 'submitted');
        }

        $providerName = '';
        $providerShortName = '';

        if (!empty($formValues['rqa_provider_id'])) {
            $provider = new Provider($this->db);
            $provider->readDataById((int) $formValues['rqa_provider_id']);

            if (!$provider->isVisible()) {
                throw new Exception('SYS_NO_RIGHTS');
            }

            $providerName = $provider->getValue('rqp_name', 'database');
            $providerShortName = $provider->getValue('rqp_short_name', 'database');

            if ($providerShortName === '') {
                $providerShortName = $providerName;
            }
        }

        $this->db->startTransaction();

        foreach ($formValues as $key => $value) {
            if (
                str_starts_with($key, 'rqa_')
                && !in_array(
                    $key,
                    array(
                        'rqa_user_id',
                        'rqa_org_id',
                        'rqa_provider_name',
                        'rqa_provider_short_name',
                        'rqa_status',
                        'rqa_review_comments',
                        'rqa_review_status',
                        'rqa_begin',
                        'rqa_end',
                        'rqa_full_day'
                    ),
                    true
                )
            ) {
                $this->activity->setValue($key, $value);
            }
        }

        $this->activity->setValue('rqa_provider_name', $providerName);
        $this->activity->setValue('rqa_provider_short_name', $providerShortName);

        if (Component::isAdministrable('REQUIREMENTS')) {
            $this->activity->setValue('rqa_review_comments', $formValues['rqa_review_comments'] ?? '');
            $this->activity->setValue('rqa_review_status', $formValues['rqa_review_status'] ?? '');
            $this->activity->setValue('rqa_status', $formValues['rqa_status'] ?? 'submitted');
        }

        $this->activity->save();

        $this->db->endTransaction();
    }
}