<?php
/**
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 */

namespace Admidio\UI\Presenter;

use Admidio\Changelog\Service\ChangelogService;
use Admidio\Components\Entity\Component;
use Admidio\Infrastructure\Exception;
use Admidio\Infrastructure\Language;
use Admidio\Infrastructure\Utils\SecurityUtils;
use Admidio\Requirements\Entity\Activity;

class RequirementsActivityPresenter extends PagePresenter
{
    protected string $activityUuid = '';

    /**
     * Constructor creates the page object and initializes all parameters.
     *
     * @param string $activityUuid UUID of the activity.
     *
     * @throws Exception
     */
    public function __construct(string $activityUuid = '')
    {
        $this->activityUuid = $activityUuid;
        parent::__construct($activityUuid);
    }

    /**
     * Create the activity edit form.
     *
     * @throws Exception
     */
    public function createEditForm(): void
    {
        global $gDb, $gL10n, $gCurrentOrgId, $gCurrentSession, $gCurrentUser;

        $activity = new Activity($gDb);

        $this->setHtmlID('adm_requirements_activity_edit');

        if ($this->activityUuid !== '') {
            $activity->readDataByUuid($this->activityUuid);

            if (!$activity->isEditable()) {
                throw new Exception('SYS_NO_RIGHTS');
            }

            $this->setHeadline($gL10n->get('SYS_EDIT_VAR', array($gL10n->get('SYS_REQ_ACTIVITY'))));
        } else {
            $activity->setValue('rqa_begin_date', DATE_NOW);
            $activity->setValue('rqa_begin_time', null);
            $activity->setValue('rqa_end_date', null);
            $activity->setValue('rqa_end_time', null);
            $activity->setValue('rqa_attendance', '0.00');
            $activity->setValue('rqa_status', 'submitted');

            $this->setHeadline($gL10n->get('SYS_CREATE_VAR', array($gL10n->get('SYS_REQ_ACTIVITY'))));
        }

        $this->addPageFunctionsMenuItem(
            'menu_item_req_provider_new',
            $gL10n->get('SYS_REQ_PROVIDER_CREATE'),
            SecurityUtils::encodeUrl(
                ADMIDIO_URL . FOLDER_MODULES . '/requirements/providers.php',
                array('mode' => 'edit')
            ),
            'bi-plus-circle-fill'
        );
        ChangelogService::displayHistoryButton(
            $this,
            'req_activities',
            'req_activities',
            !empty($this->activityUuid),
            array('uuid' => $this->activityUuid)
        );

        $form = new FormPresenter(
            'adm_requirements_activity_edit_form',
            'modules/requirements.activities.edit.tpl',
            SecurityUtils::encodeUrl(
                ADMIDIO_URL . FOLDER_MODULES . '/requirements/activities.php',
                array(
                    'uuid' => $this->activityUuid,
                    'mode' => 'save'
                )
            ),
            $this
        );

        $providerSelectBoxEntries = $this->getProviderSelectBoxEntries();

        $form->addSelectBox(
            'rqa_provider_id',
            $gL10n->get('SYS_REQ_PROVIDER'),
            $providerSelectBoxEntries,
            array(
                'defaultValue' => (int) $activity->getValue('rqa_provider_id'),
                'showContextDependentFirstEntry' => true,
                'helpTextId' => 'SYS_REQ_PROVIDER_SELECT_DESC'
            )
        );

        $form->addInput(
            'rqa_title',
            $gL10n->get('SYS_TITLE'),
            htmlentities((string) $activity->getValue('rqa_title', 'database'), ENT_QUOTES),
            array(
                'maxLength' => 255,
                'property' => FormPresenter::FIELD_REQUIRED
            )
        );

        $form->addMultilineTextInput(
            'rqa_description',
            $gL10n->get('SYS_DESCRIPTION'),
            $activity->getValue('rqa_description', 'database'),
            4
        );

        $form->addInput(
            'rqa_url',
            $gL10n->get('SYS_WEBSITE'),
            $activity->getValue('rqa_url', 'database'),
            array(
                'maxLength' => 2000,
                'type' => 'url'
            )
        );

        $form->addMultilineTextInput(
            'rqa_location',
            $gL10n->get('SYS_REQ_LOCATION'),
            $activity->getValue('rqa_location', 'database'),
            3,
            array('helpTextId' => 'SYS_REQ_ACTIVITY_LOCATION_DESC')
        );

        $form->addCheckbox(
            'rqa_full_day',
            $gL10n->get('SYS_REQ_FULL_DAY'),
            $activity->getValue('rqa_begin_time') === ''
                && $activity->getValue('rqa_end_time') === '',
            array('helpTextId' => 'SYS_REQ_FULL_DAY_DESC')
        );

        $form->addInput(
            'rqa_begin',
            $gL10n->get('SYS_START'),
            $this->getDateTimeValue(
                (string) $activity->getValue('rqa_begin_date'),
                (string) $activity->getValue('rqa_begin_time')
            ),
            array(
                'type'     => 'datetime',
                'property' => FormPresenter::FIELD_REQUIRED
            )
        );

        $form->addInput(
            'rqa_end',
            $gL10n->get('SYS_END'),
            $this->getDateTimeValue(
                (string) $activity->getValue('rqa_end_date'),
                (string) $activity->getValue('rqa_end_time')
            ),
            array('type' => 'datetime')
        );
            $this->addJavascript('
    /**
     * Function hides/show date and time fields
     */
    function setAllDay() {
        if ($("#rqa_full_day:checked").val() !== undefined) {
            if ($("#rqa_begin_time").val() == undefined) {
                $("#rqa_begin_time").val("00:00");
            }
            $("#rqa_begin_time").hide();
            if ($("#rqa_end_time").val() == undefined) {
                $("#rqa_end_time").val("00:00");
            }
            $("#rqa_end_time").hide();
        } else {
            $("#rqa_begin_time").show("slow");
            $("#rqa_end_time").show("slow");
        }
    }
');

            $this   ->addJavascript('
    setAllDay();

    $("#rqa_full_day").click(function() {
        setAllDay();
    });
    $("#rqa_begin").change(function() {
        if ($("#rqa_begin").val() > $("#rqa_end").val()) {
            $("#rqa_end").val($("#rqa_begin").val());
        }
    });',
        true
    );

        $form->addInput(
            'rqa_attendance',
            $gL10n->get('SYS_REQ_ATTENDANCE'),
            (string) $activity->getValue('rqa_attendance'),
            array(
                'type' => 'number',
                'minNumber' => 0,
                'step' => '0.01',
                'helpTextId' => 'SYS_REQ_ATTENDANCE_DESC'
            )
        );

        $form->addMultilineTextInput(
            'rqa_comments',
            $gL10n->get('SYS_COMMENT'),
            $activity->getValue('rqa_comments', 'database'),
            4
        );

        if (Component::isAdministrable('REQUIREMENTS')) {
            $form->addSelectBox(
                'rqa_status',
                $gL10n->get('SYS_REQ_STATUS'),
                array(
                    'submitted' => $gL10n->get('SYS_REQ_STATUS_SUBMITTED'),
                    'withdrawn' => $gL10n->get('SYS_REQ_STATUS_WITHDRAWN')
                ),
                array(
                    'defaultValue' => $activity->getValue('rqa_status'),
                    'arrayKeyIsNotValue' => true
                )
            );

            $form->addSelectBox(
                'rqa_review_status',
                $gL10n->get('SYS_REQ_REVIEW_STATUS'),
                array(
                    '' => '',
                    'open' => $gL10n->get('SYS_REQ_REVIEW_STATUS_OPEN'),
                    'accepted' => $gL10n->get('SYS_REQ_REVIEW_STATUS_ACCEPTED'),
                    'partially_accepted' => $gL10n->get('SYS_REQ_REVIEW_STATUS_PARTIALLY_ACCEPTED'),
                    'not_accepted' => $gL10n->get('SYS_REQ_REVIEW_STATUS_NOT_ACCEPTED'),
                    'clarification' => $gL10n->get('SYS_REQ_REVIEW_STATUS_CLARIFICATION')
                ),
                array(
                    'defaultValue' => $activity->getValue('rqa_review_status'),
                    'arrayKeyIsNotValue' => true
                )
            );

            $form->addMultilineTextInput(
                'rqa_review_comments',
                $gL10n->get('SYS_REQ_REVIEW_COMMENTS'),
                $activity->getValue('rqa_review_comments', 'database'),
                4
            );
        }

        $form->addSubmitButton(
            'adm_button_save',
            $gL10n->get('SYS_SAVE'),
            array(
                'icon' => 'bi-check-lg',
                'class' => 'offset-sm-3'
            )
        );

        $this->smarty->assign('userCreatedName', $activity->getNameOfCreatingUser());
        $this->smarty->assign('userCreatedTimestamp', $activity->getValue('rqa_timestamp_create'));
        $this->smarty->assign('lastUserEditedName', $activity->getNameOfLastEditingUser());
        $this->smarty->assign('lastUserEditedTimestamp', $activity->getValue('rqa_timestamp_change'));

        $form->addToHtmlPage();
        $gCurrentSession->addFormObject($form);
    }
    private function getDateTimeValue(string $date, string $time): string
    {
        if ($date === '') {
            $now = new \DateTime();
            return $now->format('Y-m-d H:00');
        }

        if ($time === '') {
            return $date . ' ' . '00:00';
        }

        return $date . ' ' . substr($time, 0, 5);
    }

    /**
     * Create the activity list.
     *
     * @param string $query Optional search query.
     *
     * @throws Exception
     * @throws \Smarty\Exception
     */
    public function createList(string $query = ''): void
    {
        global $gDb, $gL10n, $gCurrentOrgId, $gCurrentUser, $gCurrentSession;

        $this->setHtmlID('adm_requirements_activities');
        $this->setHeadline($gL10n->get('SYS_REQ_ACTIVITIES'));

        $this->addPageFunctionsMenuItem(
            'menu_item_req_activity_new',
            $gL10n->get('SYS_CREATE_ENTRY'),
            SecurityUtils::encodeUrl(
                ADMIDIO_URL . FOLDER_MODULES . '/requirements/activities.php',
                array('mode' => 'edit')
            ),
            'bi-plus-circle-fill'
        );
        $this->addPageFunctionsMenuItem(
            'menu_item_req_providers',
            $gL10n->get('SYS_REQ_PROVIDERS'),
            SecurityUtils::encodeUrl(
                ADMIDIO_URL . FOLDER_MODULES . '/requirements/providers.php',
                array('mode' => 'list')
            ),
            'bi-building'
        );

        ChangelogService::displayHistoryButton($this, 'req_activities', 'req_activities');

        $sqlWhere = ' WHERE rqa_org_id = ? ';
        $queryParams = array($gCurrentOrgId);

        if (!Component::isAdministrable('REQUIREMENTS')) {
            $sqlWhere .= ' AND rqa_user_id = ? ';
            $queryParams[] = (int) $gCurrentUser->getValue('usr_id');
        }

        if ($query !== '') {
            $sqlWhere .= ' AND (rqa_title LIKE ? OR rqa_provider_name LIKE ?) ';
            $queryParams[] = '%' . $query . '%';
            $queryParams[] = '%' . $query . '%';
        }

        $sql = 'SELECT *
                  FROM ' . TBL_REQ_ACTIVITIES . '
                ' . $sqlWhere . '
              ORDER BY rqa_begin_date DESC, rqa_title ASC';

        $activityStatement = $gDb->queryPrepared($sql, $queryParams);

        $templateActivities = array();

        while ($row = $activityStatement->fetch()) {
            $activity = new Activity($gDb);
            $activity->setArray($row);

            if (!$activity->isVisible()) {
                continue;
            }

            $templateActivity = array(
                'uuid' => $activity->getValue('rqa_uuid'),
                'title' => $activity->getValue('rqa_title'),
                'location' => $activity->getValue('rqa_location'),
                'providerName' => $activity->getValue('rqa_provider_short_name') !== ''
                    ? $activity->getValue('rqa_provider_short_name')
                    : $activity->getValue('rqa_provider_name'),
                'beginDate' => $activity->getValue('rqa_begin_date'),
                'beginTime' => $activity->getValue('rqa_begin_time'),
                'endDate' => $activity->getValue('rqa_end_date'),
                'endTime' => $activity->getValue('rqa_end_time'),
                'attendance' => $activity->getValue('rqa_attendance'),
                'actions' => array()
            );

            if ($activity->isEditable()) {
                $templateActivity['actions'][] = array(
                    'url' => SecurityUtils::encodeUrl(
                        ADMIDIO_URL . FOLDER_MODULES . '/requirements/activities.php',
                        array(
                            'mode' => 'edit',
                            'uuid' => $activity->getValue('rqa_uuid')
                        )
                    ),
                    'icon' => 'bi bi-pencil-square',
                    'tooltip' => $gL10n->get('SYS_EDIT')
                );
            }

            if ($activity->isDeletable()) {
                $templateActivity['actions'][] = array(
                    'dataHref' => 'callUrlHideElement(\'adm_req_activity_' .
                        $activity->getValue('rqa_uuid') . '\', \'' .
                        SecurityUtils::encodeUrl(
                            ADMIDIO_URL . FOLDER_MODULES . '/requirements/activities.php',
                            array(
                                'mode' => 'delete',
                                'uuid' => $activity->getValue('rqa_uuid')
                            )
                        ) . '\', \'' . $gCurrentSession->getCsrfToken() . '\')',
                    'dataMessage' => $gL10n->get(
                        'SYS_WANT_DELETE_ENTRY',
                        array($activity->getValue('rqa_title'))
                    ),
                    'icon' => 'bi bi-trash',
                    'tooltip' => $gL10n->get('SYS_DELETE')
                );
            }

            $templateActivities[] = $templateActivity;
        }

        $this->smarty->assign('activities', $templateActivities);
        $this->smarty->assign('query', $query);
        $this->smarty->assign('urlActivityList', ADMIDIO_URL . FOLDER_MODULES . '/requirements/activities.php');
        $this->smarty->assign('l10n', $gL10n);

        $this->pageContent .= $this->smarty->fetch('modules/requirements.activities.list.tpl');
    }

    /**
     * Get providers visible to the current user as select-box entries.
     *
     * @return array<int, string>
     *
     * @throws Exception
     */
    private function getProviderSelectBoxEntries(): array
    {
        global $gDb, $gCurrentOrgId, $gCurrentUser;

        $sqlWhere = ' WHERE rqp_org_id = ? ';
        $queryParams = array($gCurrentOrgId);

        if (!Component::isAdministrable('REQUIREMENTS')) {
            $sqlWhere .= ' AND (rqp_public = ? OR rqp_usr_id_create = ?) ';
            $queryParams[] = true;
            $queryParams[] = (int) $gCurrentUser->getValue('usr_id');
        }

        $sql = 'SELECT rqp_id, rqp_name, rqp_short_name
                    FROM ' . TBL_REQ_PROVIDERS . '
                    ' . $sqlWhere . '
                ORDER BY rqp_qualified DESC, rqp_name ASC';

        $providerStatement = $gDb->queryPrepared($sql, $queryParams);

        $providers = array();

        while ($provider = $providerStatement->fetch()) {
            $providerName = (string) $provider['rqp_name'];
            $providerShortName = (string) $provider['rqp_short_name'];

            if ($providerShortName !== '') {
                $providers[(int) $provider['rqp_id']] = $providerShortName . ' - ' . $providerName;
            } else {
                $providers[(int) $provider['rqp_id']] = $providerName;
            }
        }
        return $providers;
    }
}