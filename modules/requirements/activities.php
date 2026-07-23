<?php
/**
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 */

use Admidio\Components\Entity\Component;
use Admidio\Infrastructure\Exception;
use Admidio\Infrastructure\Utils\SecurityUtils;
use Admidio\Requirements\Entity\Activity;
use Admidio\Requirements\Service\ActivityService;
use Admidio\UI\Presenter\RequirementsActivityPresenter;

try {
    require_once(__DIR__ . '/../../system/common.php');

    require(__DIR__ . '/../../system/login_valid.php');
    if (!Component::isVisible('REQUIREMENTS')) {
        throw new Exception('SYS_NO_RIGHTS');
    }

    $getMode = admFuncVariableIsValid($_GET, 'mode', 'string', array('defaultValue' => 'list', 'validValues' => array('list', 'edit', 'save', 'delete')));
    $getActivityUuid = '';
    if (!empty($_GET['uuid'])) {
        $getActivityUuid = admFuncVariableIsValid($_GET, 'uuid', 'uuid');
    }

    $getQuery = admFuncVariableIsValid($_GET, 'query', 'string', array('defaultValue' => ''));
    switch ($getMode) {
        case 'list':
            $page = new RequirementsActivityPresenter();
            $page->createList($getQuery);
            $gNavigation->addStartUrl(CURRENT_URL, $page->getHeadline(), 'bi-clipboard-check');
            $page->show();
            break;

        case 'edit':
            $page = new RequirementsActivityPresenter($getActivityUuid);
            $page->createEditForm();
            $gNavigation->addUrl(CURRENT_URL, $page->getHeadline());
            $page->show();
            break;

        case 'save':
            $activityService = new ActivityService($gDb, $getActivityUuid);
            $activityService->save();

            $gNavigation->deleteLastUrl();

            echo json_encode(array(
                'status' => 'success',
                'url' => $gNavigation->getUrl()
            ));
            break;

        case 'delete':
            SecurityUtils::validateCsrfToken($_POST['adm_csrf_token']);

            if ($getActivityUuid === '') {
                throw new Exception('SYS_INVALID_PAGE_VIEW');
            }

            $activity = new Activity($gDb);
            $activity->readDataByUuid($getActivityUuid);

            if (!$activity->isDeletable()) {
                throw new Exception('SYS_NO_RIGHTS');
            }

            $activity->delete();

            echo json_encode(array('status' => 'success'));
            break;
    }
} catch (Throwable $e) {
    handleException($e, in_array($getMode ?? '', array('save', 'delete'), true));
}