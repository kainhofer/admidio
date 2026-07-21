<?php
/**
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 */

use Admidio\Components\Entity\Component;
use Admidio\Infrastructure\Exception;
use Admidio\Infrastructure\Utils\SecurityUtils;
use Admidio\Requirements\Entity\Provider;
use Admidio\Requirements\Service\ProviderService;
use Admidio\UI\Presenter\RequirementsProviderPresenter;

try {
    require_once(__DIR__ . '/../../system/common.php');

    // only valid logged-in users may use the provider catalogue
    require(__DIR__ . '/../../system/login_valid.php');

    $getMode = admFuncVariableIsValid($_GET, 'mode', 'string', array('defaultValue' => 'list', 'validValues'  => array('list', 'edit', 'save', 'delete')));

    $getProviderUuid = '';

    if (!empty($_GET['uuid'])) {
        $getProviderUuid = admFuncVariableIsValid($_GET, 'uuid', 'uuid');
    }

    $getQuery = admFuncVariableIsValid($_GET, 'query', 'string', array('defaultValue' => ''));

    if (!Component::isVisible('REQUIREMENTS')) {
        throw new Exception('SYS_NO_RIGHTS');
    }

    switch ($getMode) {
        case 'list':
            $page = new RequirementsProviderPresenter();
            $page->createList($getQuery);
            $gNavigation->addStartUrl(CURRENT_URL, $page->getHeadline(), 'bi-clipboard-check');
            $page->show();
            break;

        case 'edit':
            $page = new RequirementsProviderPresenter($getProviderUuid);
            $page->createEditForm();
            $gNavigation->addUrl(CURRENT_URL, $page->getHeadline());
            $page->show();
            break;

        case 'save':
            $providerService = new ProviderService($gDb, $getProviderUuid);
            $providerService->save();

            $gNavigation->deleteLastUrl();

            echo json_encode(array(
                'status' => 'success',
                'url'    => $gNavigation->getUrl()
            ));
            break;

        case 'delete':
            SecurityUtils::validateCsrfToken($_POST['adm_csrf_token']);

            if ($getProviderUuid === '') {
                throw new Exception('SYS_INVALID_PAGE_VIEW');
            }

            $provider = new Provider($gDb);
            $provider->readDataByUuid($getProviderUuid);

            if (!$provider->isDeletable()) {
                throw new Exception('SYS_NO_RIGHTS');
            }

            $provider->delete();

            echo json_encode(array('status' => 'success'));
            break;
    }
} catch (Throwable $e) {
    handleException($e, in_array($getMode ?? '', array('save', 'delete')));
}
