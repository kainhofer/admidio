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
use Admidio\Requirements\Entity\Provider;

class RequirementsProviderPresenter extends PagePresenter
{
    protected string $providerUuid = '';

    /**
     * Constructor.
     *
     * @param string $providerUuid UUID of the provider.
     *
     * @throws Exception
     */
    public function __construct(string $providerUuid = '')
    {
        $this->providerUuid = $providerUuid;
        parent::__construct($providerUuid);
    }

    /**
     * Create the provider edit form.
     *
     * @throws Exception
     */
    public function createEditForm(): void
    {
        global $gDb, $gL10n, $gCurrentSession, $gSettingsManager;

        $provider = new Provider($gDb);

        $this->setHtmlID('adm_requirements_provider_edit');

        if ($this->providerUuid !== '') {
            $provider->readDataByUuid($this->providerUuid);

            if (!$provider->isEditable()) {
                throw new Exception('SYS_NO_RIGHTS');
            }

            $this->setHeadline($gL10n->get('SYS_EDIT_VAR', array($gL10n->get('SYS_REQ_PROVIDER'))));
        } else {
            $provider->setValue('rqp_public', true);
            $provider->setValue('rqp_editable', false);
            $provider->setValue('rqp_qualified', false);

            $this->setHeadline($gL10n->get('SYS_CREATE_VAR', array($gL10n->get('SYS_REQ_PROVIDER'))));
        }

        ChangelogService::displayHistoryButton(
            $this,
            'req_providers',
            'req_providers',
            !empty($this->providerUuid),
            array('uuid' => $this->providerUuid)
        );

        $form = new FormPresenter(
            'adm_requirements_provider_edit_form',
            'modules/requirements.providers.edit.tpl',
            SecurityUtils::encodeUrl(
                ADMIDIO_URL . FOLDER_MODULES . '/requirements/providers.php',
                array(
                    'uuid' => $this->providerUuid,
                    'mode' => 'save'
                )
            ),
            $this
        );

        $form->addInput(
            'rqp_name',
            $gL10n->get('SYS_NAME'),
            htmlentities((string) $provider->getValue('rqp_name', 'database'), ENT_QUOTES),
            array(
                'maxLength' => 255,
                'property'  => FormPresenter::FIELD_REQUIRED
            )
        );
        $form->addInput(
            'rqp_short_name',
            $gL10n->get('SYS_REQ_PROVIDER_SHORT_NAME'),
            htmlentities((string) $provider->getValue('rqp_short_name', 'database'), ENT_QUOTES),
            array(
                'maxLength' => 255,
                'helpTextId' => 'SYS_REQ_PROVIDER_SHORT_NAME_DESC'
            )
        );        

        $form->addMultilineTextInput(
            'rqp_address',
            $gL10n->get('SYS_ADDRESS'),
            $provider->getValue('rqp_address', 'database'),
            3
        );

        $form->addInput(
            'rqp_url',
            $gL10n->get('SYS_WEBSITE'),
            $provider->getValue('rqp_url', 'database'),
            array(
                'maxLength' => 500,
                'type'      => 'url'
            )
        );

        $form->addMultilineTextInput(
            'rqp_description',
            $gL10n->get('SYS_DESCRIPTION'),
            $provider->getValue('rqp_description', 'database'),
            4
        );

        if (Component::isAdministrable('REQUIREMENTS')) {
            $form->addCheckbox(
                'rqp_qualified',
                $gL10n->get('SYS_REQ_PROVIDER_QUALIFIED'),
                (bool) $provider->getValue('rqp_qualified'),
                array('helpTextId' => 'SYS_REQ_PROVIDER_QUALIFIED_DESC')
            );
        }

        if (
            $this->providerUuid === ''
            || $provider->canChangeVisibilityFlags()
        ) {
            $form->addCheckbox(
                'rqp_public',
                $gL10n->get('SYS_REQ_PROVIDER_PUBLIC'),
                (bool) $provider->getValue('rqp_public'),
                array('helpTextId' => 'SYS_REQ_PROVIDER_PUBLIC_DESC')
            );

            $form->addCheckbox(
                'rqp_editable',
                $gL10n->get('SYS_REQ_PROVIDER_EDITABLE'),
                (bool) $provider->getValue('rqp_editable'),
                array('helpTextId' => 'SYS_REQ_PROVIDER_EDITABLE_DESC')
            );
        }

        $form->addSubmitButton(
            'adm_button_save',
            $gL10n->get('SYS_SAVE'),
            array(
                'icon'  => 'bi-check-lg',
                'class' => 'offset-sm-3'
            )
        );

        $this->assignSmartyVariable('userCreatedName', $provider->getNameOfCreatingUser() ?? '');
        $this->assignSmartyVariable('userCreatedTimestamp', $provider->getValue('rqp_timestamp_create') ?? '');
        $this->assignSmartyVariable('lastUserEditedName', $provider->getNameOfLastEditingUser() ?? '');
        $this->assignSmartyVariable('lastUserEditedTimestamp', $provider->getValue('rqp_timestamp_change') ?? '');

        $form->addToHtmlPage();
        $gCurrentSession->addFormObject($form);
    }

    /**
     * Create the provider list.
     *
     * @param string $query Optional search query.
     *
     * @throws Exception
     * @throws \Smarty\Exception
     */
    public function createList(string $query = ''): void
    {
        global $gDb, $gL10n, $gCurrentOrgId, $gCurrentUser, $gCurrentSession, $gSettingsManager;

        $this->setHtmlID('adm_requirements_providers');
        $this->setHeadline($gL10n->get('SYS_REQ_PROVIDERS'));

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
            'req_providers',
            'req_providers'
        );

        $sqlWhere = ' WHERE rqp_org_id = ? ';
        $queryParams = array($gCurrentOrgId);

        if (!Component::isAdministrable('REQUIREMENTS')) {
            $sqlWhere .= ' AND (rqp_public = ? OR rqp_usr_id_create = ?) ';
            $queryParams[] = true;
            $queryParams[] = (int) $gCurrentUser->getValue('usr_id');
        }

        if ($query !== '') {
            $sqlWhere .= ' AND rqp_name LIKE ? ';
            $queryParams[] = '%' . $query . '%';
        }

        $sql = 'SELECT *
                  FROM ' . TBL_REQ_PROVIDERS . '
                ' . $sqlWhere . '
              ORDER BY rqp_qualified DESC, rqp_name ASC';

        $providerStatement = $gDb->queryPrepared($sql, $queryParams);

        $templateProviders = array();

        while ($row = $providerStatement->fetch()) {
            $provider = new Provider($gDb);
            $provider->setArray($row);

            if (!$provider->isVisible()) {
                continue;
            }

            $templateProvider = array(
                'uuid'        => $provider->getValue('rqp_uuid'),
                'name'        => $provider->getValue('rqp_name'),
                'shortName'   => $provider->getValue('rqp_short_name'),
                'description' => $provider->getValue('rqp_description'),
                'url'         => $provider->getValue('rqp_url'),
                'qualified'   => (bool) $provider->getValue('rqp_qualified'),
                'public'      => (bool) $provider->getValue('rqp_public'),
                'editable'    => (bool) $provider->getValue('rqp_editable'),
                'actions'     => array()
            );

            if ($provider->isEditable()) {
                $templateProvider['actions'][] = array(
                    'url' => SecurityUtils::encodeUrl(
                        ADMIDIO_URL . FOLDER_MODULES . '/requirements/providers.php',
                        array(
                            'mode' => 'edit',
                            'uuid' => $provider->getValue('rqp_uuid')
                        )
                    ),
                    'icon'    => 'bi bi-pencil-square',
                    'tooltip' => $gL10n->get('SYS_EDIT')
                );
            }

            if ($provider->isDeletable()) {
                $templateProvider['actions'][] = array(
                    'dataHref' => 'callUrlHideElement(\'adm_req_provider_' .
                        $provider->getValue('rqp_uuid') . '\', \'' .
                        SecurityUtils::encodeUrl(
                            ADMIDIO_URL . FOLDER_MODULES . '/requirements/providers.php',
                            array(
                                'mode' => 'delete',
                                'uuid' => $provider->getValue('rqp_uuid')
                            )
                        ) . '\', \'' . $gCurrentSession->getCsrfToken() . '\')',
                    'dataMessage' => $gL10n->get(
                        'SYS_WANT_DELETE_ENTRY',
                        array($provider->getValue('rqp_name'))
                    ),
                    'icon'    => 'bi bi-trash',
                    'tooltip' => $gL10n->get('SYS_DELETE')
                );
            }

            $templateProviders[] = $templateProvider;
        }

        $this->smarty->assign('providers', $templateProviders);
        $this->smarty->assign('query', $query);
        $this->smarty->assign('urlProviderList', ADMIDIO_URL . FOLDER_MODULES . '/requirements/providers.php');
        $this->smarty->assign('l10n', $gL10n);

        $this->pageContent .= $this->smarty->fetch('modules/requirements.providers.list.tpl');
    }
}