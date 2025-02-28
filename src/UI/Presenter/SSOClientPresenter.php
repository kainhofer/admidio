<?php
namespace Admidio\UI\Presenter;

use Admidio\Infrastructure\Exception;
use Admidio\Infrastructure\Language;
use Admidio\SSO\Entity\SAMLClient;
use Admidio\SSO\Service\SAMLService;
use Admidio\Infrastructure\Utils\SecurityUtils;
use Admidio\Changelog\Service\ChangelogService;
use Admidio\Roles\Entity\RolesRights;

/**
 * @brief Class with methods to display the module pages.
 *
 * This class adds some functions that are used in the menu module to keep the
 * code easy to read and short
 *
 * **Code example**
 * ```
 * // generate html output with available registrations
 * $page = new MenuPresenter('adm_menu', $headline);
 * $page->createEditForm();
 * $page->show();
 * ```
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 */
class SSOClientPresenter extends PagePresenter
{
    /**
     * @var int id of the SAML or OIDC client.
     */
    protected int $clientId = 0;

    /**
     * Constructor creates the page object and initialized all parameters.
     * @param string $clientId Id of the SAML or OIDC client.
     * @throws Exception
     */
    public function __construct(int $clientId = 0)
    {
        $this->clientId = $clientId;
        parent::__construct('');
    }

    /**
     * Create the data for the edit form of a SAML client.
     * @throws Exception
     */
    public function createSAMLEditForm(): void
    {
        global $gDb, $gL10n, $gCurrentSession;

        // create SAML client object
        $client = new SAMLClient($gDb);
        if ($this->clientId > 0) {
            $this->setHeadline($gL10n->get('SYS_EDIT_VAR', array($gL10n->get('SYS_SSO_CLIENT_SAML'))));
        } else {
            $this->setHeadline($gL10n->get('SYS_CREATE_VAR', array($gL10n->get('SYS_SSO_CLIENT_SAML'))));
        }
        $this->setHtmlID('admidio-saml-client-edit');
        
        $roleAccessSet = array();
        if ($this->clientId > 0) {
            $client->readDataById($this->clientId);
        }

        // Access restrictions by role/group are handled through role rights
        $sqlRoles = 'SELECT rol_id, rol_name, org_shortname, cat_name
                       FROM ' . TBL_ROLES . '
                 INNER JOIN ' . TBL_CATEGORIES . '
                         ON cat_id = rol_cat_id
                 INNER JOIN ' . TBL_ORGANIZATIONS . '
                         ON org_id = cat_org_id
                      WHERE rol_valid  = true
                        AND rol_system = false
                        AND cat_name_intern <> \'EVENTS\'
                   ORDER BY cat_name, rol_name';
        $allRolesStatement = $gDb->queryPrepared($sqlRoles);
        $allRolesSet = array();
        while ($rowViewRoles = $allRolesStatement->fetch()) {
            // Each role is now added to this array
            $allRolesSet[] = array(
                $rowViewRoles['rol_id'], // ID 
                $rowViewRoles['rol_name'] . ' (' . $rowViewRoles['org_shortname'] . ')', // Value
                $rowViewRoles['cat_name'] // Group
            );
        }

        ChangelogService::displayHistoryButton($this, 'saml-client', 'saml_clients', !empty($this->clientId), array('id' => $this->clientId));

        // show form
        $form = new FormPresenter(
            'adm_saml_client_edit_form',
            'modules/saml_client.edit.tpl',
            SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_PLUGINS . '/sso/clients.php', array('id' => $this->clientId, 'mode' => 'save_saml')),
            $this
        );

        $form->addInput(
            'smc_client_name',
            $gL10n->get('SYS_SSO_CLIENT_NAME'),
            $client->getValue('smc_client_name'),
            array('maxLength' => 250, 'property' => FormPresenter::FIELD_REQUIRED, 'helpTextId' => $gL10n->get('SYS_SSO_CLIENT_NAME_DESC'))
        );
        $form->addInput(
            'smc_client_id',
            $gL10n->get('SYS_SSO_CLIENT_ID'),
            $client->getValue('smc_client_id'),
            array('maxLength' => 250, 'property' => FormPresenter::FIELD_REQUIRED, 'helpTextId' => $gL10n->get('SYS_SSO_CLIENT_ID_DESC'))
        );
        $form->addInput(
            'smc_metadata_url',
            $gL10n->get('SYS_SSO_METADATA_URL'),
            $client->getValue('smc_metadata_url'),
            array('type' => 'url', 'maxLength' => 2000, 'helpTextId' => $gL10n->get('SYS_SSO_METADATA_URL_DESC'))
        );
        $form->addInput(
            'smc_acs_url',
            $gL10n->get(textId: 'SYS_SSO_ACS_URL'),
            $client->getValue('smc_acs_url'),
            array('type' => 'url', 'maxLength' => 2000, 'property' => FormPresenter::FIELD_REQUIRED, 'helpTextId' => $gL10n->get('SYS_SSO_ACS_URL_DESC'))
        );
        $form->addInput(
            'smc_slo_url',
            $gL10n->get(textId: 'SYS_SSO_SLO_URL'),
            $client->getValue('smc_slo_url'),
            array('type' => 'url', 'maxLength' => 2000, 'helpTextId' => $gL10n->get('SYS_SSO_SLO_URL_DESC'))
        );
        $form->addMultilineTextInput(
            'smc_x509_certificate',
            $gL10n->get('SYS_SSO_X509_CERTIFICATE'),
            $client->getValue('smc_x509_certificate'),
            6,
            array('maxLength' => 6000, 'helpTextId' => $gL10n->get('SYS_SSO_X509_CERTIFICATE_DESC'))
        );


        $form->addSelectBox(
            'sso_saml_roles',
            $gL10n->get('SYS_SSO_ROLES'),
            $allRolesSet,
            array(
                'property' => FormPresenter::FIELD_DEFAULT,
                'defaultValue' => $client->getAccessRolesIds(),
                'multiselect' => true,
                'helpTextId' => 'SYS_SSO_ROLES_DESC'
            )
        );

        $form->addSubmitButton(
            'adm_button_save', 
            $gL10n->get('SYS_SAVE'), 
            array('icon' => 'bi-check-lg', 'class' => 'offset-sm-3'));


    /*******************************************
     * Button to load metadata from the URL
     */
    $form->addButton('adm_button_metadata_setup', $gL10n->get('SYS_SSO_LOAD_METADATA'), array('icon' => 'bi-gear-fill', 'class' => 'btn btn-primary'));
    $this->addJavascript('
    $("#adm_button_metadata_setup").click(function () {
        const metadataUrl = $("#smc_metadata_url").val().trim();
        if (!metadataUrl) { alert("Please enter a metadata URL."); return;}

        // First try to load the metadata directly from the client. If we run into CORS error (loading from a different server 
        // than the one hosting Admidio is often not permitted), we use the admidio server\'s CORS proxy script.
        $.get(metadataUrl)
            .done(function (metadataXml) {
                handleClientMetadataXML(metadataXml);
            })
            .fail(function () {
                // Loading directly from the client failed, try using the CORS proxy script in admidio\'s source tree
                const currentDir = window.location.pathname.substring(0, window.location.pathname.lastIndexOf(\'/\'));
                const proxyUrl = `${window.location.origin}${currentDir}/fetch_metadata.php?url=${encodeURIComponent(metadataUrl)}`;
                $.get(proxyUrl)
                    .done(function (metadataXml) {
                        handleClientMetadataXML(metadataXml);
                    })
                    .fail(function () {
                        alert("Error loading metadata. Please check the URL and try again.");
                    });
            });
    });

    function handleClientMetadataXML(metadataXml) {
        let xmlDoc;
        // If response is already an XML Document, use it directly
        if (metadataXml instanceof Document) {
            xmlDoc = metadataXml;
        } else if (typeof metadataXml === "string") {
            // If response is a string, attempt to parse it as XML
            xmlDoc = $.parseXML(metadataXml);
        } else {
            alert("Unexpected response format.");
            return false;
        }
        const $xml = $(xmlDoc);

        // Use native JavaScript methods to handle XML namespaces
        const entityDescriptor = xmlDoc.querySelector("EntityDescriptor");
        const entityId = entityDescriptor ? entityDescriptor.getAttribute("entityID") : ""

        // Extract Assertion Consumer Service (ACS) URL
        const acsElement = xmlDoc.querySelector("AssertionConsumerService");
        const acsUrl = acsElement ? acsElement.getAttribute("Location") : ""

        const sloElement = xmlDoc.querySelector("SingleLogoutService");
        const sloUrl = sloElement ? sloElement.getAttribute("Location") : ""
        
        // Extract X.509 Certificate
        const x509Element = xmlDoc.querySelector("KeyDescriptor[use=\'signing\'] X509Certificate");
        const x509Cert = x509Element ? x509Element.textContent.trim() : ""
        
        // Populate input fields
        if (entityId !="") {
            $("#smc_client_id").val(entityId);
        }
        if (acsUrl !="") {
            $("#smc_acs_url").val(acsUrl);
        }
        if (sloUrl !="") {
            $("#smc_slo_url").val(sloUrl);
        }
        if (x509Cert !="") {
            $("#smc_x509_certificate").val(formatCertificate(x509Cert));
        }
    }
    // Helper function to format X.509 certificate with proper line breaks
    function formatCertificate(cert) {
        if (!cert) return "";
        return `-----BEGIN CERTIFICATE-----\n${cert.match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----`;
    }
        ', true);

        $this->smarty->assign('nameUserCreated', $client->getNameOfCreatingUser());
        $this->smarty->assign('timestampUserCreated', $client->getValue('smc_timestamp_create'));
        $this->smarty->assign('nameLastUserEdited', $client->getNameOfLastEditingUser());
        $this->smarty->assign('timestampLastUserEdited', $client->getValue('smc_timestamp_change'));
        $form->addToHtmlPage();
        $gCurrentSession->addFormObject($form);
    }



    /**
     * Create the list of SAML and OIDC clients to show to the user.
     * @throws Exception|\Smarty\Exception
     */
    public function createList(): void
    {
        global $gCurrentSession, $gL10n, $gDb, $gCurrentUser;

        $this->setHtmlID('adm_sso_clients_configuration');
        $this->setHeadline($gL10n->get('SYS_SSO_CLIENT_ADMIN'));


        // link to preferences
        $this->addPageFunctionsMenuItem(
            'menu_item_sso_preferences',
            $gL10n->get('SYS_SETTINGS'),
            ADMIDIO_URL . FOLDER_MODULES . '/preferences.php',
            'bi-gear-fill'
        );

        // link to add new client (SAML 2.0 or OIDC is selectable)
        $this->addPageFunctionsMenuItem(
            'menu_item_sso_new_client_saml',
            $gL10n->get('SYS_SSO_CLIENT_ADD_SAML'),
            SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_PLUGINS . '/sso/clients.php', array('mode' => 'edit_saml')),
            'bi-plus-circle-fill'
        );

        // link to add new client (SAML 2.0 or OIDC is selectable)
        $this->addPageFunctionsMenuItem(
            'menu_item_sso_new_client_oidc',
            $gL10n->get('SYS_SSO_CLIENT_ADD_OIDC'),
            SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_PLUGINS . '/sso/clients.php', array('mode' => 'edit_oidc')),
            'bi-plus-circle-fill'
        );

        ChangelogService::displayHistoryButton($this, 'sso-clients', array('saml_clients', 'oauth_clients'));


        $this->addHtml('<p>' . $gL10n->get('SYS_SSO_CLIENT_ADMIN_DESC') . '</p>');

        /* ****************************************************/  
        // SAML 2.0 clients
        /* ****************************************************/  
        $this->addHtml('<h3 class="admidio-content-subheader">' . $gL10n->get('SYS_SSO_CLIENTS_SAML') . '</h3>');
    
        $table = new \HtmlTable('adm_saml_clients_table', $this, true, false);
    
    //    $table->setColumnAlignByArray(array('left', 'left', 'left', 'left', 'left', 'right'));
    
        $table->addRowHeadingByArray(array(
            $gL10n->get('SYS_SSO_CLIENT_NAME'),
            $gL10n->get('SYS_SSO_CLIENT_ID'),
            $gL10n->get('SYS_SSO_ACS_URL'),
            $gL10n->get('SYS_SSO_ROLES'),
            ''
        ));
    
        $table->setMessageIfNoRowsFound('SYS_SSO_NO_SAML_CLIENTS_FOUND');
    
        $table->disableDatatablesColumnsSort(array(3, 6));
        $table->setDatatablesColumnsNotHideResponsive(array(6));
        // special settings for the table
    
    
        $SAMLService = new SAMLService($gDb, $gCurrentUser);
        $templateClientNodes = array();
        foreach ($SAMLService->getIds() as $clientId) {
            $client = new SAMLClient($gDb, $clientId);
            $templateClient = array();
            $templateClient[] = $client->getValue('smc_client_name');
            $templateClient[] = $client->getValue('smc_client_id');
            $templateClient[] = $client->getValue('smc_acs_url');
            $templateClient[] = implode(', ', $client->getAccessRolesNames());
            //$templateClient[] = $client->getValue('create_name');

            $actions = '';
            // add link to edit SAML client
            $actions .= '<a class="admidio-icon-link" href="' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_PLUGINS . '/sso/clients.php', array('mode' => 'edit_saml', 'id' => $clientId)) . '">' .
                    '<i class="bi bi-pencil-square" data-bs-toggle="tooltip" title="' . $gL10n->get('SYS_SSO_EDIT_SAML_CLIENT') . '"></i></a>';
            
            // add link to delete SAML client
            $actions .= '<a class="admidio-icon-link admidio-messagebox" href="javascript:void(0);" data-buttons="yes-no"
                    data-message="' . $gL10n->get('SYS_DELETE_ENTRY', array($client->readableName())) . '"
                    data-href="callUrlHideElement(\'adm_saml_client_' . $clientId . '\', \'' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_PLUGINS . '/sso/clients.php', array('mode' => 'delete_saml', 'id' => $clientId)) . '\', \'' . $gCurrentSession->getCsrfToken() . '\')">
                    <i class="bi bi-trash" data-bs-toggle="tooltip" title="' . $gL10n->get('SYS_SSO_CLIENT_DELETE') . '"></i>
                </a>';
            $templateClient[] = $actions;

            $table->addRowByArray($templateClient, 'adm_saml_client_' . $clientId, array('nobr' => 'true'));
        }
    
        // add table to the form
        $this->addHtml(html: $table->show());

        


        /* ****************************************************/  
        // OIDC clients
        /* ****************************************************/  
        $this->addHtml('<h3 class="admidio-content-subheader">' . $gL10n->get('SYS_SSO_CLIENTS_OIDC') . '</h3>');

        $table = new \HtmlTable('adm_saml_clients_table', $this, true, true);
        $table->setMessageIfNoRowsFound('SYS_SSO_NO_OIDC_CLIENTS_FOUND');

        $this->addHtml($table->show());

    }
}
