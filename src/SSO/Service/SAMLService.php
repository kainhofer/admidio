<?php
namespace Admidio\SSO\Service;

use LightSaml\Builder\Profile\Metadata\MetadataProfileBuilder;
use LightSaml\Model\Protocol\AuthnRequest;
use LightSaml\Model\Protocol\LogoutRequest;
use LightSaml\Model\Protocol\Response;
use LightSaml\Model\Assertion\Assertion;
use LightSaml\Model\Assertion\Subject;
use LightSaml\Model\Assertion\NameID;
use LightSaml\Model\Assertion\AttributeStatement;
use LightSaml\Model\Assertion\Attribute;
use LightSaml\SamlConstants;
use LightSaml\Credential\X509Certificate;
use LightSaml\Credential\KeyHelper;
use LightSaml\Binding\HttpRedirectBinding;
use LightSaml\Binding\HttpPostBinding;
use LightSaml\Model\Metadata\EntityDescriptor;
use LightSaml\Model\Metadata\IdpSsoDescriptor;
use LightSaml\Model\Metadata\SingleSignOnService;
use LightSaml\Model\Metadata\SingleLogoutService;
use LightSaml\Model\Context\SerializationContext;
use Admidio\SSO\Repository\ServiceProviderRepository;

use Admidio\Infrastructure\Database;
use Admidio\Users\Entity\User;
use Admidio\Roles\Entity\RolesRights;
use Admidio\SSO\Entity\SAMLClient;
use Exception;


class SAMLService {
    private Database $db;
    private User $currentUser;
    private $spRepository;
    private $idpEntityId;
    private $ssoUrl;
    private $sloUrl;

    public function __construct(Database $db, User $currentUser) {
        global $gSettingsManager;
        $this->db           = $db;
        $this->currentUser  = $currentUser;
        // $this->spRepository = new ServiceProviderRepository($db);

        if ($gSettingsManager->getInt('sso_pretty_urls')) {
            $this->idpEntityId = ADMIDIO_URL;
            $this->ssoUrl      = ADMIDIO_URL . "/adm_plugins/sso/saml/ssso";
            $this->sloUrl      = ADMIDIO_URL . "/adm_plugins/sso/saml/slo";
        } else {
            $this->idpEntityId = ADMIDIO_URL;
            $this->ssoUrl      = ADMIDIO_URL . "/adm_plugins/sso/index.php?type=saml&action=sso";
            $this->sloUrl      = ADMIDIO_URL . "/adm_plugins/sso/index.php?type=saml&action=slo";
        }
    }


    
    /**
     * Save data from the SAML client edit form into the database.
     * @throws Exception
     */
    public function save($clientId)
    {
        global $gCurrentSession;

        // check form field input and sanitized it from malicious content
        $clientEditForm = $gCurrentSession->getFormObject($_POST['adm_csrf_token']);
        $formValues = $clientEditForm->validate($_POST);

        $client = new SAMLClient($this->db, $clientId);

        $this->db->startTransaction();

        // write form values in menu object
        foreach ($formValues as $key => $value) {
            if (str_starts_with($key, 'smc_')) {
                $client->setValue($key, $value);
            }
        }

        $client->save();

        // save changed roles rights of the menu
        if (isset($_POST['sso_saml_roles'])) {
            $accessRoles = array_map('intval', $_POST['sso_saml_roles']);
        } else {
            $accessRoles = array();
        }

        $accessRolesRights = new RolesRights($this->db, 'sso_saml_access', $clientId);
        $accessRolesRights->saveRoles($accessRoles);

        $this->db->endTransaction();
    }


    
    /**
     * Return all SAML client Ids stored in the database. For each client ID, the full SAML client can be 
     * retrieved by new SAMLClient($db, $clientId).
     * @return array Returns an array with all client Ids
     * @throws Exception
     */
    public function getClientIds(): array
    {
        $sql = 'SELECT smc_client_id
          FROM ' . TBL_SAML_CLIENTS . ' AS clients';
        $clients = array();
        $clientsStatement = $this->db->queryPrepared($sql, []);
        while ($row = $clientsStatement->fetch()) {
            $clients[] = $row['smc_client_id'];
        }
        return $clients;
    }
    
    /**
     * Return all numeric Ids of  SAML clients stored in the database.
     * @return array Returns an array with all numeric  Ids
     * @throws Exception
     */
    public function getIds(): array
    {
        $sql = 'SELECT smc_id
          FROM ' . TBL_SAML_CLIENTS . ' AS clients';
        $clients = array();
        $clientsStatement = $this->db->queryPrepared($sql, []);
        while ($row = $clientsStatement->fetch()) {
            $clients[] = $row['smc_id'];
        }
        return $clients;
    }


    protected function receiveMessage() {
        $request = \Symfony\Component\HttpFoundation\Request::createFromGlobals();

        $bindingFactory = new \LightSaml\Binding\BindingFactory();
        $binding = $bindingFactory->getBindingByRequest($request);
        
        $messageContext = new \LightSaml\Context\Profile\MessageContext();
        $response = $binding->receive($request, $messageContext);
        
        return $response;
    }

    public function handleMetadataRequest() {
        $entityDescriptor = new EntityDescriptor();
        $entityDescriptor->setEntityID($this->idpEntityId);

        $idpDescriptor = new IdpSsoDescriptor();
        $idpDescriptor->addProtocolSupportEnumeration(SamlConstants::NS_SAMLP);
        
        $ssoService = new SingleSignOnService();
        $ssoService->setBinding(SamlConstants::BINDING_HTTP_REDIRECT);
        $ssoService->setLocation($this->ssoUrl);
        $idpDescriptor->addSingleSignOnService($ssoService);
        
        $sloService = new SingleLogoutService();
        $sloService->setBinding(SamlConstants::BINDING_HTTP_REDIRECT);
        $sloService->setLocation($this->sloUrl);
        $idpDescriptor->addSingleLogoutService($sloService);

        $entityDescriptor->addItem($idpDescriptor);
        
        $context = new SerializationContext();
        $entityDescriptor->serialize($context->getDocument(), $context);
        
        return $context->getDocument()->saveXML();
    }

    public function handleSSORequest(AuthnRequest $request) {
        if (!$this->currentUser->isLoggedIn()) {
            header("Location: /adm_program/system/login.php");
            exit;
        }
        $request = $this->receiveMessage();
        if (!$request instanceof AuthnRequest) {
            throw new Exception("Invalid request");
        }


        $issuer = new \LightSaml\Model\Assertion\Issuer($this->idpEntityId);

        $response = new Response();
        $response
            ->addAssertion($assertion = new Assertion())
            ->setStatus(new \LightSaml\Model\Protocol\Status(
                        new \LightSaml\Model\Protocol\StatusCode(
                                        SamlConstants::STATUS_SUCCESS)
                        ))
            ->setID(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setDestination('https://sp.com/acs') // TODO_RK
            ->setIssuer($issuer)
        ;

        $assertion
            ->setId(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setIssuer($issuer)
            ->setSubject(
                (new Subject())
                    ->setNameID(new NameID(
                        $this->currentUser->getValue("usr_id"), // TODO_RK
                        SamlConstants::NAME_ID_FORMAT_UNSPECIFIED
                    ))
                    ->addSubjectConfirmation(
                        (new \LightSaml\Model\Assertion\SubjectConfirmation())
                            ->setMethod(SamlConstants::CONFIRMATION_METHOD_BEARER)
                            ->setSubjectConfirmationData(
                                (new \LightSaml\Model\Assertion\SubjectConfirmationData())
                                    ->setInResponseTo($request->getID())
                                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                                    ->setRecipient('https://sp.com/acs') // TODO_RK
                            )
                    )
            )
            ->setConditions(
                (new \LightSaml\Model\Assertion\Conditions())
                    ->setNotBefore(new \DateTime())
                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                    ->addItem(
                        new \LightSaml\Model\Assertion\AudienceRestriction(['https://sp.com/acs']) // TODO_RK
                    )
            );

        $attributeStatement = new AttributeStatement();
        $attributeStatement->addAttribute(new Attribute(\LightSaml\ClaimTypes::EMAIL_ADDRESS, $this->currentUser->getValue("usr_email")));
        $attributeStatement->addAttribute(new Attribute(\LightSaml\ClaimTypes::COMMON_NAME, $this->currentUser->readableName()));
        // TODO_RK: Add more attributes, in particular groups, firstname, lastname, username, user id
        $assertion->addItem($attributeStatement);

        $assertion->addItem(
                (new \LightSaml\Model\Assertion\AuthnStatement())
                    ->setAuthnInstant(new \DateTime('-10 MINUTE'))
                    ->setSessionIndex('_some_session_index')
                    ->setAuthnContext(
                        (new \LightSaml\Model\Assertion\AuthnContext())
                            ->setAuthnContextClassRef(\LightSaml\SamlConstants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT)
                    )
            )
        ;


        
        $subject = new Subject();
        $nameId = new NameID();
        $nameId->setValue($this->currentUser->getValue("usr_id"));
        $nameId->setFormat(SamlConstants::NAME_ID_FORMAT_UNSPECIFIED);
        $subject->setNameID($nameId);
        $assertion->setSubject($subject);
        

        $response->addAssertion($assertion);
        
        $binding = new HttpPostBinding();
        return $binding->send($response);
    }

    public function handleSLORequest(LogoutRequest $request) {
        session_destroy();
        return json_encode(["SLO" => true]);
    }
}
