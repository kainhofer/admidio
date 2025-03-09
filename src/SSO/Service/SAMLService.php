<?php
namespace Admidio\SSO\Service;

use Admidio\Preferences\Entity\Preferences;
use LightSaml\Builder\Profile\Metadata\MetadataProfileBuilder;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use LightSaml\Model\Protocol\AuthnRequest;
use LightSaml\Model\Protocol\LogoutRequest;
use LightSaml\Model\Protocol\LogoutResponse;
use LightSaml\Model\Protocol\Response;
use LightSaml\Model\Protocol\AttributeQuery;
use LightSaml\Model\Assertion\Assertion;
use LightSaml\Model\Assertion\Subject;
use LightSaml\Model\Assertion\NameID;
use LightSaml\Model\Assertion\AttributeStatement;
use LightSaml\Model\Assertion\Attribute;
use LightSaml\SamlConstants;
use LightSaml\Context\Profile\ProfileContext;
use LightSaml\Credential\X509Certificate;
use LightSaml\Credential\KeyHelper;
use LightSaml\Binding\HttpRedirectBinding;
use LightSaml\Binding\HttpPostBinding;
use LightSaml\Model\Metadata\EntityDescriptor;
use LightSaml\Model\Metadata\KeyDescriptor;
use LightSaml\Model\Metadata\IdpSsoDescriptor;
use LightSaml\Model\Metadata\SingleSignOnService;
use LightSaml\Model\Metadata\SingleLogoutService;
use LightSaml\Model\Context\SerializationContext;
use LightSaml\Model\XmlDSig\SignatureWriter;
use Admidio\SSO\Repository\ServiceProviderRepository;

use Admidio\Infrastructure\Database;
use Admidio\Preferences\ValueObject\SettingsManager;
use Admidio\Users\Entity\User;
use Admidio\Roles\Entity\Role;
use Admidio\Roles\Entity\RolesRights;
use Admidio\SSO\Entity\SAMLClient;
use Admidio\SSO\Entity\Key;
use Exception;
use RobRichards\XMLSecLibs\XMLSecurityKey;


class SAMLService {
    private Database $db;
    private User $currentUser;
    private $spRepository;
    private $idpEntityId;
    private $ssoUrl;
    private $sloUrl;
    private $metadataUrl;

    public function __construct(Database $db, User $currentUser) {
        global $gSettingsManager;
        $this->db           = $db;
        $this->currentUser  = $currentUser;
        // $this->spRepository = new ServiceProviderRepository($db);

        $this->idpEntityId = $gSettingsManager->get('sso_saml_entity_id');
        $this->ssoUrl      = ADMIDIO_URL . "/adm_plugins/sso/index.php/saml/sso";
        $this->sloUrl      = ADMIDIO_URL . "/adm_plugins/sso/index.php/saml/slo";
        $this->metadataUrl = ADMIDIO_URL . "/adm_plugins/sso/index.php/saml/metadata";
    }

    /**
     * Return the SSO endpoint
     * @return string
     */
    public function getSsoEndpoint() {
        return $this->ssoUrl;
    }
    /**
     * Return the SLO endpoint
     * @return string
     */
    public function getSloEndpoint() {
        return $this->sloUrl;
    }
    /**
     * Return the metadata endpoint
     * @return string
     */
    public function getMetadataUrl() {
        return $this->metadataUrl;
    }

    public function getIdPEntityId() : string {
        return $this->idpEntityId;
    }

    
    /**
     * Save data from the SAML client edit form into the database.
     * @throws Exception
     */
    public function save($getClientUUID)
    {
        global $gCurrentSession;

        // check form field input and sanitized it from malicious content
        $clientEditForm = $gCurrentSession->getFormObject($_POST['adm_csrf_token']);
        $formValues = $clientEditForm->validate($_POST);

        $client = new SAMLClient($this->db);
        $client->readDataByUUID($getClientUUID);

        $this->db->startTransaction();

        // Collect all field mappings and the catch-all checkbox
        $samlFields = array_combine($formValues['SAML_saml_fields']??[], $formValues['Admidio_saml_fields']??[]);
        $client->setFieldMapping($samlFields, $formValues['saml_fields_all_other']??false);

        // Collect all role mappings and the catch-all checkbox
        $samlRoles = array_combine($formValues['SAML_saml_roles']??[], $formValues['Admidio_saml_roles']??[]);
        $client->setRoleMapping($samlRoles, $formValues['saml_roles_all_other']??false);

        // write all other form values
        foreach ($formValues as $key => $value) {
            if (str_starts_with($key, 'smc_')) {
                $client->setValue($key, $value);
            }
        }

        $client->save();

        // save changed roles rights of the menu
        if (isset($_POST['saml_roles_access'])) {
            $accessRoles = array_map('intval', $_POST['saml_roles_access']);
        } else {
            $accessRoles = array();
        }

        $accessRolesRights = new RolesRights($this->db, 'sso_saml_access', $client->getValue('smc_id'));
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

    /**
     * Return all UUIDs of  SAML clients stored in the database.
     * @return array Returns an array with all UUIDs
     * @throws Exception
     */
    public function getUUIDs(): array
    {
        $sql = 'SELECT smc_uuid
          FROM ' . TBL_SAML_CLIENTS . ' AS clients';
        $clients = array();
        $clientsStatement = $this->db->queryPrepared($sql, []);
        while ($row = $clientsStatement->fetch()) {
            $clients[] = $row['smc_uuid'];
        }
        return $clients;
    }

    public function getSignatureWriter(string $privkeyPEM, X509Certificate $cert) {
        $privateKeyResource = KeyHelper::createPrivateKey($privkeyPEM, '', false, XMLSecurityKey::RSA_SHA256);
        $signatureWriter = new SignatureWriter($cert, $privateKeyResource, XmlSecurityDSig::SHA256);
        return $signatureWriter;
    }

    protected function receiveMessage() {
        $request = \Symfony\Component\HttpFoundation\Request::createFromGlobals();

        $bindingFactory = new \LightSaml\Binding\BindingFactory();
        $binding = $bindingFactory->getBindingByRequest($request);
        
        $messageContext = new \LightSaml\Context\Profile\MessageContext();
        $binding->receive($request, $messageContext);
        
        return $messageContext->getMessage();
    }

    public function getKeysCertificates() {
        global $gSettingsManager;

        // Private key and Certificate for signatures
        $signatureKeyID = $gSettingsManager->get('sso_saml_signing_key');
        $signatureKey = new Key($this->db, $signatureKeyID);
        
        $idpPrivateKeyPem = $signatureKey->getValue('key_private');
        $idpCertPem = $signatureKey->getValue('key_certificate');
        if (!$idpCertPem) {
            $idpCert = null;
        } else {
            $idpCert = new X509Certificate();
            $idpCert->loadPem($idpCertPem);
        }

        // Certificate for Encryption
        $encryptionKeyID = $gSettingsManager->get('sso_saml_encryption_key');
        $encryptionKey = new Key($this->db, $encryptionKeyID);
        $idpCertEncPem = $encryptionKey->getValue('key_certificate');
        if (!$idpCertEncPem) {
            $idpCertEnc = null;
        } else {
            $idpCertEnc = new X509Certificate();
            $idpCertEnc->loadPem($idpCertEncPem);
        }

        // Return everything as a named array
        return ['idpPrivateKey' => $idpPrivateKeyPem, 'idpCert' => $idpCert, 'idpCertEnc' => $idpCertEnc];

    }

    public function handleMetadataRequest() {
        global $gSettingsManager;
        if ($gSettingsManager->get('sso_saml_enabled') !== '1') {
            throw new Exception("SSO SAML is not enabled");
        }

        $keys = $this->getKeysCertificates();

        $entityId = $this->getIdPEntityId();
        $ssoUrl = $this->getSsoEndpoint();
        $sloUrl = $this->getSloEndpoint();
        $metadataUrl = $this->getMetadataUrl();

        if (!$entityId || !$ssoUrl || !$keys['idpCert'] || !$keys['idpPrivateKey']) {
            throw new Exception("SAML IDP settings are not configured properly.");
        }


        $entityDescriptor = new EntityDescriptor();
        $entityDescriptor->setID(\LightSaml\Helper::generateID());
        $entityDescriptor->setEntityID($entityId);

        // Create IDP SSO Descriptor
        $idpDescriptor = new IDPSSODescriptor();
        $idpDescriptor->setProtocolSupportEnumeration(($gSettingsManager->get('sso_saml_supported_protocols')) ?: SamlConstants::PROTOCOL_SAML2);

        // Add KeyDescriptor for signing
        $keyDescriptor = new KeyDescriptor();
        $keyDescriptor->setUse(KeyDescriptor::USE_SIGNING);
        $keyDescriptor->setCertificate($keys['idpCert']);
        $idpDescriptor->addKeyDescriptor($keyDescriptor);

        // Add KeyDescriptor for encryption
        $keyDescriptor = new KeyDescriptor();
        $keyDescriptor->setUse(KeyDescriptor::USE_ENCRYPTION);
        $keyDescriptor->setCertificate($keys['idpCertEnc']);
        $idpDescriptor->addKeyDescriptor($keyDescriptor);

        // Add NameIDFormats
        $idpDescriptor->addNameIDFormat(SamlConstants::NAME_ID_FORMAT_UNSPECIFIED);
        $idpDescriptor->addNameIDFormat(SamlConstants::NAME_ID_FORMAT_EMAIL);
        $idpDescriptor->addNameIDFormat(SamlConstants::NAME_ID_FORMAT_TRANSIENT);
        $idpDescriptor->addNameIDFormat(SamlConstants::NAME_ID_FORMAT_PERSISTENT);
        $idpDescriptor->addNameIDFormat(SamlConstants::NAME_ID_FORMAT_X509_SUBJECT_NAME);



        // Add SingleSignOnService endpoints with different bindings
        $ssoServiceRedirect = new SingleSignOnService();
        $ssoServiceRedirect->setLocation($ssoUrl);
        $ssoServiceRedirect->setBinding(SamlConstants::BINDING_SAML2_HTTP_REDIRECT);
        $idpDescriptor->addSingleSignOnService($ssoServiceRedirect);

        $ssoServicePost = new SingleSignOnService();
        $ssoServicePost->setLocation($ssoUrl);
        $ssoServicePost->setBinding(SamlConstants::BINDING_SAML2_HTTP_POST);
        $idpDescriptor->addSingleSignOnService($ssoServicePost);


        // Add SingleSignOnService endpoints with different bindings
        $sloServiceRedirect = new SingleLogoutService();
        $sloServiceRedirect->setLocation($sloUrl);
        $sloServiceRedirect->setBinding(SamlConstants::BINDING_SAML2_HTTP_REDIRECT);
        $idpDescriptor->addSingleLogoutService($sloServiceRedirect);

        $sloServicePost = new SingleLogoutService();
        $sloServicePost->setLocation($sloUrl);
        $sloServicePost->setBinding(SamlConstants::BINDING_SAML2_HTTP_POST);
        $idpDescriptor->addSingleLogoutService($sloServicePost);

        

        // Add the IDP Descriptor to EntityDescriptor
        $entityDescriptor->addItem($idpDescriptor);

        // Sign the metadata with private key
        if (!empty($keys['idpPrivateKey']) && !empty($keys['idpCert'])) {
            $entityDescriptor->setSignature($this->getSignatureWriter($keys['idpPrivateKey'], $keys['idpCert']));
        }

        // Output metadata as XML
        header('Content-Type: application/xml');
        // echo $entityDescriptor->toXML()->ownerDocument->saveXML();
        // exit;

        $context = new SerializationContext();
        $entityDescriptor->serialize($context->getDocument(), $context);
        
        echo $context->getDocument()->saveXML();
    }

    public function getSPfromID($clientID) {
        // $entityIdClient = $request->getIssuer()->getValue();

        // Load the SAML client data (entityID is in $request->issuer->getValue())
        $client = new SAMLClient($this->db);
        $client->readDataByEntityId($clientID);
        if ($client->isNewRecord()) {
            throw new Exception("SAML 2.0 client '$clientID' not found in database. Please check the SAML 2.0 client settings and configure the client in Admidio.");
        }
        return $client;
    }

    public function errorResponse(string|array $status, $message, $request, $client) {
        if (!is_array($status)) $status = [$status];
        $statusCode = new \LightSaml\Model\Protocol\StatusCode($status[0]);
        if (count($status) > 1) {
            $statusCode->setStatusCode(new \LightSaml\Model\Protocol\StatusCode($status[1]));
        }
        $status = new \LightSaml\Model\Protocol\Status();
        $status->setStatusCode($statusCode);
        $status->setStatusMessage($message);


        $response = new Response();
        $response->setStatus($status);
        $response->setID('ID' . \LightSaml\Helper::generateID());
        $response->setInResponseTo($request->getID());
        $response->setIssueInstant(new \DateTime());
        $response->setDestination($request->getAssertionConsumerServiceURL());

        
        $issuer = new \LightSaml\Model\Assertion\Issuer($this->getIdPEntityId());
        $response->setIssuer($issuer);

        $keys = $this->getKeysCertificates();
        $response->setSignature($this->getSignatureWriter($keys['idpPrivateKey'], $keys['idpCert']));

        $messageContext = new \LightSaml\Context\Profile\MessageContext();
        $messageContext->setMessage($response);
        
        $binding = new HttpPostBinding();
        $httpResponse = $binding->send($messageContext);
        print $httpResponse->getContent();

        
    }


    public function handleSSORequest() {
        global $gCurrentUser, $gCurrentUserId, $rootPath, $gSettingsManager, $gL10n, $gProfileFields;

        if ($gSettingsManager->get('sso_saml_enabled') !== '1') {
            throw new Exception("SSO SAML is not enabled");
        }

        $request = $this->receiveMessage();
        if (!$request instanceof AuthnRequest) {
            throw new Exception("Invalid request (not an AuthnRequest)");
        }

        if (!$gCurrentUserId) {
            require_once($rootPath . '/adm_program/system/login_valid.php');
        }

        // Load the SAML client data (entityID is in $request->issuer->getValue())
        $entityIdClient = $request->getIssuer()->getValue();
        $client = $this->getSPfromID($entityIdClient);

        $requestId = $request->getID(); // Extract from incoming AuthnRequest
        $clientACS = $request->getAssertionConsumerServiceURL();
        $issuer = new \LightSaml\Model\Assertion\Issuer($this->getIdPEntityId());

        // Check whether the current user has access permissions to the SP client:
        if (!$client->hasAccessRight()) {
            // TODO_RK: Redirect / Show a page with the hint that the current user does not have permissions to access the client 
            // -> Please choose another username: Logout / Switch
            $this->errorResponse([SamlConstants::STATUS_RESPONDER, "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"],
                     "User does not have permission to access this SP.", $request, $client);
            exit;
        }
        
        $login = $this->currentUser->getValue($client->getValue('smc_userid_field'))??'';

        $statusSuccess = new \LightSaml\Model\Protocol\Status(
            new \LightSaml\Model\Protocol\StatusCode(SamlConstants::STATUS_SUCCESS));

        $response = new Response();
        $response->setStatus($statusSuccess);
        $response->setID('ID' . \LightSaml\Helper::generateID());
        $response->setIssueInstant(issueInstant: new \DateTime());
        $response->setDestination($clientACS);
        $response->setIssuer($issuer);
        $response->setInResponseTo($requestId);
        $response->addAssertion($assertion = new Assertion());

        // Create SubjectConfirmationData
        $subjectConfirmationData = new \LightSaml\Model\Assertion\SubjectConfirmationData();
        $subjectConfirmationData
            ->setRecipient($clientACS) // Required recipient URL
            ->setNotOnOrAfter(new \DateTime('+10 MINUTE')) // Expiry time
            ->setInResponseTo($requestId); // ID of the AuthnRequest (optional but recommended)

        // Create SubjectConfirmation (Bearer method)
        $subjectConfirmation = new \LightSaml\Model\Assertion\SubjectConfirmation();
        $subjectConfirmation
            ->setMethod(SamlConstants::CONFIRMATION_METHOD_BEARER) // Bearer confirmation method
            ->setSubjectConfirmationData($subjectConfirmationData);
            
        $subject = new Subject();
        $subject->setNameID(new NameID($login, SamlConstants::NAME_ID_FORMAT_UNSPECIFIED));
        $subject->addSubjectConfirmation($subjectConfirmation);

        $assertion
            ->setId('ID' . \LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setIssuer($issuer)
            ->setSubject($subject)
            ->setConditions(
                (new \LightSaml\Model\Assertion\Conditions())
                ->setNotBefore(new \DateTime('-5 SECOND'))
                ->setNotOnOrAfter(new \DateTime('+10 MINUTE'))
                ->addItem(
                    new \LightSaml\Model\Assertion\AudienceRestriction([$entityIdClient])
                )
            );
            
        $assertion->addItem(
            (new \LightSaml\Model\Assertion\AuthnStatement())
                ->setAuthnInstant(new \DateTime('-5 SECOND'))
                ->setSessionNotOnOrAfter(new \DateTime('+10 MINUTE'))
                ->setSessionIndex(session_id())
                ->setAuthnContext(
                    (new \LightSaml\Model\Assertion\AuthnContext())
                        ->setAuthnContextClassRef(SamlConstants::AUTHN_CONTEXT_UNSPECIFIED)
                )
        );

        $attributeStatement = new AttributeStatement();

        $attributeStatement->addAttribute(
            (new Attribute('username', $login))
                ->setFriendlyName('Username')
                ->setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
        );
        
        $fields = explode(',', $client->getValue('smc_user_fields'));
        foreach ($fields as $attrName) {
            $att = $this->getUserAttribute($gCurrentUser, $attrName);
            if ($att->getFirstAttributeValue() !== null) {
                $attributeStatement->addAttribute($att);
            }
        }
        $assertion->addItem($attributeStatement);


        // TODO: Sign the assertion and the whole response!
        $keys = $this->getKeysCertificates();
        $assertion->setSignature($this->getSignatureWriter($keys['idpPrivateKey'], $keys['idpCert']));
        $response->setSignature($this->getSignatureWriter($keys['idpPrivateKey'], $keys['idpCert']));

        $messageContext = new \LightSaml\Context\Profile\MessageContext();
        $messageContext->setMessage($response);
        
        $binding = new HttpPostBinding();
        $httpResponse = $binding->send($messageContext);
        print $httpResponse->getContent();
    }


    public function handleSLORequest() {
        global $gCurrentUserId, $gCurrentUser, $gDb, $gMenu, $g_organization;
        global $gSettingsManager, $gCurrentSession, $gCurrentOrganization, $gProfileFields, $gCurrentOrgId, $gValidLogin;

        if ($gSettingsManager->get('sso_saml_enabled') !== '1') {
            throw new Exception("SSO SAML is not enabled");
        }

        $request = $this->receiveMessage();
        if (!$request instanceof LogoutRequest) {
            throw new Exception("Invalid request (not a LogoutRequest)");
        }

        $sessionId = session_id();

        $entityIdClient = $request->getIssuer()->getValue();
        $client = $this->getSPfromID($entityIdClient);

        if ($gCurrentUserId) {
            // Logout will only work if you are logged in...


            /**  1. LOCAL LOGOUT FROM ADMIDIO */

            // If user is logged in, terminate their current session
            $this->db->queryPrepared("DELETE FROM adm_sessions WHERE ses_session_id = ?", [$sessionId]);

            $gValidLogin = false;

            // remove user from session
            $gCurrentSession->logout();
        
            // if login organization is different to organization of config file then create new session variables
            if (strcasecmp($gCurrentOrganization->getValue('org_shortname'), $g_organization) !== 0 && $g_organization !== '') {
                // read organization of config file with their preferences
                $gCurrentOrganization->readDataByColumns(array('org_shortname' => $g_organization));
        
                // read new profile field structure for this organization
                $gProfileFields->readProfileFields($gCurrentOrgId);
        
                // save new organization id to session
                $gCurrentSession->setValue('ses_org_id', $gCurrentOrgId);
                $gCurrentSession->save();
        
                // read all settings from the new organization
                $gSettingsManager = new SettingsManager($gDb, $gCurrentOrgId);
            }
        
            // clear data from global objects
            $gCurrentUser->clear();
            $gMenu->initialize();
        
                    
            /**  2. NOTIFY ALL REGISTERED CLIENTS OF THE LOGOUT */

            
            // Notify all registered SPs for logout
            foreach ($this->getIds() as $spId) {
                $sp = new SAMLClient($this->db, $spId);
                $this->sendLogoutRequest($sp, $gCurrentUser);
            }

            $logoutResponse = new LogoutResponse();
            $logoutResponse->setIssuer(new \LightSaml\Model\Assertion\Issuer($this->getIdPEntityId()));
            $logoutResponse->setInResponseTo($request->getID());
            $statusSuccess = new \LightSaml\Model\Protocol\Status(
                new \LightSaml\Model\Protocol\StatusCode(SamlConstants::STATUS_SUCCESS));
            $logoutResponse->setStatus($statusSuccess);
            
            // Sign the response!
            $keys = $this->getKeysCertificates();
            $logoutResponse->setSignature($this->getSignatureWriter($keys['idpPrivateKey'], $keys['idpCert']));
            
            $messageContext = new \LightSaml\Context\Profile\MessageContext();
            $messageContext->setMessage($logoutResponse);
            
            $binding = new HttpPostBinding();
            $httpResponse = $binding->send($messageContext, $client->getValue('smc_slo_url'));
            print $httpResponse->getContent();
        }
        
    }

    public function sendLogoutRequest(SAMLClient $client, User $user) {
        $sloUrl = $client->getValue('smc_slo_url');
        $login = $user->getValue($client->getValue('smc_userid_field'))??'';

        if (empty($sloUrl) || $user->isNewRecord() || empty($login)) {
            return;
        }
        $logoutRequest = new LogoutRequest();
        $logoutRequest->setIssuer(new \LightSaml\Model\Assertion\Issuer($this->getIdPEntityId()));
        $logoutRequest->setId(\LightSaml\Helper::generateId());
  
        $logoutRequest->setNameID(new NameID($login, SamlConstants::NAME_ID_FORMAT_UNSPECIFIED));
        $logoutRequest->setDestination($sloUrl);
        
        // Sign the response!
        $keys = $this->getKeysCertificates();
        $logoutRequest->setSignature($this->getSignatureWriter($keys['idpPrivateKey'], $keys['idpCert']));

        $messageContext = new \LightSaml\Context\Profile\MessageContext();
        $messageContext->setMessage($logoutRequest);
        
        // $binding = new HttpRedirectBinding();
        $binding = new HttpPostBinding();
        $httpResponse = $binding->send($messageContext, $sloUrl);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $sloUrl);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(['SMALRequest' => $httpResponse->getContent()]));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch); // Send the request and save the response to $response

        curl_close($ch); // Close cURL session

        print $response;
    }
/*
    public function handleAttributeQuery() {
        // TODO: This should work like the Response to an AuthnRequest, but with the requested attributes
        // Unfortunately, the lightsaml library does not provide a way to extract the requested attributes from the AttributeQuery
        // So the code would be quite different, as the request object does not provide nice accessor functions like AuthnRequest!
        
        global $gSettingsManager, $gCurrentUserId, $rootPath;
        if ($gSettingsManager->get('sso_saml_enabled') !== '1') {
            throw new Exception("SSO SAML is not enabled");
        }

        $request = $this->receiveMessage();
        if (!$request instanceof Message) {
            throw new Exception("Invalid request (not an AttributeQuery)");
        }

        if (!$gCurrentUserId) {
            require_once($rootPath . '/adm_program/system/login_valid.php');
        }

        // Load the SAML client data (entityID is in $request->issuer->getValue())
        $clientACS = $request->getAssertionConsumerServiceURL();
        $entityIdClient = $request->getIssuer()->getValue();
        $client = $this->getSPfromID($entityIdClient);

            
        $response = new Response();
        $issuer = new \LightSaml\Model\Assertion\Issuer($this->getIdPEntityId());
        $response->setIssuer($issuer);

        $attributeStatement = new AttributeStatement();

        foreach ($request->getRequestedAttributes() as $requestedAttribute) {
            $attrName = $requestedAttribute->getName();
            $attrFriendlyName = $requestedAttribute->getFriendlyName();

            $att = $this->getUserAttribute($gCurrentUser, $attrName, $attrFriendlyName);
            if ($att->getFirstAttributeValue() !== null) {
                $attributeStatement->addAttribute($att);
            }
        }

        // TODO:....

        
        // $binding = new HttpPostBinding();
        // $binding->send($response, $attributeQuery->getIssuer()->getValue());
        // exit;
    
    }
*/
    private function getUserAttribute($user, $attributeName, $friendlyName = null) {
        global $gL10n, $gProfileFields;

        // recode $attributeName to admidio field names, but use original $attributeName in response
        $mapping = [
            'urn:oid:0.9.2342.19200300.100.1.1' => 'usr_login_name',
            'urn:oid:2.5.4.3' => 'usr_name',
            'urn:oid:2.5.4.10' => 'EMAIL',
            'urn:oid:2.5.4.11' => 'roles',
        ];
        $field = $mapping[$attributeName]??$attributeName;
        
        $att = new Attribute();
        
        if ($field == 'usr_name' || $field == 'fullname') {
            $att->setName($attributeName);
            $att->setAttributeValue($user->readableName());
            $att->setFriendlyName($friendlyName ?: $gL10n->get('SYS_NAME'));

        } elseif ($field == 'roles') {
            $att->setName($attributeName);
            $att->setFriendlyName($friendlyName ?: $gL10n->get('SYS_ROLES'));

            $roles = $user->getRoleMemberships();
            foreach ($roles as $roleId) {
               $role = new Role($this->db, $roleId);
               $roleName = $role->getValue('rol_name');
               $att->addAttributeValue($roleName);
            }            
        } else {
            // User profile fields or user fields
            $att->setName(strtolower($attributeName));
            $att->setAttributeValue($user->getValue($field));
            $friendlyNames = [
                'usr_login_name' => 'SYS_USERNAME',
                'usr_id' =>         'SYS_SSO_USERID_ID',
                'usr_uuid' =>       'SYS_SSO_USERID_UUID'
            ];
            if (array_key_exists($field, $friendlyNames)) {
                $att->setFriendlyName($friendlyName ?: $gL10n->get($friendlyNames[$field]));
            } else {
                $att->setFriendlyName($friendlyName ?: $gProfileFields->getProperty($field, 'usf_name'));
            }
        }
        return $att;
    }
}    
