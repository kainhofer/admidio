<?php
namespace Admidio\SSO\Service;

use Admidio\Preferences\Entity\Preferences;
use LightSaml\Builder\Profile\Metadata\MetadataProfileBuilder;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
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
use LightSaml\Model\Metadata\KeyDescriptor;
use LightSaml\Model\Metadata\IdpSsoDescriptor;
use LightSaml\Model\Metadata\SingleSignOnService;
use LightSaml\Model\Metadata\SingleLogoutService;
use LightSaml\Model\Context\SerializationContext;
use LightSaml\Model\XmlDSig\SignatureWriter;
use Admidio\SSO\Repository\ServiceProviderRepository;

use Admidio\Infrastructure\Database;
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

        // Collect all user field into one comma-separated string
        $formValues['smc_user_fields'] = implode(',', $formValues['sso_saml_fields']);

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

    public function handleSSORequest() {
        global $gCurrentUser, $gCurrentUserId, $rootPath, $gSettingsManager, $gL10n, $gProfileFields;

        $request = $this->receiveMessage();
        if (!$request instanceof AuthnRequest) {
            throw new Exception("Invalid request (not an AuthnRequest)");
        }

        if (!$gCurrentUserId) {
            require_once($rootPath . '/adm_program/system/login_valid.php');
        }

        $entityIdClient = $request->getIssuer()->getValue();
        $requestId = $request->getID(); // Extract from incoming AuthnRequest
        $clientACS = $request->getAssertionConsumerServiceURL();
        $issuer = new \LightSaml\Model\Assertion\Issuer($this->getIdPEntityId());

        // Load the SAML client data (entityID is in $request->issuer->getValue())
        $client = new SAMLClient($this->db);
        $client->readDataByEntityId($entityIdClient);
        if ($client->isNewRecord()) {
            throw new Exception("SAML 2.0 client '$entityIdClient' not found in database. Please check the SAML 2.0 client settings and configure the client in Admidio.");
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
//        $assertion->setNamespace(SamlConstants::NS_ASSERTION); // ✅ Explicitly set namespace

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
                ->setAuthnInstant(new \DateTime('-10 MINUTE'))
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
        foreach ($fields as $field) {

            // Roles are handled explicitly after the loop!
            if ($field == 'roles') {
                continue;
            }

            $value = $this->currentUser->getValue($field);
            
            $friendlyName = '';
            if (!empty($value)) {
                if (strncmp($field, 'usr_', 4) === 0) {
                    switch ($field) {
                        case 'usr_login_name':
                            $friendlyName = $gL10n->get('SYS_USERNAME'); break;
                        case 'usr_id':
                            $friendlyName = $gL10n->get('SYS_SSO_USERID_ID'); break;
                        case 'usr_uuid':
                            $friendlyName = $gL10n->get('SYS_SSO_USERID_UUID'); break;
                    }
                } else {
                    $friendlyName = $gProfileFields->getProperty($field, 'usf_name'); 
                }

                $attributeStatement->addAttribute(
                    (new Attribute(strtolower($field), $value))
                        ->setFriendlyName($friendlyName)
                );
            }
        }

        // TODO: Flag whether roles should be sent as one comma-separated string or as individual role tags in the attribute!
        if (in_array('roles', $fields)) {
            $attr = new Attribute('roles');
            $attr->setFriendlyName($gL10n->get('SYS_ROLES'));

            $roles = $this->currentUser->getRoleMemberships();
            foreach ($roles as $roleId) {
               $role = new Role($this->db, $roleId);
               $roleName = $role->getValue('rol_name');
               $attr->addAttributeValue($roleName);
            
            }
            $attributeStatement->addAttribute($attr);
        }
        $assertion->addItem($attributeStatement);


        // $response->addAssertion($assertion);

        // TODO: Sign the assertion and the whole response!
        $keys = $this->getKeysCertificates();
        $assertion->setSignature($this->getSignatureWriter($keys['idpPrivateKey'], $keys['idpCert']));
        $response->setSignature($this->getSignatureWriter($keys['idpPrivateKey'], $keys['idpCert']));

        $messageContext = new \LightSaml\Context\Profile\MessageContext();
        $messageContext->setMessage($response);
        
        $binding = new HttpPostBinding();
        $httpResponse = $binding->send($messageContext);
        print $httpResponse->getContent();
        
        // return $binding->send($response);
    }


    public function handleSLORequest(LogoutRequest $request) {
        session_destroy();
        return json_encode(["SLO" => true]);
    }
}
