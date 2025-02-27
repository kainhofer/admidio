<?php

use Admidio\Events\Entity\Event;
use Admidio\Infrastructure\Database;
use Admidio\Infrastructure\Plugins\Overview;
use Admidio\Infrastructure\Utils\SecurityUtils;

use Admidio\SSO\Service\OIDCService;
use Admidio\SSO\Service\SAMLService;

/**
 ***********************************************************************************************
 * Event list
 *
 * Plugin that lists the latest events in a slim interface and
 * can thus be ideally used in an overview page.
 *
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 ***********************************************************************************************
 */
try {
    $rootPath = dirname(__DIR__, 2);
    $pluginFolder = basename(__DIR__);

    require_once($rootPath . '/adm_program/system/common.php');
    require_once($rootPath . '/adm_program/system/login_valid.php');

    // only include config file if it exists
    if (is_file(__DIR__ . '/config.php')) {
        require_once(__DIR__ . '/config.php');
    }

    $requestUri = $_SERVER['REQUEST_URI'];
    $method = $_SERVER['REQUEST_METHOD'];

    $type = 'oidc';

    if ($gSettingsManager->getInt('sso_pretty_urls')) {
        if (strpos($requestUri, '/saml/') !== false) {
            $type = 'saml';
        } else {
            $type = 'oidc';
        }
    } else {
        $type = admFuncVariableIsValid(($method == 'GET')?$_GET:$_POST, 'type', 'string')??'oidc';
    }

    if ($type === 'oidc') {
        $oidcService = new OIDCService($gDb, $gCurrentUser);

        if ($gSettingsManager->getInt('sso_pretty_urls')) {
            if (strpos($requestUri, '/authorize') !== false && $method === 'GET') {
                $oidcService->handleAuthorizationRequest();
            } elseif (strpos($requestUri, '/token') !== false && $method === 'POST') {
                $oidcService->handleTokenRequest();
            } elseif (strpos($requestUri, '/userinfo') !== false && $method === 'GET') {
                $oidcService->handleUserInfoRequest();
            } elseif (strpos($requestUri, '/.well-known/jwks.json') !== false && $method === 'GET') {
                $oidcService->handleJWKSRequest();
            } elseif (strpos($requestUri, '/.well-known/openid-configuration') !== false && $method === 'GET') {
                $oidcService->handleDiscoveryRequest();
            } elseif (strpos($requestUri, '/introspect') !== false && $method === 'POST') {
                $oidcService->handleIntrospectionRequest();
            } elseif (strpos($requestUri, '/revoke') !== false && $method === 'POST') {
                $oidcService->handleRevocationRequest();
            } elseif (strpos($requestUri, '/logout') !== false && $method === 'GET') {
                $oidcService->handleLogoutRequest();
            } else {
                header('HTTP/1.1 404 Not Found');
                echo json_encode(['error' => 'Endpoint not found']);
            }
        } else {
            $action = admFuncVariableIsValid(($method == 'GET')?$_GET:$_POST, 'action', 'string')??'userinfo';
            if ($action == 'authorize' && $method === 'GET') {
                $oidcService->handleAuthorizationRequest();
            } elseif ($action == 'token' && $method === 'POST') {
                $oidcService->handleTokenRequest();
            } elseif ($action == 'userinfo' && $method === 'GET') {
                $oidcService->handleUserInfoRequest();
            } elseif ($action == 'jwks' && $method === 'GET') {
                $oidcService->handleJWKSRequest();
            } elseif ($action = 'openid-configuration' && $method === 'GET') {
                $oidcService->handleDiscoveryRequest();
            } elseif ($action = 'introspect' && $method === 'POST') {
                $oidcService->handleIntrospectionRequest();
            } elseif ($action = 'revoke' && $method === 'POST') {
                $oidcService->handleRevocationRequest();
            } elseif ($action = 'logout' && $method === 'GET') {
                $oidcService->handleLogoutRequest();
            } else {
                header('HTTP/1.1 404 Not Found');
                echo json_encode(['error' => 'Endpoint not found']);
            }
        }
     
    } elseif ($type === 'saml') {

        $samlService = new SAMLService($gDb, $gCurrentUser);

        if ($gSettingsManager->getInt('sso_pretty_urls')) {
            if (strpos($requestUri, '/saml/metadata') !== false && $method === 'GET') {
                $samlService->handleMetadataRequest();
            } elseif (strpos($requestUri, '/saml/sso') !== false && $method === 'POST') {
                $samlService->handleSSORequest();
            } elseif (strpos($requestUri, '/saml/slo') !== false && $method === 'POST') {
                $samlService->handleSLORequest();
            } else {
                header('HTTP/1.1 404 Not Found');
                echo json_encode(['error' => 'Endpoint not found']);
            }
        } else {
            $action = admFuncVariableIsValid(($method == 'GET')?$_GET:$_POST, 'action', 'string');
            if ($action == 'metadata' && $method === 'GET') {
                $samlService->handleMetadataRequest();
            } elseif ($action == 'sso' && $method === 'POST') {
                $samlService->handleSSORequest();
            } elseif ($action == 'slo' && $method === 'POST') {
                $samlService->handleSLORequest();
            } else {
                header('HTTP/1.1 404 Not Found');
                echo json_encode(['error' => 'Endpoint not found']);
            }
        }
        
    
        
    } else {
        header('HTTP/1.1 404 Not Found');
        echo json_encode(['error' => 'URL or authorization protocol not available']);
    }





} catch (Throwable $e) {
    echo $e->getMessage();
}

exit;
