<?php
/**
 ***********************************************************************************************
 * Constants that will be used within Admidio
 *
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 ***********************************************************************************************
 */
if (basename($_SERVER['SCRIPT_FILENAME']) === 'constants.php') {
    exit('This page may not be called directly!');
}

define('SCRIPT_START_TIME', microtime(true));

// ##################
// ###  VERSIONS  ###
// ##################

// !!! Please do not edit these version numbers !!!
const MIN_PHP_VERSION = '8.2.0';

const ADMIDIO_VERSION_MAIN = 5;
const ADMIDIO_VERSION_MINOR = 0;
const ADMIDIO_VERSION_PATCH = 0;
const ADMIDIO_VERSION_BETA = 1;

const ADMIDIO_VERSION = ADMIDIO_VERSION_MAIN . '.' . ADMIDIO_VERSION_MINOR . '.' . ADMIDIO_VERSION_PATCH;

if (ADMIDIO_VERSION_BETA > 0) {
    define('ADMIDIO_VERSION_TEXT', ADMIDIO_VERSION . ' Beta ' . ADMIDIO_VERSION_BETA);
} else {
    define('ADMIDIO_VERSION_TEXT', ADMIDIO_VERSION);
}

// ######################
// ###  URLS & PATHS  ###
// ######################

// Admidio Homepage
const ADMIDIO_HOMEPAGE = 'https://www.admidio.org/';

// BASIC STUFF
// https://www.php.net/manual/en/reserved.variables.server.php => $_SERVER['HTTPS']
define('SCHEME', parse_url($g_root_path, PHP_URL_SCHEME)); // get SCHEME out of $g_root_path because server doesn't have this info if ssl proxy is used
const HTTPS = SCHEME === 'https'; // true | false
define('PORT', (int) $_SERVER['SERVER_PORT']); // 443 | 80

$port = (PORT === 80 || PORT === 443) ? '' : ':' . PORT; // :1234

if (isset($_SERVER['HTTP_X_FORWARDED_HOST']) && $_SERVER['HTTP_X_FORWARDED_HOST'] !== $_SERVER['HTTP_HOST']) {
    // if ssl proxy is used than this proxy is the host and the cookie must be set for this
    // due to https://github.com/Admidio/admidio/issues/898 changed HTTP_X_FORWARDED_SERVER into HTTP_X_FORWARDED_HOST
    define('HOST', $_SERVER['HTTP_X_FORWARDED_HOST'] . $port . '/' . $_SERVER['HTTP_HOST']); // ssl.example.org/my.domain.net
    define('DOMAIN', strstr($_SERVER['HTTP_X_FORWARDED_HOST'] . $port . ':', ':', true)); // ssl.example.org
} else {
    define('HOST', $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] . $port); // www.example.org:1234
    define('DOMAIN', strstr(HOST . ':', ':', true)); // www.example.org | www.myproxy.com
}
define('ADMIDIO_URL_PATH', is_null(parse_url($g_root_path, PHP_URL_PATH)) ? '' : parse_url($g_root_path, PHP_URL_PATH)); // /subfolder

// PATHS
define('SERVER_PATH', realpath($_SERVER['DOCUMENT_ROOT'])); // /var/www
define('ADMIDIO_PATH', dirname(__DIR__, 2)); // /var/www/subfolder
define('CURRENT_PATH', realpath($_SERVER['SCRIPT_FILENAME'])); // /var/www/subfolder/modules/overview.php

// URLS
define('ADMIDIO_URL', $g_root_path); // https://www.example.org:1234/subfolder | https://www.myproxy.com:1234/www.example.com/subfolder
define('FILE_URL', (strlen(ADMIDIO_URL_PATH) > 0 && strpos($_SERVER['SCRIPT_NAME'], (string) ADMIDIO_URL_PATH) === false) ? SCHEME . '://' . HOST . ADMIDIO_URL_PATH . $_SERVER['SCRIPT_NAME'] : SCHEME . '://' . HOST . $_SERVER['SCRIPT_NAME']); // https://www.example.org:1234/subfolder/index.php
define('CURRENT_URL', (strlen(ADMIDIO_URL_PATH) > 0 && strpos($_SERVER['REQUEST_URI'], (string) ADMIDIO_URL_PATH) === false) ? SCHEME . '://' . HOST . ADMIDIO_URL_PATH . $_SERVER['REQUEST_URI'] : SCHEME . '://' . HOST . $_SERVER['REQUEST_URI']); // https://www.example.org:1234/subfolder/index.php?param=value

// FOLDERS
const FOLDER_DATA = '/adm_my_files';
const FOLDER_TEMP_DATA = '/adm_my_files/temp';
const FOLDER_SYSTEM = '/system';
const FOLDER_INSTALLATION = '/install';
const FOLDER_LIBS = '/libs'; // PHP libs
const FOLDER_LANGUAGES = '/languages';
const FOLDER_THEMES = '/themes';
const FOLDER_MODULES = '/modules';
const FOLDER_PLUGINS = '/adm_plugins';

// ####################
// ###  DATE-STUFF  ###
// ####################

// Define default timezone
date_default_timezone_set($gTimezone);

// date and time for use in scripts
define('DATE_NOW', date('Y-m-d'));
define('DATETIME_NOW', date('Y-m-d H:i:s'));
const DATE_MAX = '9999-12-31';

// ###################
// ###  DB-CONFIG  ###
// ###################

define('DB_ENGINE', $gDbType);
define('DB_HOST', $g_adm_srv);
define('DB_PORT', $g_adm_port);
define('DB_NAME', $g_adm_db);
define('DB_USERNAME', $g_adm_usr);
define('DB_PASSWORD', $g_adm_pw);

// ###################
// ###  DB-TABLES  ###
// ###################

define('TABLE_PREFIX', $g_tbl_praefix);

const TBL_ANNOUNCEMENTS = TABLE_PREFIX . '_announcements';
const TBL_AUTO_LOGIN = TABLE_PREFIX . '_auto_login';
const TBL_CATEGORIES = TABLE_PREFIX . '_categories';
const TBL_CATEGORY_REPORT = TABLE_PREFIX . '_category_report';
const TBL_COMPONENTS = TABLE_PREFIX . '_components';
const TBL_EVENTS = TABLE_PREFIX . '_events';
const TBL_FILES = TABLE_PREFIX . '_files';
const TBL_FOLDERS = TABLE_PREFIX . '_folders';
const TBL_FORUM_TOPICS = TABLE_PREFIX . '_forum_topics';
const TBL_FORUM_POSTS = TABLE_PREFIX . '_forum_posts';
const TBL_GUESTBOOK = TABLE_PREFIX . '_guestbook';
const TBL_GUESTBOOK_COMMENTS = TABLE_PREFIX . '_guestbook_comments';
const TBL_IDS = TABLE_PREFIX . '_ids';
const TBL_LINKS = TABLE_PREFIX . '_links';
const TBL_LIST_COLUMNS = TABLE_PREFIX . '_list_columns';
const TBL_LISTS = TABLE_PREFIX . '_lists';
const TBL_LOG = TABLE_PREFIX . '_log_changes';
const TBL_MEMBERS = TABLE_PREFIX . '_members';
const TBL_MENU = TABLE_PREFIX . '_menu';
const TBL_MESSAGES = TABLE_PREFIX . '_messages';
const TBL_MESSAGES_ATTACHMENTS = TABLE_PREFIX . '_messages_attachments';
const TBL_MESSAGES_CONTENT = TABLE_PREFIX . '_messages_content';
const TBL_MESSAGES_RECIPIENTS = TABLE_PREFIX . '_messages_recipients';
const TBL_OIDC_CLIENTS = TABLE_PREFIX . '_oidc_clients';
const TBL_OIDC_ACCESS_TOKENS = TABLE_PREFIX . '_oidc_access_tokens';
const TBL_OIDC_REFRESH_TOKENS = TABLE_PREFIX . '_oidc_refresh_tokens';
const TBL_OIDC_AUTH_CODES = TABLE_PREFIX . '_oidc_auth_codes';
const TBL_ORGANIZATIONS = TABLE_PREFIX . '_organizations';
const TBL_PHOTOS = TABLE_PREFIX . '_photos';
const TBL_PREFERENCES = TABLE_PREFIX . '_preferences';
const TBL_REGISTRATIONS = TABLE_PREFIX . '_registrations';
const TBL_ROLE_DEPENDENCIES = TABLE_PREFIX . '_role_dependencies';
const TBL_ROLES = TABLE_PREFIX . '_roles';
const TBL_ROLES_RIGHTS = TABLE_PREFIX . '_roles_rights';
const TBL_ROLES_RIGHTS_DATA = TABLE_PREFIX . '_roles_rights_data';
const TBL_ROOMS = TABLE_PREFIX . '_rooms';
const TBL_SAML_CLIENTS = TABLE_PREFIX . '_saml_clients';
const TBL_SSO_KEYS = TABLE_PREFIX . '_sso_keys';
const TBL_SESSIONS = TABLE_PREFIX . '_sessions';
const TBL_TEXTS = TABLE_PREFIX . '_texts';
const TBL_USERS = TABLE_PREFIX . '_users';
const TBL_USER_DATA = TABLE_PREFIX . '_user_data';
const TBL_USER_FIELDS = TABLE_PREFIX . '_user_fields';
const TBL_USER_FIELD_OPTIONS = TABLE_PREFIX . '_user_field_select_options';
const TBL_USER_RELATIONS = TABLE_PREFIX . '_user_relations';
const TBL_USER_RELATION_TYPES = TABLE_PREFIX . '_user_relation_types';
const TBL_INVENTORY_ITEM_DATA = TABLE_PREFIX . '_inventory_item_data';
const TBL_INVENTORY_FIELDS = TABLE_PREFIX . '_inventory_fields';
const TBL_INVENTORY_FIELD_OPTIONS = TABLE_PREFIX . '_inventory_field_select_options';
const TBL_INVENTORY_ITEMS = TABLE_PREFIX . '_inventory_items';
const TBL_INVENTORY_ITEM_LEND_DATA = TABLE_PREFIX . '_inventory_item_lend_data';

// #####################
// ###  OTHER STUFF  ###
// #####################

// create an installation unique cookie prefix and remove special characters
if (isset($g_adm_db)) {
    if (isset($gDebug)) {
        $cookiePrefix = 'ADMIDIO_' . DB_NAME . '_' . TABLE_PREFIX;
    } else {
        $cookiePrefix = 'ADMIDIO_' . substr(md5(DB_NAME), 0,5);
    }
} else {
    $cookiePrefix = 'ADMIDIO_' . TABLE_PREFIX;
}
define('COOKIE_PREFIX', preg_replace('/\W/', '_', $cookiePrefix));

// Password settings
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_GEN_LENGTH = 16;
const PASSWORD_GEN_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

// ####################
// ###  DEPRECATED  ###
// ####################
