<?php
/**
 ***********************************************************************************************
 * Installation step: start_installation
 *
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 ***********************************************************************************************
 */

use Admidio\Components\Entity\ComponentUpdate;
use Admidio\Infrastructure\Exception;
use Admidio\Infrastructure\Utils\PasswordUtils;
use Admidio\Infrastructure\Utils\PhpIniUtils;
use Admidio\Infrastructure\Utils\SecurityUtils;
use Admidio\Organizations\Entity\Organization;
use Admidio\Infrastructure\Entity\Entity;
use Admidio\ProfileFields\ValueObjects\ProfileFields;
use Admidio\Users\Entity\User;
use Ramsey\Uuid\Uuid;

if (basename($_SERVER['SCRIPT_FILENAME']) === 'start_installation.php') {
    exit('This page may not be called directly!');
}

// Check if configuration file exists. This file must be copied to the base folder of the Admidio installation.
if (!is_file($configPath)) {
    throw new Exception('INS_CONFIGURATION_FILE_NOT_FOUND', array('config.php'));
}

// first check if session is filled (if installation was aborted then this is not filled)
// if previous dialogs were filled then check if the settings are equal to config file
if (isset($_SESSION['table_prefix'])
&&    ($_SESSION['db_engine']      !== DB_ENGINE
    || $_SESSION['db_host']        !== DB_HOST
    || $_SESSION['db_port']        !== DB_PORT
    || $_SESSION['db_name']        !== DB_NAME
    || $_SESSION['db_username']    !== DB_USERNAME
    || $_SESSION['db_password']    !== DB_PASSWORD
    || $_SESSION['table_prefix']   !== TABLE_PREFIX)) {
    throw new Exception('INS_DATA_DO_NOT_MATCH', array('config.php'));
}

// set execution time to 5 minutes because we have a lot to do
PhpIniUtils::startNewExecutionTimeLimit(300);

// read data from sql script db.sql and execute all statements to the current database
\Admidio\InstallationUpdate\Service\Installation::querySqlFile($db, 'db.sql');

// create default data

// add system component to database
$component = new ComponentUpdate($db);
$component->setValue('com_type', 'SYSTEM');
$component->setValue('com_name', 'Admidio Core');
$component->setValue('com_name_intern', 'CORE');
$component->setValue('com_version', ADMIDIO_VERSION);
$component->setValue('com_beta', ADMIDIO_VERSION_BETA);
$component->setValue('com_update_step', $component->getMaxUpdateStep());
$component->save();

// create a hidden system user for internal use
// all recordsets created by installation will get the create id of the system user
$gCurrentUser = new Entity($db, TBL_USERS, 'usr');
$gCurrentUser->setValue('usr_login_name', $gL10n->get('SYS_SYSTEM'));
$gCurrentUser->setValue('usr_valid', '0');
$gCurrentUser->setValue('usr_timestamp_create', DATETIME_NOW);
$gCurrentUser->save(false); // no registered user -> UserIdCreate couldn't be filled
$gCurrentUserId = $gCurrentUser->getValue('usr_id');

// create all modules components
$sql = 'INSERT INTO '.TBL_COMPONENTS.'
               (com_type, com_name, com_name_intern, com_version, com_beta)
        VALUES (\'MODULE\', \'SYS_ANNOUNCEMENTS\',   \'ANNOUNCEMENTS\',  \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_CATEGORIES\',      \'CATEGORIES\',     \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_CATEGORY_REPORT\', \'CATEGORY-REPORT\',\''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_EVENTS\',          \'EVENTS\',         \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_DOCUMENTS_FILES\', \'DOCUMENTS-FILES\',\''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_INVENTORY\',        \'INVENTORY\',     \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_FORUM\',           \'FORUM\',          \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_WEBLINKS\',        \'LINKS\',          \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_GROUPS_ROLES\',    \'GROUPS-ROLES\',   \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_CONTACTS\',        \'CONTACTS\',       \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_MESSAGES\',        \'MESSAGES\',       \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_MENU\',            \'MENU\',           \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_ORGANIZATION\',    \'ORGANIZATIONS\',  \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_PHOTOS\',          \'PHOTOS\',         \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_SETTINGS\',        \'PREFERENCES\',    \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_PROFILE\',         \'PROFILE\',        \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_REGISTRATION\',    \'REGISTRATION\',   \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')
             , (\'MODULE\', \'SYS_ROOM_MANAGEMENT\', \'ROOMS\',          \''.ADMIDIO_VERSION.'\', '.ADMIDIO_VERSION_BETA.')';
$db->query($sql); // TODO add more params

// create organization independent categories
$sql = 'INSERT INTO '.TBL_CATEGORIES.'
               (cat_org_id, cat_uuid, cat_type, cat_name_intern, cat_name, cat_default, cat_system, cat_sequence, cat_usr_id_create, cat_timestamp_create)
        VALUES (NULL, \'' . Uuid::uuid4() . '\', \'USF\', \'BASIC_DATA\', \'SYS_BASIC_DATA\', false, true, 1, ?, ?) -- $gCurrentUserId, DATETIME_NOW';
$db->queryPrepared($sql, array($gCurrentUserId, DATETIME_NOW));
$categoryIdMasterData = $db->lastInsertId();

$sql = 'INSERT INTO '.TBL_CATEGORIES.'
               (cat_org_id, cat_uuid, cat_type, cat_name_intern, cat_name, cat_default, cat_system, cat_sequence, cat_usr_id_create, cat_timestamp_create)
        VALUES (NULL, \'' . Uuid::uuid4() . '\', \'USF\', \'SOCIAL_NETWORKS\', \'SYS_SOCIAL_NETWORKS\', false, false, 2, ?, ?) -- $gCurrentUserId, DATETIME_NOW';
$db->queryPrepared($sql, array($gCurrentUserId, DATETIME_NOW));
$categoryIdSocialNetworks = $db->lastInsertId();

$sql = 'INSERT INTO '.TBL_CATEGORIES.'
               (cat_org_id, cat_uuid, cat_type, cat_name_intern, cat_name, cat_default, cat_system, cat_sequence, cat_usr_id_create, cat_timestamp_create)
        VALUES (NULL, \'' . Uuid::uuid4() . '\', \'USF\', \'ADDIDIONAL_DATA\', \'INS_ADDIDIONAL_DATA\', false, false, 3, ?, ?) -- $gCurrentUserId, DATETIME_NOW';
$db->queryPrepared($sql, array($gCurrentUserId, DATETIME_NOW));
$categoryIdAddidionalData = $db->lastInsertId();

// create roles rights
$sql = 'INSERT INTO '.TBL_ROLES_RIGHTS.'
               (ror_name_intern, ror_table)
        VALUES (\'folder_view\',   \'adm_folders\')
             , (\'folder_upload\', \'adm_folders\')
             , (\'category_view\', \'adm_categories\')
             , (\'event_participation\', \'adm_events\')
             , (\'menu_view\',     \'adm_menu\')
             , (\'sso_saml_access\', \'adm_saml_clients\')
             , (\'sso_oidc_access\', \'adm_oidc_clients\')
             ';
$db->queryPrepared($sql);

// add edit categories right with reference to parent right
$sql = 'INSERT INTO '.TBL_ROLES_RIGHTS.'
               (ror_name_intern, ror_table, ror_ror_id_parent)
        VALUES (\'category_edit\', \'adm_categories\', (SELECT rr.ror_id FROM '.TBL_ROLES_RIGHTS.' rr WHERE rr.ror_name_intern = \'category_view\'))';
$db->queryPrepared($sql);

// create profile fields of category basic data
$sql = 'INSERT INTO '.TBL_USER_FIELDS.'
               (usf_cat_id, usf_uuid, usf_type, usf_name_intern, usf_name, usf_description, usf_system, usf_disabled, usf_required_input, usf_registration, usf_sequence, usf_usr_id_create, usf_timestamp_create)
        VALUES ('.$categoryIdMasterData.', \'' . Uuid::uuid4() . '\', \'TEXT\',         \'LAST_NAME\',  \'SYS_LASTNAME\',  NULL, true, true, 1, true, 1,  '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdMasterData.', \'' . Uuid::uuid4() . '\', \'TEXT\',         \'FIRST_NAME\', \'SYS_FIRSTNAME\', NULL, true, true, 1, true, 2,  '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdMasterData.', \'' . Uuid::uuid4() . '\', \'TEXT\',         \'STREET\',     \'SYS_STREET\',    NULL, false, false, 0, false, 3,  '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdMasterData.', \'' . Uuid::uuid4() . '\', \'TEXT\',         \'POSTCODE\',   \'SYS_POSTCODE\',  NULL, false, false, 0, false, 4,  '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdMasterData.', \'' . Uuid::uuid4() . '\', \'TEXT\',         \'CITY\',       \'SYS_CITY\',      NULL, false, false, 0, false, 5,  '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdMasterData.', \'' . Uuid::uuid4() . '\', \'TEXT\',         \'COUNTRY\',    \'SYS_COUNTRY\',   NULL, false, false, 0, false, 6,  '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdMasterData.', \'' . Uuid::uuid4() . '\', \'PHONE\',        \'PHONE\',      \'SYS_PHONE\',     NULL, false, false, 0, false, 7,  '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdMasterData.', \'' . Uuid::uuid4() . '\', \'PHONE\',        \'MOBILE\',     \'SYS_MOBILE\',    NULL, false, false, 0, false, 8,  '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdMasterData.', \'' . Uuid::uuid4() . '\', \'DATE\',         \'BIRTHDAY\',   \'SYS_BIRTHDAY\',  NULL, false, false, 0, false, 10, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdMasterData.', \'' . Uuid::uuid4() . '\', \'RADIO_BUTTON\', \'GENDER\',     \'SYS_GENDER\',    NULL, false, false, 0, false, 11, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdMasterData.', \'' . Uuid::uuid4() . '\', \'EMAIL\',        \'EMAIL\',      \'SYS_EMAIL\',     NULL, true, false, 2, true, 12, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdMasterData.', \'' . Uuid::uuid4() . '\', \'URL\',          \'WEBSITE\',    \'SYS_WEBSITE\',   NULL, false, false, 0, false, 13, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdAddidionalData.', \'' . Uuid::uuid4() . '\', \'CHECKBOX\', \'DATA_PROTECTION_PERMISSION\', \'SYS_DATA_PROTECTION_PERMISSION\', \''.$gL10n->get('SYS_DATA_PROTECTION_PERMISSION_DESC').'\', false, false, 2, false, 14, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')';
$db->query($sql); // TODO add more params

// add gender options to database
$sql = 'INSERT INTO '.TBL_USER_FIELD_OPTIONS.'
               (uso_usf_id, uso_value, uso_sequence)
        VALUES ((SELECT usf_id FROM '.TBL_USER_FIELDS.' WHERE usf_cat_id = '.$categoryIdMasterData.' AND usf_name_intern = \'GENDER\'), \'gender-male|SYS_MALE\', 1)
             , ((SELECT usf_id FROM '.TBL_USER_FIELDS.' WHERE usf_cat_id = '.$categoryIdMasterData.' AND usf_name_intern = \'GENDER\'), \'gender-female|SYS_FEMALE\', 2)
             , ((SELECT usf_id FROM '.TBL_USER_FIELDS.' WHERE usf_cat_id = '.$categoryIdMasterData.' AND usf_name_intern = \'GENDER\'), \'gender-trans|SYS_DIVERSE\', 3)';
$db->query($sql);

// create profile fields of category social networks
$sql = 'INSERT INTO '.TBL_USER_FIELDS.'
               (usf_cat_id, usf_uuid, usf_type, usf_name_intern, usf_name, usf_description, usf_icon, usf_url, usf_system, usf_sequence, usf_usr_id_create, usf_timestamp_create)
        VALUES ('.$categoryIdSocialNetworks.', \'' . Uuid::uuid4() . '\', \'TEXT\', \'FACEBOOK\',              \'SYS_FACEBOOK\',    \''.$gL10n->get('SYS_SOCIAL_NETWORK_FIELD_URL_DESC').'\', \'facebook\',  \'https://www.facebook.com/#user_content#\',     false, 1, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdSocialNetworks.', \'' . Uuid::uuid4() . '\', \'TEXT\', \'INSTAGRAM\',             \'SYS_INSTAGRAM\',   \''.$gL10n->get('SYS_SOCIAL_NETWORK_FIELD_URL_DESC').'\', \'instagram\', \'https://www.instagram.com/#user_content#\',    false, 2, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdSocialNetworks.', \'' . Uuid::uuid4() . '\', \'TEXT\', \'LINKEDIN\',              \'SYS_LINKEDIN\',    \''.$gL10n->get('SYS_SOCIAL_NETWORK_FIELD_URL_DESC').'\', \'linkedin\',  \'https://www.linkedin.com/in/#user_content#\',  false, 3, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdSocialNetworks.', \'' . Uuid::uuid4() . '\', \'TEXT\', \'MASTODON\',              \'SYS_MASTODON\',    \''.$gL10n->get('SYS_SOCIAL_NETWORK_FIELD_URL_DESC').'\', \'mastodon\',  \'https://mastodon.social/#user_content#\',      false, 4, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , ('.$categoryIdSocialNetworks.', \'' . Uuid::uuid4() . '\', \'TEXT\', \'XING\',                  \'SYS_XING\',        \''.$gL10n->get('SYS_SOCIAL_NETWORK_FIELD_URL_DESC').'\', null,          \'https://www.xing.com/profile/#user_content#\', false, 7, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')';
$db->query($sql); // TODO add more params

// create user relation types
$sql = 'INSERT INTO '.TBL_USER_RELATION_TYPES.'
               (urt_id, urt_uuid, urt_name, urt_name_male, urt_name_female, urt_id_inverse, urt_usr_id_create, urt_timestamp_create)
        VALUES (1, \'' . Uuid::uuid4() . '\', \''.$gL10n->get('INS_PARENT').'\',      \''.$gL10n->get('INS_FATHER').'\',           \''.$gL10n->get('INS_MOTHER').'\',          null, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , (2, \'' . Uuid::uuid4() . '\', \''.$gL10n->get('INS_CHILD').'\',       \''.$gL10n->get('INS_SON').'\',              \''.$gL10n->get('INS_DAUGHTER').'\',           1, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , (3, \'' . Uuid::uuid4() . '\', \''.$gL10n->get('INS_SIBLING').'\',     \''.$gL10n->get('INS_BROTHER').'\',          \''.$gL10n->get('INS_SISTER').'\',             3, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , (4, \'' . Uuid::uuid4() . '\', \''.$gL10n->get('INS_SPOUSE').'\',      \''.$gL10n->get('INS_HUSBAND').'\',          \''.$gL10n->get('INS_WIFE').'\',               4, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , (5, \'' . Uuid::uuid4() . '\', \''.$gL10n->get('INS_COHABITANT').'\',  \''.$gL10n->get('INS_COHABITANT_MALE').'\',  \''.$gL10n->get('INS_COHABITANT_FEMALE').'\',  5, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , (6, \'' . Uuid::uuid4() . '\', \''.$gL10n->get('SYS_COMPANION').'\',   \''.$gL10n->get('SYS_BOYFRIEND').'\',        \''.$gL10n->get('SYS_GIRLFRIEND').'\',         6, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , (7, \'' . Uuid::uuid4() . '\', \''.$gL10n->get('SYS_SUPERIOR').'\',    \''.$gL10n->get('SYS_SUPERIOR_MALE').'\',    \''.$gL10n->get('SYS_SUPERIOR_FEMALE').'\', null, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')
             , (8, \'' . Uuid::uuid4() . '\', \''.$gL10n->get('INS_SUBORDINATE').'\', \''.$gL10n->get('INS_SUBORDINATE_MALE').'\', \''.$gL10n->get('INS_SUBORDINATE_FEMALE').'\', 7, '.$gCurrentUserId.', \''. DATETIME_NOW.'\')';
$db->query($sql); // TODO add more params

$sql = 'UPDATE '.TBL_USER_RELATION_TYPES.'
           SET urt_id_inverse = 2
         WHERE urt_id = 1';
$db->queryPrepared($sql);

$sql = 'UPDATE '.TBL_USER_RELATION_TYPES.'
           SET urt_id_inverse = 8
         WHERE urt_id = 7';
$db->queryPrepared($sql);

\Admidio\InstallationUpdate\Service\Installation::disableSoundexSearchIfPgSql($db);

// create new organization
$gCurrentOrganization = new Organization($db, $_SESSION['orga_shortname']);
$gCurrentOrganization->setValue('org_longname', $_SESSION['orga_longname']);
$gCurrentOrganization->setValue('org_shortname', $_SESSION['orga_shortname']);
$gCurrentOrganization->setValue('org_homepage', ADMIDIO_URL);
$gCurrentOrganization->setValue('org_email_administrator', $_SESSION['orga_email']);
$gCurrentOrganization->save();
$gCurrentOrgId = $gCurrentOrganization->getValue('org_id');

$gProfileFields = new ProfileFields($db, $gCurrentOrgId);

// create administrator and assign roles
$administrator = new User($db, $gProfileFields);
$administrator->setValue('usr_login_name', $_SESSION['user_login']);
$administrator->setPassword($_SESSION['user_password']);
$administrator->setValue('usr_usr_id_create', $gCurrentUserId);
$administrator->setValue('usr_timestamp_create', DATETIME_NOW);
$administrator->save(false); // no registered user -> UserIdCreate couldn't be filled
$adminUsrId = $administrator->getValue('usr_id');

// write all preferences from preferences.php in table adm_preferences
require_once(ADMIDIO_PATH . FOLDER_INSTALLATION. '/db_scripts/preferences.php');

// set some specific preferences whose values came from user input of the installation wizard
$defaultOrgPreferences['system_language'] = $language;

// calculate the best cost value for your server performance
$benchmarkResults = PasswordUtils::costBenchmark($gPasswordHashAlgorithm);
if (is_int($benchmarkResults['options']['cost'])) {
    $defaultOrgPreferences['system_hashing_cost'] = $benchmarkResults['options']['cost'];
}

// create all necessary data for this organization
$gSettingsManager =& $gCurrentOrganization->getSettingsManager();
$gSettingsManager->setMulti($defaultOrgPreferences, false);
$gCurrentOrganization->createBasicData($adminUsrId);

// create default room for room module in database
$sql = 'INSERT INTO '.TBL_ROOMS.'
               (room_uuid, room_name, room_description, room_capacity, room_usr_id_create, room_timestamp_create)
        VALUES (\'' . Uuid::uuid4() . '\', ?, ?, 15, ?, ?) -- $gL10n->get(\'INS_CONFERENCE_ROOM\'), $gL10n->get(\'INS_DESCRIPTION_CONFERENCE_ROOM\'), $gCurrentUserId, DATETIME_NOW';
$params = array(
    $gL10n->get('INS_CONFERENCE_ROOM'),
    $gL10n->get('INS_DESCRIPTION_CONFERENCE_ROOM'),
    $gCurrentUserId,
    DATETIME_NOW
);
$db->queryPrepared($sql, $params);

// first create a user object "current user" with administrator rights
// because administrator is allowed to edit firstname and lastname
$gCurrentUser = new User($db, $gProfileFields, $adminUsrId);
$gCurrentUser->saveChangesWithoutRights();
$gCurrentUser->setValue('LAST_NAME', $_SESSION['user_last_name']);
$gCurrentUser->setValue('FIRST_NAME', $_SESSION['user_first_name']);
$gCurrentUser->setValue('EMAIL', $_SESSION['user_email']);
$gCurrentUser->save(false);

// now create a full user object for system user
$systemUser = new User($db, $gProfileFields, $gCurrentUserId);
$systemUser->saveChangesWithoutRights();
$systemUser->setValue('LAST_NAME', $gL10n->get('SYS_SYSTEM'));
$systemUser->save(false); // no registered user -> UserIdCreate couldn't be filled

// now set current user to system user
$gCurrentUser->readDataById($gCurrentUserId);

// Menu entries for the standard installation
$sql = 'INSERT INTO '.TBL_MENU.'
               (men_com_id, men_men_id_parent, men_uuid, men_node, men_order, men_standard, men_name_intern, men_url, men_icon, men_name, men_description)
        VALUES (NULL, NULL, \'' . Uuid::uuid4() . '\', true, 1, true, \'modules\', NULL, \'\', \'SYS_MODULES\', \'\')
             , (NULL, NULL, \'' . Uuid::uuid4() . '\', true, 2, true, \'administration\', NULL, \'\', \'SYS_ADMINISTRATION\', \'\')
             , (NULL, NULL, \'' . Uuid::uuid4() . '\', true, 3, true, \'extensions\', NULL, \'\', \'SYS_EXTENSIONS\', \'\')
             , (NULL, 1, \'' . Uuid::uuid4() . '\', false, 1, true, \'overview\', \''.FOLDER_MODULES.'/overview.php\', \'bi-house-door-fill\', \'SYS_OVERVIEW\', \'\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'ANNOUNCEMENTS\'), 1, \'' . Uuid::uuid4() . '\', false, 2, true, \'announcements\', \''.FOLDER_MODULES.'/announcements.php\', \'newspaper\', \'SYS_ANNOUNCEMENTS\', \'SYS_ANNOUNCEMENTS_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'EVENTS\'), 1, \'' . Uuid::uuid4() . '\', false, 3, true, \'events\', \''.FOLDER_MODULES.'/events/events.php\', \'calendar-week-fill\', \'SYS_EVENTS\', \'SYS_EVENTS_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'MESSAGES\'), 1, \'' . Uuid::uuid4() . '\', false, 4, true, \'messages\', \''.FOLDER_MODULES.'/messages/messages.php\', \'envelope-fill\', \'SYS_MESSAGES\', \'SYS_MESSAGES_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'GROUPS-ROLES\'), 1, \'' . Uuid::uuid4() . '\', false, 5, true, \'groups-roles\', \''.FOLDER_MODULES.'/groups-roles/groups_roles.php\', \'people-fill\', \'SYS_GROUPS_ROLES\', \'SYS_GROUPS_ROLES_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'CONTACTS\'), 1, \'' . Uuid::uuid4() . '\', false, 6, true, \'contacts\', \''.FOLDER_MODULES.'/contacts/contacts.php\', \'person-vcard-fill\', \'SYS_CONTACTS\', \'SYS_CONTACTS_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'DOCUMENTS-FILES\'), 1, \'' . Uuid::uuid4() . '\', false, 7, true, \'documents-files\', \''.FOLDER_MODULES.'/documents-files.php\', \'file-earmark-arrow-down-fill\', \'SYS_DOCUMENTS_FILES\', \'SYS_DOCUMENTS_FILES_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'INVENTORY\'), 1, \'' . Uuid::uuid4() . '\', false, 8, true, \'inventory\', \''.FOLDER_MODULES.'/inventory.php\', \'box-seam-fill\', \'SYS_INVENTORY\', \'SYS_INVENTORY_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'PHOTOS\'), 1, \'' . Uuid::uuid4() . '\', false, 9, true, \'photo\', \''.FOLDER_MODULES.'/photos/photos.php\', \'image-fill\', \'SYS_PHOTOS\', \'SYS_PHOTOS_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'CATEGORY-REPORT\'), 1, \'' . Uuid::uuid4() . '\', false, 10, true, \'category-report\', \''.FOLDER_MODULES.'/category-report/category_report.php\', \'list-stars\', \'SYS_CATEGORY_REPORT\', \'SYS_CATEGORY_REPORT_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'LINKS\'), 1, \'' . Uuid::uuid4() . '\', false, 11, true, \'weblinks\', \''.FOLDER_MODULES.'/links/links.php\', \'link-45deg\', \'SYS_WEBLINKS\', \'SYS_WEBLINKS_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'FORUM\'), 1, \'' . Uuid::uuid4() . '\', false, 12, true, \'forum\', \''.FOLDER_MODULES.'/forum.php\', \'chat-dots-fill\', \'SYS_FORUM\', \'SYS_FORUM_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'PREFERENCES\'), 2, \'' . Uuid::uuid4() . '\', false, 1, true, \'orgprop\', \''.FOLDER_MODULES.'/preferences.php\', \'gear-fill\', \'SYS_SETTINGS\', \'ORG_ORGANIZATION_PROPERTIES_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'REGISTRATION\'), 2, \'' . Uuid::uuid4() . '\', false, 2, true, \'registration\', \''.FOLDER_MODULES.'/registration.php\', \'card-checklist\', \'SYS_REGISTRATIONS\', \'SYS_MANAGE_NEW_REGISTRATIONS_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'MENU\'), 2, \'' . Uuid::uuid4() . '\', false, 3, true, \'menu\', \''.FOLDER_MODULES.'/menu.php\', \'menu-button-wide-fill\', \'SYS_MENU\', \'SYS_MENU_DESC\')
             , ((SELECT com_id FROM '.TBL_COMPONENTS.' WHERE com_name_intern = \'ORGANIZATIONS\'), 2, \'' . Uuid::uuid4() . '\', false, 4, true, \'organization\', \''.FOLDER_MODULES.'/organizations.php\', \'diagram-3-fill\', \'SYS_ORGANIZATION\', \'SYS_ORGANIZATION_DESC\')';
$db->query($sql);

// delete session data
session_unset();
session_destroy();

$gLogger->info('INSTALLATION: Installation successfully complete');

echo json_encode(array(
    'status' => 'success',
    'url' => SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_INSTALLATION . '/installation.php', array('step' => 'installation_successful'))));
exit();
