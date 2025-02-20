<?php
/**
 ***********************************************************************************************
 * Show history of generic database record changes
 *
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 *
 * Parameters:
 *
 * table            : The type of changes to be listed (name of the DB table, excluding the prefix)
 * id...............: If set only show the change history of that database record
 * uuid             : If set only show the change history of that database record
 * related_id       : If set only show the change history of objects related to that id (e.g. membership of a role/group)
 * filter_date_from : is set to actual date,
 *                    if no date information is delivered
 * filter_date_to   : is set to 31.12.9999,
 *                    if no date information is delivered
 ***********************************************************************************************
 */

use Admidio\Infrastructure\Exception;
use Admidio\Infrastructure\Language;
use Admidio\UI\Presenter\FormPresenter;
use Admidio\UI\Presenter\PagePresenter;
use Admidio\Users\Entity\User;
use Admidio\Changelog\Service\ChangelogService;
use Admidio\Roles\Entity\Role;





try {
    require_once(__DIR__ . '/../system/common.php');
    require(__DIR__ . '/../system/login_valid.php');

    // calculate default date from which the profile fields history should be shown
    $filterDateFrom = DateTime::createFromFormat('Y-m-d', DATE_NOW);
    $filterDateFrom->modify('-' . $gSettingsManager->getInt('contacts_field_history_days') . ' day');


    // Initialize and check the parameters
    $getTable = admFuncVariableIsValid($_GET, 'table','string');
    $getTables = ($getTable !== null && $getTable != "") ? array_map('trim', explode(",", $getTable)) : [];
    $getUuid = admFuncVariableIsValid($_GET, 'uuid', 'string');
    $getId = admFuncVariableIsValid($_GET, 'id', 'int');
    $getRelatedId = admFuncVariableIsValid($_GET, 'related_id', 'string');
    $getDateFrom = admFuncVariableIsValid($_GET, 'filter_date_from', 'date', array('defaultValue' => $filterDateFrom->format($gSettingsManager->getString('system_date'))));
    $getDateTo   = admFuncVariableIsValid($_GET, 'filter_date_to', 'date', array('defaultValue' => DATE_NOW));
    
    $haveID = !empty($getId) || !empty($getUuid);

    // named array of permission flag (true/false/"user-specific" per table)
    $tablesPermitted = ChangelogService::getPermittedTables($gCurrentUser);
    if ($gSettingsManager->getInt('changelog_module_enabled') == 0) {
        throw new Exception('SYS_MODULE_DISABLED');
    }
    if ($gSettingsManager->getInt('changelog_module_enabled') == 2 && !$gCurrentUser->isAdministrator()) {
        throw new Exception('SYS_NO_RIGHTS');
    }
    $accessAll = $gCurrentUser->isAdministrator() || 
        (!empty($getTables) && empty(array_diff($getTables, $tablesPermitted)));
        
    // create a user object. Will fill it later if we encounter a user id
    $user = new User($gDb, $gProfileFields);
    $userUUID = null;
    // User log contains at most four tables: User, user_data, user_relations and members -> they have many more permissions than other tables!
    $isUserLog = (!empty($getTables) && empty(array_diff($getTables, ['users', 'user_data', 'user_relations', 'members'])));
    if ($isUserLog) {
        if (!empty($getUuid)) {
            $user->readDataByUuid($getUuid);
        } elseif (!empty($getId)) {
            $user->readDataById($getId);
        }
        if (!$user->isNewRecord()) {
            $userUUID = $user->getValue('usr_uuid');
        }
    }

    // Access permissions:
    // Special case: Access to profile history on a per-user basis: Either admin or at least edit user rights are required, or explicit access to the desired user: 
    if (!$accessAll &&
            !(!empty($getTables) && empty(array_diff($getTables, $tablesPermitted))) &&
            $isUserLog) {
        // If a user UUID is given, we need access to that particular user
        // if no UUID is given, editUsers permissions are required
        if (($userUuid === '' && !$gCurrentUser->editUsers())
            || ($userUuid !== '' && !$gCurrentUser->hasRightEditProfile($user))) {
//                throw new Exception('SYS_NO_RIGHTS');
                $gMessage->show($gL10n->get('SYS_NO_RIGHTS'));
       }
    }



    // Page Headline: Depending on the tables and ID/UUID/RelatedIDs, we have different cases:
    //  * Userlog (tables users,user_data,members): Either "Change history of NAME" or "Change history of user data and memberships" (if no ID/UUID)
    //  * No object ID/UUIDs given: "Change history: Table description 1[, Table description 2, ...]" or "Change history"  (if no tables given)
    //  * Only one table (table column will be hidden): "Change history: OBJECTNAME (Table description)"
    //  * 
    $tableTitles = array_map([ChangelogService::class, 'getTableLabel'], $getTables);
    // set headline of the script
    if ($isUserLog && $haveID) {
        $headline = $gL10n->get('SYS_CHANGE_HISTORY_OF', array($user->readableName()));
    } elseif ($isUserLog) {
        $headline = $gL10n->get('SYS_CHANGE_HISTORY_USERDATA');
    } elseif (empty($getUuid) && empty($getId) && empty($getRelatedId)) {
        if (count($tableTitles) > 0) {
            $headline = $gL10n->get('SYS_CHANGE_HISTORY_GENERIC', [implode(', ', $tableTitles)]);
        } else {
            $headline = $gL10n->get('SYS_CHANGE_HISTORY');
        }
    } else {
        $objName = '';
        $useTable = $getTables[0]??'users';
        $object = ChangelogService::getObjectForTable($useTable);
        if ($useTable == 'members') {
            // Memberships are special-cased, as the membership Role UUID is stored as relatedID
            $object = new Role($gDb);
            $object->readDataByUuid($getRelatedId);
        }
        // We have an ID or UUID and/or a relatedID -> Object depends on the table(s)!
        if (!empty($object)) {
            if ($useTable == 'members') {
                // already handled
            } elseif (!empty($getUuid)) {
                $object->readDataByUuid($getUuid);
            } elseif (!empty($getId)) {
                $object->readDataById($getId);
            }
            $objName = $object->readableName();
        }
        if (count($getTables) == 0) {
            if (empty($objName)) {
                $headline = $gL10n->get('SYS_CHANGE_HISTORY');
            } else {
                $headline = $gL10n->get('SYS_CHANGE_HISTORY_OF', [$objName]);
            }
        } else {
            $headline = $gL10n->get('SYS_CHANGE_HISTORY_GENERIC2', [$objName, implode(', ', $tableTitles)]);
        }
    }

    // add page to navigation history
    $gNavigation->addUrl(CURRENT_URL, $headline);

    // add page to navigation history
    $gNavigation->addUrl(CURRENT_URL, $headline);

    // filter_date_from and filter_date_to can have different formats
    // now we try to get a default format for intern use and html output
    $objDateFrom = DateTime::createFromFormat('Y-m-d', $getDateFrom);
    if ($objDateFrom === false) {
        // check if date has system format
        $objDateFrom = DateTime::createFromFormat($gSettingsManager->getString('system_date'), $getDateFrom);
        if ($objDateFrom === false) {
            $objDateFrom = DateTime::createFromFormat($gSettingsManager->getString('system_date'), '1970-01-01');
        }
    }

    $objDateTo = DateTime::createFromFormat('Y-m-d', $getDateTo);
    if ($objDateTo === false) {
        // check if date has system format
        $objDateTo = DateTime::createFromFormat($gSettingsManager->getString('system_date'), $getDateTo);
        if ($objDateTo === false) {
            $objDateTo = DateTime::createFromFormat($gSettingsManager->getString('system_date'), '1970-01-01');
        }
    }

    // DateTo should be greater than DateFrom
    if ($objDateFrom > $objDateTo) {
        throw new Exception('SYS_DATE_END_BEFORE_BEGIN');
    }

    $dateFromIntern = $objDateFrom->format('Y-m-d');
    $dateFromHtml = $objDateFrom->format($gSettingsManager->getString('system_date'));
    $dateToIntern = $objDateTo->format('Y-m-d');
    $dateToHtml = $objDateTo->format($gSettingsManager->getString('system_date'));


    // create sql conditions
    $sqlConditions = '';
    $queryParamsConditions = array();

    if (!is_null($getTables) && count($getTables) > 0) {
        // Add each table as a separate condition, joined by OR:
        $sqlConditions .= ' AND ( ' .  implode(' OR ', array_map(fn($tbl) => 'log_table = ?', $getTables)) . ' ) ';
        $queryParamsConditions = array_merge($queryParamsConditions, $getTables);
    }

    if (!is_null($getId) && $getId > 0) {
        $sqlConditions .= ' AND (log_record_id = ? )';
        $queryParamsConditions[] = $getId;
    }
    if (!is_null($getUuid) && $getUuid) {
        $sqlConditions .= ' AND (log_record_uuid = ? )';
        $queryParamsConditions[] = $getUuid;
    }
    if (!is_null($getRelatedId) && $getRelatedId > 0) {
        $sqlConditions .= ' AND (log_related_id = ? )';
        $queryParamsConditions[] = $getRelatedId;
    }



    $sql = 'SELECT log_id as id, log_table as table_name, 
        log_record_id as record_id, log_record_uuid as uuid, log_record_name as name, log_record_linkid as link_id,
        log_related_id as related_id, log_related_name as related_name,
        log_field as field, log_field_name as field_name, 
        log_action as action,
        log_value_new as value_new, log_value_old as value_old, 
        log_usr_id_create as usr_id_create, usr_create.usr_uuid as uuid_usr_create, create_last_name.usd_value AS create_last_name, create_first_name.usd_value AS create_first_name, 
        log_timestamp_create as timestamp
        FROM ' . TBL_LOG . ' 
        -- Extract data of the creating user...
        INNER JOIN '.TBL_USERS.' usr_create 
                ON usr_create.usr_id = log_usr_id_create
        INNER JOIN '.TBL_USER_DATA.' AS create_last_name
                ON create_last_name.usd_usr_id = log_usr_id_create
               AND create_last_name.usd_usf_id = ? -- $gProfileFields->getProperty(\'LAST_NAME\', \'usf_id\')
        INNER JOIN '.TBL_USER_DATA.' AS create_first_name
                ON create_first_name.usd_usr_id = log_usr_id_create
               AND create_first_name.usd_usf_id = ? -- $gProfileFields->getProperty(\'FIRST_NAME\', \'usf_id\')
        WHERE
               log_timestamp_create BETWEEN ? AND ? -- $dateFromIntern and $dateToIntern
        ' . $sqlConditions . '
        ORDER BY log_id DESC';

    $queryParams = [
        $gProfileFields->getProperty('LAST_NAME', 'usf_id'),
        $gProfileFields->getProperty('FIRST_NAME', 'usf_id'),
        $dateFromIntern . ' 00:00:00',
        $dateToIntern . ' 23:59:59',
    ];




    $fieldHistoryStatement = $gDb->queryPrepared($sql, array_merge($queryParams, $queryParamsConditions));

    if ($fieldHistoryStatement->rowCount() === 0) {
        // message is shown, so delete this page from navigation stack
        $gNavigation->deleteLastUrl();

        // show message if there were no changes
        $gMessage->show($gL10n->get('SYS_NO_CHANGES_LOGGED'));
    }

    // create html page object
    $page = PagePresenter::withHtmlIDAndHeadline('admidio-history', $headline);
    $page->setContentFullWidth();
    
    // Logic for hiding certain columns:
    // If we have only one table name given, hide the table column
    // If we view the user profile field changes page, hide the column, too
    $showTableColumn = true;
    if (count($getTables) == 1) {
        $showTableColumn = false;
    }
    // If none of the related-to values is set, hide the related_to column
    $showRelatedColumn = true;
    $noShowRelatedTables = ['user_fields', 'users', 'user_data'];


    $form = new FormPresenter(
        'adm_navbar_filter_form',
        'sys-template-parts/form.filter.tpl',
        ADMIDIO_URL . FOLDER_MODULES . '/changelog.php',
        $page,
        array('type' => 'navbar', 'setFocus' => false)
    );

    // create filter menu with input elements for start date and end date
    $form->addInput('table', '', $getTable, array('property' => FormPresenter::FIELD_HIDDEN));
    $form->addInput('uuid', '', $getUuid, array('property' => FormPresenter::FIELD_HIDDEN));
    $form->addInput('id', '', $getId, array('property' => FormPresenter::FIELD_HIDDEN));
    $form->addInput('related_id', '', $getRelatedId, array('property' => FormPresenter::FIELD_HIDDEN));
    $form->addInput('filter_date_from', $gL10n->get('SYS_START'), $dateFromHtml, array('type' => 'date', 'maxLength' => 10));
    $form->addInput('filter_date_to', $gL10n->get('SYS_END'), $dateToHtml, array('type' => 'date', 'maxLength' => 10));
    $form->addSubmitButton('adm_button_send', $gL10n->get('SYS_OK'));
    $form->addToHtmlPage();

    $table = new HtmlTable('history_table', $page, true, true);


    /* For now, simply show all column of the changelog table. As time permits, we can improve this by hiding unneccessary columns and by better naming columns depending on the table.
     * 
     * Columns to be displayed / hidden:
     *   0. If there is only one value in the table column, hide it and display it in the title of the page.
     *   1. If there is a single ID or UUID, the record name is not displayed. It should be shown in the title of the page.
     *   2. If there is a single related-to ID, and the table is memberships, the role name should already be displayed in the title, so don't show it again.
     *   3. If none of the entries have a related ID, hide the related ID column.
     */
    $columnHeading = array();

    $table->setDatatablesOrderColumns(array(array(8, 'desc')));
    if ($showTableColumn) {
        $columnHeading[] = $gL10n->get('SYS_TABLE');
    }
    $columnHeading[] = $gL10n->get('SYS_NAME');
    if ($showRelatedColumn) {
        $columnHeading[] = $gL10n->get('SYS_RELATED_TO');
    }
    $columnHeading[] = $gL10n->get('SYS_FIELD');
    $columnHeading[] = $gL10n->get('SYS_NEW_VALUE');
    $columnHeading[] = $gL10n->get('SYS_PREVIOUS_VALUE');
    $columnHeading[] = $gL10n->get('SYS_EDITED_BY');
    $columnHeading[] = $gL10n->get('SYS_CHANGED_AT');

    $table->addRowHeadingByArray($columnHeading);

    $fieldStrings = ChangelogService::getFieldTranslations();
    $recordHidden = false;
    while ($row = $fieldHistoryStatement->fetch()) {
        $rowTable = $row['table_name'];

        $allowRecordAccess = false;
        // First step: Check view permissions to that particular log entry:
        if ($accessAll || in_array($rowTable, $tablesPermitted)) {
            $allowRecordAccess = true;
        } else {
            // no global access permissions to that particular data/table
            // Some objects have more fine-grained permissions (e.g. each group can have access permissions
            // based on the user's role -> the calling user might have access to one particular role, but not in general)
            if (in_array($rowTable, ['users', 'user_data', 'user_relations', 'members'])) {
                // user UUID is available as uuid; current user has no general access to profile data, but might have permissions to this specific user (due to fole permissions)
                $rowUser = new User($gDb, $gProfileFields);
                $rowUser->readDataByUuid($row['uuid']);
                if ($gCurrentUser->hasRightEditProfile($rowUser)) {
                    $allowRecordAccess = true;
                }
            }
            // NO access to this record allowed -> Set flag to show warning about records being 
            // hidden due to insufficient permissions
            if (!$allowRecordAccess) {
                $recordHidden = true;
                continue;
            }
        }

        $fieldInfo = $row['field_name'];
        $fieldInfo = array_key_exists($fieldInfo, $fieldStrings) ? $fieldStrings[$fieldInfo] : $fieldInfo;


        $timestampCreate = DateTime::createFromFormat('Y-m-d H:i:s', $row['timestamp']);
        $columnValues    = array();

        // 1. Column showing DB table name (only if more then one tables are shown; One table should be displayed in the headline!)
        if ($showTableColumn) {
            $columnValues[] = ChangelogService::getTableLabel($row['table_name']);
        }


        // 2. Name column: display name and optionally link it with the linkID or the recordID 
        //    Some tables need special-casing, though
        $rowLinkId = ($row['link_id']>0) ? $row['link_id'] : $row['record_id'];
        $rowName = $row['name'] ?? '';
        $rowName = Language::translateIfTranslationStrId($rowName);
        if ($row['table_name'] == 'members') {
            $columnValues[] = ChangelogService::createLink($rowName, 'users', $rowLinkId, $row['uuid'] ?? '');
        } else {
            $columnValues[] = ChangelogService::createLink($rowName, $row['table_name'], $rowLinkId, $row['uuid'] ?? '');
        }

        // 3. Optional Related-To column, e.g. for group memberships, we show the user as main name and the group as related
        //    Similarly, files/folders, organizations, guestbook comments, etc. show their parent as related
        if ($showRelatedColumn) {
            $relatedName = $row['related_name'];
            if (!empty($relatedName)) {
                $relatedTable = ChangelogService::getRelatedTable($row['table_name'], $relatedName);
                $relID = 0;
                $relUUID = '';
                $rid = $row['related_id'];
                if (empty($rid)) {
                    // do nothing
                    $columnValues[] = $relatedName;
                } elseif (ctype_digit($rid)) { // numeric related_ID -> Interpret it as ID
                    $relID = (int)$row['related_id'];
                    $columnValues[] = ChangelogService::createLink($relatedName, $relatedTable, $relID, $relUUID);
                } else { // non-numeric related_ID -> Interpret it as UUID
                    $relUUID = $row['related_id'];
                    $columnValues[] = ChangelogService::createLink($relatedName, $relatedTable, $relID, $relUUID);
                }
            } else {
                $columnValues[] = '';
            }
        }

        // 4. The field that was changed. For record creation/deletion, show an indicator, too.
        if ($row['action'] == "DELETED") {
            $columnValues[] = '<em>['.$gL10n->get('SYS_DELETED').']</em>';
        } elseif ($row['action'] == 'CREATED') {
            $columnValues[] = '<em>['.$gL10n->get('SYS_CREATED').']</em>';
        } elseif (!empty($fieldInfo)) {
            // Note: Even for user fields, we don't want to use the current user field name from the database, but the name stored in the log table from the time the change was done!.
            $fieldName = (is_array($fieldInfo) && isset($fieldInfo['name'])) ? $fieldInfo['name'] : $fieldInfo;
            $columnValues[] = Language::translateIfTranslationStrId($fieldName); // TODO_RK: Use field_id to link to the field -> Target depends on the table!!!!
        } else {
            $columnValues[] = '';
        }


        // 5. Show new and old values; For some tables we know further details about formatting
        $valueNew = $row['value_new'];
        $valueOld = $row['value_old'];
        if ($row['table_name'] == 'user_data') {
            // Format the values depending on the user field type:
            $valueNew = $gProfileFields->getHtmlValue($gProfileFields->getPropertyById((int) $row['field'], 'usf_name_intern'), $valueNew);
            $valueOld = $gProfileFields->getHtmlValue($gProfileFields->getPropertyById((int) $row['field'], 'usf_name_intern'), $valueOld);
        } elseif (is_array($fieldInfo) && isset($fieldInfo['type'])) {
            $valueNew = ChangelogService::formatValue($valueNew, $fieldInfo['type'], $fieldInfo['entries']??[]);
            $valueOld = ChangelogService::formatValue($valueOld, $fieldInfo['type'], $fieldInfo['entries']??[]);
        }

        $columnValues[] = (!empty($valueNew)) ? $valueNew : '&nbsp;';
        $columnValues[] = (!empty($valueOld)) ? $valueOld : '&nbsp;';

        // 6. User and date of the change
        $columnValues[] = ChangelogService::createLink($row['create_last_name'].', '.$row['create_first_name'], 'users', 0, $row['uuid_usr_create']);
        // $columnValues[] = '<a href="'.SecurityUtils::encodeUrl(ADMIDIO_URL.FOLDER_MODULES.'/profile/profile.php', array('user_uuid' => $row['uuid_usr_create'])).'">'..'</a>';
        $columnValues[] = $timestampCreate->format($gSettingsManager->getString('system_date').' '.$gSettingsManager->getString('system_time'));
        $table->addRowByArray($columnValues);
    }

    
    // If any of the records was hidden due to insufficient permissions, add a warning notice>
    if ($recordHidden) {
        $page->addHtml('<div class="alert alert-danger form-alert" style=""><i class="bi bi-exclamation-circle-fill"></i>' . 
            $gL10n->get('SYS_LOG_RECORDS_HIDDEN') . '</div>');
    }
    $page->addHtml($table->show());
    $page->show();
} catch (Exception $e) {
    $gMessage->show($e->getMessage());
}
