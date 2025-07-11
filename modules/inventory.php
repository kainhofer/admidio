<?php

// Admidio namespaces
use Admidio\Infrastructure\Exception;
use Admidio\Infrastructure\Utils\SecurityUtils;
use Admidio\Infrastructure\Utils\PhpIniUtils;
use Admidio\Menu\Entity\MenuEntry;
use Admidio\Inventory\Entity\SelectOptions;
use Admidio\Inventory\Service\ExportService;
use Admidio\Inventory\Service\ImportService;
use Admidio\Inventory\Service\ItemFieldService;
use Admidio\Inventory\Service\ItemService;
use Admidio\UI\Presenter\InventoryFieldsPresenter;
use Admidio\UI\Presenter\InventoryImportPresenter;
use Admidio\UI\Presenter\InventoryItemPresenter;
use Admidio\UI\Presenter\InventoryPresenter;

/**
 ***********************************************************************************************
 * Overview and maintenance of all item fields
 *
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 *
 *  Parameters:
 *
 *  mode : list     - (default) Show page with a list of all item fields
 *         edit     - Show form to create or edit a item field
 *         save     - Save the data of the form
 *         delete   - Delete a item field
 *         sequence - Change sequence for a item field
 * direction : Direction to change the sequence of the item field
 ***********************************************************************************************
 */

try {
    require_once(__DIR__ . '/../system/common.php');
    require(__DIR__ . '/../system/login_valid.php');

    // Initialize and check the parameters
    $getMode = admFuncVariableIsValid($_GET, 'mode', 'string', array('defaultValue' => 'list', 'validValues' => array('list', 'field_list', 'field_edit', 'field_save', 'field_delete', 'check_option_entry_status', 'delete_option_entry', 'sequence', 'item_edit','item_edit_lend', 'item_save', 'item_delete_explain_msg', 'item_delete_keeper_explain_msg', 'item_make_former', 'item_undo_former', 'item_delete', 'import_file_selection', 'import_read_file', 'import_assign_fields', 'import_items', 'print_preview', 'print_xlsx', 'print_ods', 'print_csv-ms', 'print_csv-oo', 'print_pdf', 'print_pdfl')));
    $getinfUUID = admFuncVariableIsValid($_GET, 'uuid', 'uuid');
    $getOptionID = admFuncVariableIsValid($_GET, 'option_id', 'int', array('defaultValue' => 0));
    $getFieldName = admFuncVariableIsValid($_GET, 'field_name', 'string', array('defaultValue' => "", 'directOutput' => true));
    $getiniUUID = admFuncVariableIsValid($_GET, 'item_uuid', 'uuid');
    $postCopyNumber = admFuncVariableIsValid($_POST, 'item_copy_number', 'numeric', array('defaultValue' => 1));
    $postCopyField = admFuncVariableIsValid($_POST, 'item_copy_field', 'int', array('defaultValue' => 0));
    $postRedirect = admFuncVariableIsValid($_POST, 'redirect', 'numeric', array('defaultValue' => 1));
    $postImported = admFuncVariableIsValid($_POST, 'imported', 'numeric', array('defaultValue' => 0));
    $getCopy = admFuncVariableIsValid($_GET, 'copy', 'bool', array('defaultValue' => false));
    $getFormer = admFuncVariableIsValid($_GET, 'item_former', 'bool', array('defaultValue' => false));
    $getRedirectToImport = admFuncVariableIsValid($_GET, 'redirect_to_import', 'bool', array('defaultValue' => false));
    $getItemUUIDs = admFuncVariableIsValid($_GET, 'item_uuids', 'array', array('defaultValue' => array()));
    if (empty($getItemUUIDs)) {
        $getItemUUIDs = admFuncVariableIsValid($_POST, 'uuids', 'array', array('defaultValue' => array()));
        $getItemUUIDs = array_map(function($uuid) {
            return preg_replace('/adm_inventory_item_/', '', $uuid);
        }, $getItemUUIDs);
    }
    $getLended = admFuncVariableIsValid($_GET, 'item_lended', 'bool', array('defaultValue' => false));

    // check if module is active
    if ($gSettingsManager->getInt('inventory_module_enabled') === 0) {
        throw new Exception('SYS_MODULE_DISABLED');
    } elseif ($gSettingsManager->getInt('inventory_module_enabled') === 1 && !$gValidLogin) {
        throw new Exception('SYS_NO_RIGHTS');
    } elseif ($gSettingsManager->getInt('inventory_module_enabled') === 3 && !$gCurrentUser->isAdministratorInventory()) {
        throw new Exception('SYS_NO_RIGHTS');
    }

    switch ($getMode) {
        case 'list':
            $headline = $gL10n->get('SYS_INVENTORY');
            $gNavigation->addStartUrl(CURRENT_URL, $headline, 'bi-box-seam-fill');
            $page = new InventoryPresenter();
            $page->setHeadline($headline);
            $page->setContentFullWidth();
            $page->createList();
            $page->show();
            break;
#region fields
        case 'field_list':
            $headline = $gL10n->get('SYS_INVENTORY_ITEMFIELDS');
            $gNavigation->addUrl(CURRENT_URL, $headline);
            $itemFields = new InventoryFieldsPresenter('adm_inventory_item_fields');
            $itemFields->setHeadline($headline);
            $itemFields->createList();
            $itemFields->show();
            break;

        case 'field_edit':
            // set headline of the script
            if ($getinfUUID !== '') {
                $headline = $gL10n->get('SYS_INVENTORY_ITEMFIELD_EDIT');
            } else {
                $headline = $gL10n->get('SYS_INVENTORY_ITEMFIELD_CREATE');
            }

            $gNavigation->addUrl(CURRENT_URL, $headline);
            $itemFields = new InventoryFieldsPresenter('adm_item_fields_edit');
            $itemFields->setHeadline($headline);
            $itemFields->createEditForm($getinfUUID, $getFieldName);
            $itemFields->show();
            break;

        case 'field_save':
            $itemFieldsModule = new ItemFieldService($gDb, $getinfUUID);
            $itemFieldsModule->save();

            $gNavigation->deleteLastUrl();
            echo json_encode(array('status' => 'success', 'url' => $gNavigation->getUrl()));
            break;

        case 'field_delete':
            // check the CSRF token of the form against the session token
            SecurityUtils::validateCsrfToken($_POST['adm_csrf_token']);

            $itemFieldsModule = new ItemFieldService($gDb, $getinfUUID);
            $itemFieldsModule->delete();

            echo json_encode(array('status' => 'success', 'message' => $gL10n->get('SYS_INVENTORY_ITEMFIELD_DELETED')));
            break;

        case 'check_option_entry_status':
            // check the CSRF token of the form against the session token
            SecurityUtils::validateCsrfToken($_POST['adm_csrf_token']);

            $status = 'error';
            // check if the option entry has any dependencies in the database
            if ($getOptionID > 0) {
                $itemFieldsModule = new ItemFieldService($gDb, $getinfUUID);

                $option = new SelectOptions($gDb, $itemFieldsModule->getFieldID());
                if ($option->isOptionUsed($getOptionID)) {
                    // if the option is used in a profile field, then it cannot be deleted
                    $status = 'used';
                } else {
                    // option entry can be deleted
                    $status = 'unused';
                }
            }
            echo json_encode(array('status' => $status));
            break;

        case 'delete_option_entry':
            // check the CSRF token of the form against the session token
            SecurityUtils::validateCsrfToken($_POST['adm_csrf_token']);

            $status = 'error';
            // check if the option entry has any dependencies in the database
            if ($getOptionID > 0) {
                $itemFieldsModule = new ItemFieldService($gDb, $getinfUUID);

                $option = new SelectOptions($gDb, $itemFieldsModule->getFieldID());
                // delete the option entry
                $option->deleteOption($getOptionID);
                $status = 'success';
            }
            echo json_encode(array('status' => $status));
            break;

        case 'sequence':
            // Update menu entry sequence
            $postDirection = admFuncVariableIsValid($_POST, 'direction', 'string', array('validValues' => array(MenuEntry::MOVE_UP, MenuEntry::MOVE_DOWN)));
            $getOrder      = admFuncVariableIsValid($_GET, 'order', 'array');

            // check the CSRF token of the form against the session token
            SecurityUtils::validateCsrfToken($_POST['adm_csrf_token']);

            $itemFieldsModule = new ItemFieldService($gDb, $getinfUUID);

            if (!empty($getOrder)) {
                // set new order (drag and drop)
                $ret = $itemFieldsModule->setSequence(explode(',', $getOrder));
            } else {
                $ret = $itemFieldsModule->moveSequence($postDirection);
            }

            echo json_encode(array('status' =>  ($ret ? 'success' : 'error')));
            break;
#endregion
#region items
        case 'item_edit':
            // set headline of the script
            if ($getiniUUID !== '' && $getCopy) {
                $headline = $gL10n->get('SYS_INVENTORY_ITEM_COPY');
            }
            elseif (count($getItemUUIDs) > 1) {
                $headline = $gL10n->get('SYS_INVENTORY_ITEMS_EDIT');
            }
            elseif ($getiniUUID !== '' || count($getItemUUIDs) === 1) {
                $headline = $gL10n->get('SYS_INVENTORY_ITEM_EDIT');
                // set the item uuid to the single selected item
                if (count($getItemUUIDs) === 1) {
                    $getiniUUID = $getItemUUIDs[0];
                }
            }
            else {
                $headline = $gL10n->get('SYS_INVENTORY_ITEM_CREATE');
            }

            $gNavigation->addUrl(CURRENT_URL, $headline);

            if (count($getItemUUIDs) > 1) {
                $item = new InventoryItemPresenter('adm_items_edit');
                $item->setHeadline($headline);
                $item->createEditItemsForm($getItemUUIDs);
            }
            else {
                $item = new InventoryItemPresenter('adm_item_edit');
                $item->setHeadline($headline);
                $item->createEditForm($getiniUUID, $getCopy);
            }

            $item->show();
            break;

        case 'item_edit_lend':
            // set headline of the script
            if ($getLended) {
                $headline = $gL10n->get('SYS_INVENTORY_ITEM_RETURN');
            }
            else {
                $headline = $gL10n->get('SYS_INVENTORY_ITEM_LEND');
            }
            $gNavigation->addUrl(CURRENT_URL, $headline);
            $item = new InventoryItemPresenter('adm_item_edit_lend');
            $item->setHeadline($headline);
            $item->createEditLendForm($getiniUUID);
            $item->show();
            break;

        case 'item_save':
            if ($getiniUUID !== '' && $getCopy) {
                $getiniUUID = '';
                $message = $gL10n->get('SYS_INVENTORY_ITEM_COPIED');
            }
            elseif (count($getItemUUIDs) > 0) {
                $message = $gL10n->get('SYS_INVENTORY_SELECTION_EDITED');
            }
            elseif ($getiniUUID !== '') {
                $message = $gL10n->get('SYS_INVENTORY_ITEM_EDITED');
            }
            else {
                $message = $gL10n->get('SYS_INVENTORY_ITEM_CREATED');
            }

            if (count($getItemUUIDs) > 0) {
                foreach ($getItemUUIDs as $itemUuid) {
                    $itemModule = new ItemService($gDb, $itemUuid, $postCopyField, $postCopyNumber, $postImported);
                    $itemModule->save(true);
                }
            }
            else {
                $itemModule = new ItemService($gDb, $getiniUUID, $postCopyField, $postCopyNumber, $postImported);
                $itemModule->save();
            }

            $gNavigation->deleteLastUrl();
            echo json_encode(array('status' => 'success', 'message' => $message,'url' => $gNavigation->getUrl()));
            break;

        case 'item_delete_explain_msg':
            if (count($getItemUUIDs) > 0) {
                $undoFormerOnClick = 'callUrlHideElements(\'adm_inventory_item_\', [\'' . implode('\', \'', $getItemUUIDs) . '\'], \'' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_undo_former')) . '\', \'' . $gCurrentSession->getCsrfToken() . '\')';
                $formerOnClick = 'callUrlHideElements(\'adm_inventory_item_\', [\'' . implode('\', \'', $getItemUUIDs) . '\'], \'' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_make_former')) . '\', \'' . $gCurrentSession->getCsrfToken() . '\')';
                $deleteOnClick = 'callUrlHideElements(\'adm_inventory_item_\', [\'' . implode('\', \'', $getItemUUIDs) . '\'], \'' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_delete')) . '\', \'' . $gCurrentSession->getCsrfToken() . '\')';
                $headerMsg = $gL10n->get('SYS_NOTE');
            }
            else {
                $formerOnClick = 'callUrlHideElement(\'adm_inventory_item_' . $getiniUUID . '\', \'' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_make_former', 'item_uuid' => $getiniUUID)) . '\', \'' . $gCurrentSession->getCsrfToken() . '\')';
                $deleteOnClick = 'callUrlHideElement(\'adm_inventory_item_' . $getiniUUID . '\', \'' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_delete', 'item_uuid' => $getiniUUID)) . '\', \'' . $gCurrentSession->getCsrfToken() . '\')';
                $headerMsg = $gL10n->get('SYS_INVENTORY_ITEM_DELETE');
            }

            $msg =  '
                <div class="modal-header">
                    <h3 class="modal-title">' . $headerMsg . '</h3>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">';
                if (count($getItemUUIDs) > 0) {
                    $msg.= '<p><i class="bi bi-eye-fill"></i>&nbsp;' . $gL10n->get('SYS_INVENTORY_SELECTION_UNDO_FORMER_DESC', array($gL10n->get('SYS_INVENTORY_SELECTION_UNDO_FORMER'))) . '</p>';
                    $msg.= '<p><i class="bi bi-eye-slash-fill"></i>&nbsp;' . $gL10n->get('SYS_INVENTORY_SELECTION_MAKE_FORMER_DESC', array($gL10n->get('SYS_INVENTORY_SELECTION_MAKE_FORMER'))) . '</p>';
                    $msg.= '<p><i class="bi bi-trash-fill"></i>&nbsp;' . $gL10n->get('SYS_INVENTORY_SELECTION_DELETE_DESC', array($gL10n->get('SYS_DELETE_SELECTION'))) . '</p>';
                }
                else {
                    if (!$getFormer) {
                        $msg.= '<p><i class="bi bi-eye-slash-fill"></i>&nbsp;' . $gL10n->get('SYS_INVENTORY_ITEM_MAKE_FORMER_DESC', array($gL10n->get('SYS_INVENTORY_ITEM_MAKE_FORMER'))) . '</p>';
                    }
                    if ($gCurrentUser->isAdministratorInventory()) {
                        $msg.= '<p><i class="bi bi-trash-fill"></i>&nbsp;' . $gL10n->get('SYS_INVENTORY_ITEM_DELETE_DESC', array($gL10n->get('SYS_INVENTORY_ITEM_DELETE'))) . '</p>';
                    }
                }
                $msg.='</div>
                <div class="modal-footer">';
                if (count($getItemUUIDs) > 0) {
                    $msg .= '<button id="adm_button_former" type="button" class="btn btn-primary mr-4" onclick="' . $undoFormerOnClick . '">
                        <i class="bi bi-eye"></i>' . $gL10n->get('SYS_INVENTORY_SELECTION_UNDO_FORMER') . '</button>';
                    $msg .= '<button id="adm_button_former" type="button" class="btn btn-primary mr-4" onclick="' . $formerOnClick . '">
                        <i class="bi bi-eye-slash"></i>' . $gL10n->get('SYS_INVENTORY_SELECTION_MAKE_FORMER') . '</button>';
                    $msg.= '<button id="adm_button_delete" type="button" class="btn btn-primary" onclick="' . $deleteOnClick . '">
                        <i class="bi bi-trash"></i>' . $gL10n->get('SYS_DELETE_SELECTION') . '</button>';
                }
                else {
                    if (!$getFormer) {
                        $msg .= '<button id="adm_button_former" type="button" class="btn btn-primary mr-4" onclick="' . $formerOnClick . '">
                            <i class="bi bi-eye-slash"></i>' . $gL10n->get('SYS_INVENTORY_ITEM_MAKE_FORMER') . '</button>';
                    }
                    if ($gCurrentUser->isAdministratorInventory()) {
                        $msg.= '<button id="adm_button_delete" type="button" class="btn btn-primary" onclick="' . $deleteOnClick . '">
                            <i class="bi bi-trash"></i>' . $gL10n->get('SYS_INVENTORY_ITEM_DELETE') . '</button>';
                    }
                }
                $msg.='<div id="adm_status_message" class="mt-4 w-100"></div>
                </div>';

                echo $msg;
            break;
        
        case 'item_delete_keeper_explain_msg':
            $msg =  '
                <div class="modal-header">
                    <h3 class="modal-title">' . $gL10n->get('SYS_INVENTORY_ITEM_MAKE_FORMER') . '</h3>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p><i class="bi bi-eye-slash-fill"></i>&nbsp;' . $gL10n->get('SYS_INVENTORY_KEEPER_FORMER_DESC') . '</p>
                </div>
                <div class="modal-footer">
                <button id="adm_button_former" type="button" class="btn btn-primary mr-4" onclick="callUrlHideElement(\'adm_inventory_item_' . $getiniUUID . '\', \'' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_make_former', 'item_uuid' => $getiniUUID)) . '\', \'' . $gCurrentSession->getCsrfToken() . '\')">
                        <i class="bi bi-eye-slash"></i>' . $gL10n->get('SYS_INVENTORY_ITEM_MAKE_FORMER') . '</button>
                <div id="adm_status_message" class="mt-4 w-100"></div>
                </div>';

                echo $msg;
            break;

        case 'item_make_former':
            // check the CSRF token of the form against the session token
            SecurityUtils::validateCsrfToken($_POST['adm_csrf_token']);
            if (count($getItemUUIDs) > 0) {
                foreach ($getItemUUIDs as $itemUuid) {
                    $itemModule = new ItemService($gDb, $itemUuid);
                    $itemModule->makeItemFormer();
                }
                echo json_encode(array('status' => 'success', 'message' => $gL10n->get('SYS_INVENTORY_SELECTION_MADE_FORMER')));
            }
            else {
                $itemModule = new ItemService($gDb, $getiniUUID);
                $itemModule->makeItemFormer();
                echo json_encode(array('status' => 'success', 'message' => $gL10n->get('SYS_INVENTORY_ITEM_MADE_FORMER')));
           }

            break;

        case 'item_undo_former':
            // check the CSRF token of the form against the session token
            SecurityUtils::validateCsrfToken($_POST['adm_csrf_token']);
            if (count($getItemUUIDs) > 0) {
                foreach ($getItemUUIDs as $itemUuid) {
                    $itemModule = new ItemService($gDb, $itemUuid);
                    $itemModule->undoItemFormer();
                }
                echo json_encode(array('status' => 'success', 'message' => $gL10n->get('SYS_INVENTORY_SELECTION_UNDONE_FORMER')));
            }
            else {
                $itemModule = new ItemService($gDb, $getiniUUID);
                $itemModule->undoItemFormer();
            echo json_encode(array('status' => 'success', 'message' => $gL10n->get('SYS_INVENTORY_ITEM_UNDONE_FORMER')));
           }

            break;
    
        case 'item_delete':
            // check the CSRF token of the form against the session token
            SecurityUtils::validateCsrfToken($_POST['adm_csrf_token']);

            if (count($getItemUUIDs) > 0) {
                foreach ($getItemUUIDs as $itemUuid) {
                    $itemModule = new ItemService($gDb, $itemUuid);
                    $itemModule->delete();                   
                }
                echo json_encode(array('status' => 'success', 'message' => $gL10n->get('SYS_INVENTORY_SELECTION_DELETED')));
            }
            else {
                $itemModule = new ItemService($gDb, $getiniUUID);
                $itemModule->delete();

                echo json_encode(array('status' => 'success', 'message' => $gL10n->get('SYS_INVENTORY_ITEM_DELETED')));
            }
            break;
#endregion
#region import
        case 'import_file_selection':
            // check if file_uploads is set to ON in the current server settings...
            if (!PhpIniUtils::isFileUploadEnabled()) {
                $gMessage->show($gL10n->get('SYS_SERVER_NO_UPLOAD'));
                 // => EXIT
                 break;
            }

            $headline = $gL10n->get('SYS_IMPORT');
            $gNavigation->addUrl(CURRENT_URL, $headline);

            $import = new InventoryImportPresenter('adm_inventory_import');
            $import->setHeadline($headline);
            $import->createImportFileSelectionForm();
            $import->show();
            break;

         case 'import_read_file':
            $import = new ImportService();
            $import->readImportFile();
            echo json_encode(array(
                'status' => 'success',
                'url' => SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'import_assign_fields'))
            ));
            break;

        case 'import_assign_fields':
            $headline = $gL10n->get('SYS_ASSIGN_FIELDS');
            $gNavigation->addUrl(CURRENT_URL, $headline);

            $import = new InventoryImportPresenter('adm_inventory_import_assign_fields');
            $import->setHeadline($headline);
            $import->createAssignFieldsForm();
            $import->show();
            break;

        case 'import_items':
            $import = new ImportService();
            $retStr = $import->importItems();

            $gNavigation->deleteLastUrl();
        
            // Go back to item view
            if ($gNavigation->count() > 1) {
                $gNavigation->deleteLastUrl();
            }
            
            // Unset the import request session
            if (isset($_SESSION['import_csv_request'])) {
                unset($_SESSION['import_csv_request']);
            }

            // Unset the import data session
            if (isset($_SESSION['import_data'])) {
                unset($_SESSION['import_data']);
            }
            
            echo json_encode(array('status' => $retStr['success'], 'message' => $retStr['message'], 'url' => $gNavigation->getUrl()));
            break;
#endregion
#region print
        case 'print_preview':
            $headline = $gL10n->get('SYS_INVENTORY');
            $page = new InventoryPresenter();
            $page->setHeadline($headline);
            $page->setPrintMode();
            $page->createList();
            $page->show();
            break;

        case 'print_xlsx':
        case 'print_ods':
        case 'print_csv-ms':
        case 'print_csv-oo':
        case 'print_pdf':
        case 'print_pdfl':
            $export = new ExportService();
            $exportMode = str_replace('print_', '', $getMode);
            $export->createExport($exportMode);
            break;
#endregion
        default:
            $gMessage->show($gL10n->get('SYS_INVALID_PAGE_VIEW'));
            break;
    }
} catch (Throwable $e) {
    if (in_array($getMode, array('field_save', 'field_delete', 'sequence', 'item_save', 'import_read_file', 'import_items'))) {
        echo// PHP namespaces
        json_encode(array('status' => 'error', 'message' => $e->getMessage()));
    } else {
        $gMessage->show($e->getMessage());
    }
}
