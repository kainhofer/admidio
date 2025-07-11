<?php

namespace Admidio\UI\Presenter;

// Admidio namespaces
use Admidio\Categories\Entity\Category;
use Admidio\Categories\Service\CategoryService;
use Admidio\Infrastructure\Language;
use Admidio\Infrastructure\Exception;
use Admidio\Infrastructure\Utils\SecurityUtils;
use Admidio\Infrastructure\Utils\StringUtils;
use Admidio\Inventory\ValueObjects\ItemsData;
use Admidio\Changelog\Service\ChangelogService;
use Admidio\UI\Component\DataTables;
use Admidio\UI\Presenter\FormPresenter;
use Admidio\UI\Presenter\PagePresenter;
use Admidio\Users\Entity\User;

/**
 * @brief Class with methods to display the module pages.
 *
 * This class adds some functions that are used in the menu module to keep the
 * code easy to read and short
 *
 * **Code example**
 * ```
 * // generate html output with available registrations
 * $page = new Menu('adm_menu', $headline);
 * $page->createEditForm();
 * $page->show();
 * ```
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 */
class InventoryPresenter extends PagePresenter
{
    /**
     * @var ItemsData Object of the class ItemsData that contains all data of the inventory items.
     */
    protected ItemsData $itemsData;
    /**
     * @var CategoryService An object of the class CategoryService to get all categories.
     */
    protected CategoryService $categoryService;
    /**
     * @var string filter string for the search field
     */
    protected string $getFilterString = '';
    /**
     * @var string filter string for the category UUID selection
     */
    protected string $getFilterCategoryUUID = '';
    /**
     * @var int filter id for the keeper selection
     */
    protected int $getFilterKeeper = 0;
    /**
     * @var int filter for all items
     */
    protected int $getFilterItems = 0;
    /**
     * @var bool true if all items should be shown
     */
    protected bool $showFormerItems = false;


    /**
     * Constructor creates the page object and initialized all parameters.
     * @throws Exception
     */
    public function __construct()
    {
        global $gDb, $gCurrentOrgId;

        // initialize the parameters
        $this->getFilterString = admFuncVariableIsValid($_GET, 'items_filter_string', 'string', array('defaultValue' => ''));
        $this->getFilterCategoryUUID = admFuncVariableIsValid($_GET, 'items_filter_category', 'string', array('defaultValue' => ''));
        $this->getFilterKeeper = admFuncVariableIsValid($_GET, 'items_filter_keeper', 'int', array('defaultValue' => 0));
        $this->getFilterItems = admFuncVariableIsValid($_GET, 'items_filter', 'int', array('defaultValue' => 0));

        $this->itemsData = new ItemsData($gDb, $gCurrentOrgId);
        
        $this->showFormerItems = ($this->getFilterItems >= 1) ? true : false;
        $this->itemsData->showFormerItems($this->showFormerItems);
        $this->itemsData->readItems();

        $this->categoryService = new CategoryService($gDb, 'IVT');

        parent::__construct($this->getFilterCategoryUUID);
    }

    /**
     * Create a functions menu and a filter navbar.
     * @return void
     * @throws Exception
     */
    protected function createHeader(): void
    {
        global $gCurrentUser, $gL10n, $gDb, $gCurrentOrgId, $gProfileFields;

        if ($gCurrentUser->isAdministratorInventory()) {
            // show link to view inventory history
            ChangelogService::displayHistoryButton($this, 'inventory', 'inventory_fields,inventory_field_select_options,inventory_items,inventory_item_data,inventory_item_lend_data');
           
            // show link to create new item
            $this->addPageFunctionsMenuItem(
                'menu_item_inventory_create_item',
                $gL10n->get('SYS_INVENTORY_ITEM_CREATE'),
                SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php' , array('mode' => 'item_edit')),
                'bi-plus-circle-fill'
            );
        }

        if ($gCurrentUser->isAdministratorInventory()) {
            // link to print overlay and exports
            $this->addPageFunctionsMenuItem(
                'menu_item_lists_print_view',
                $gL10n->get('SYS_PRINT_PREVIEW'),
                'javascript:void(0);',
                'bi-printer-fill'
            );

            // dropdown menu for export options
            $this->createExportDropdown();

            // show link to import items
            $this->addPageFunctionsMenuItem(
                'menu_item_inventory_import_items',
                $gL10n->get('SYS_INVENTORY_IMPORT_ITEMS'),
                SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php' , array('mode' => 'import_file_selection')),
                'bi-upload'
            );

            // show link to maintain fields
            $this->addPageFunctionsMenuItem(
                'menu_item_inventory_item_fields',
                $gL10n->get('SYS_INVENTORY_ITEMFIELDS_EDIT'),
                SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php' , array('mode' => 'field_list')),
                'bi-ui-radios'
            );
        }

        // filter form
        $keeper = ($this->isCurrentUserKeeper()) ? $gCurrentUser->getValue('usr_id') : null;
        $showFilterForm = ($gCurrentUser->isAdministratorInventory() || $this->isKeeperAuthorizedToEdit($keeper)) ? FormPresenter::FIELD_DEFAULT : FormPresenter::FIELD_DISABLED;

        $form = new FormPresenter(
            'adm_navbar_filter_form',
            'sys-template-parts/form.filter.tpl',
            '',
            $this,
            array('type' => 'navbar', 'setFocus' => false)
        );
        
        $initialFilter = addslashes($this->getFilterString);
        $printBaseUrl  = SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'print_preview'));
        
        $this->addJavascript('
            $(document).ready(function(){
                // only submit non-empty filter values
                $("#items_filter_category, #items_filter_keeper, #items_filter").on("change", function(){
                    var form = $("#adm_navbar_filter_form");

                    // Text-Filter
                    var textFilterInput = $("#items_filter_string");
                    if (textFilterInput.val() === "") {
                        textFilterInput.removeAttr("name");
                    } else {
                        textFilterInput.attr("name", "items_filter_string");
                    }

                    // Category
                    var categorySelect = $("#items_filter_category");
                    if (categorySelect.val() === "") {
                        categorySelect.removeAttr("name");
                    } else {
                        categorySelect.attr("name", "items_filter_category");
                    }

                    // Keeper
                    var keeperSelect = $("#items_filter_keeper");
                    if (keeperSelect.val() === "") {
                        keeperSelect.removeAttr("name");
                    } else {
                        keeperSelect.attr("name", "items_filter_keeper");
                    }

                    // items filter
                    var itemsSelect = $("#items_filter");
                    if (itemsSelect.val() === "") {
                        itemsSelect.removeAttr("name");
                    } else {
                        itemsSelect.attr("name", "items_filter");
                    }

                    form.submit();
                });

                // fill the DataTable filter string with the current search value
                var table = $("#adm_inventory_table").DataTable();            
                var initFilter = "' . $initialFilter . '";
                if (initFilter !== "") {
                    table.search(initFilter).draw();
                }
            
                // set the filter string in the form when the DataTable is searched
                table.on("search.dt", function(){
                var textFilter = table.search() || "";
                $("#adm_navbar_filter_form")
                    .find("input[name=\'items_filter_string\']")
                    .val(textFilter);
                });
            
                // create the print view link with the current filter values
                $("#menu_item_lists_print_view").off("click").on("click", function(e){
                    e.preventDefault();
                    var textFilter     = $("#items_filter_string").val() || "";
                    var category     = $("#items_filter_category").val()   || "";
                    var keeper  = $("#items_filter_keeper").val()     || "";
                    var filterItems = $("#items_filter").val()     || "";
                    var url = "' . $printBaseUrl . '"
                            + "&items_filter_string="   + encodeURIComponent(textFilter)
                            + "&items_filter_category=" + encodeURIComponent(category)
                            + "&items_filter_keeper="   + encodeURIComponent(keeper)
                            + "&items_filter="        + encodeURIComponent(filterItems);
                
                    window.open(url, "_blank");
                });
            });',
            true
        );
        
        // filter string (hidden)
        $form->addInput('items_filter_string', $gL10n->get('SYS_FILTER'), "", array('property' => FormPresenter::FIELD_HIDDEN));
        
        // filter category
        $form->addSelectBoxForCategories(
            'items_filter_category',
            $gL10n->get('SYS_CATEGORY'),
            $gDb,
            'IVT',
            FormPresenter::SELECT_BOX_MODUS_FILTER,
            array('defaultValue' => $this->getFilterCategoryUUID)
        );

        // read all keeper
        $sql = 'SELECT DISTINCT ind_value, 
            CASE 
                WHEN ind_value = -1 THEN \'n/a\'
                ELSE CONCAT_WS(\', \', last_name.usd_value, first_name.usd_value)
            END as keeper_name
            FROM '.TBL_INVENTORY_ITEM_DATA.'
            INNER JOIN '.TBL_INVENTORY_FIELDS.'
                ON inf_id = ind_inf_id
            LEFT JOIN '. TBL_USER_DATA. ' as last_name
                ON last_name.usd_usr_id = ind_value
                AND last_name.usd_usf_id = '. $gProfileFields->getProperty('LAST_NAME', 'usf_id'). '
            LEFT JOIN '. TBL_USER_DATA. ' as first_name
                ON first_name.usd_usr_id = ind_value
                AND first_name.usd_usf_id = '. $gProfileFields->getProperty('FIRST_NAME', 'usf_id'). '
            WHERE (inf_org_id  = '. $gCurrentOrgId .'
                OR inf_org_id IS NULL)
            AND inf_name_intern = \'KEEPER\'
            ORDER BY keeper_name ASC;';

        // filter keeper
        $form->addSelectBoxFromSql(
            'items_filter_keeper',
            $gL10n->get('SYS_INVENTORY_KEEPER'),
            $gDb,
            $sql,
            array(
                'property' => $showFilterForm,
                'defaultValue' => $this->getFilterKeeper,
                'showContextDependentFirstEntry' => true
            )
        );

        $selectBoxValues = array(
            '0' => $gL10n->get('SYS_INVENTORY_FILTER_CURRENT_ITEMS'),
            '1' => $gL10n->get('SYS_INVENTORY_FILTER_FORMER_ITEMS'),
            '2' => $gL10n->get('SYS_ALL')
        );
        // filter all items
        $form->addSelectBox(
            'items_filter',
            $gL10n->get('SYS_INVENTORY_ITEMS'),
            $selectBoxValues,
            array(
                'property' => $showFilterForm,
                'defaultValue' => $this->getFilterItems,
                'showContextDependentFirstEntry' => false
            )
        );

        $form->addToHtmlPage();
    }

    /**
     * Create the export dropdown menu for the inventory items.
     * This method adds various export options to the page functions menu.
     *
     * @return void
     * @throws Exception
     */
    protected function createExportDropdown() : void
    {
        global $gL10n;
        // create the export dropdown menu
        $this->addPageFunctionsMenuItem(
            'menu_item_lists_export',
            $gL10n->get('SYS_EXPORT_TO'),
            '#',
            'bi-download'
        );
        $this->addPageFunctionsMenuItem(
            'menu_item_lists_xlsx',
            $gL10n->get('SYS_MICROSOFT_EXCEL') .' (*.xlsx)',
            SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array(
                    'items_filter_string'   => $this->getFilterString,
                    'items_filter_category' => $this->getFilterCategoryUUID,
                    'items_filter_keeper'   => $this->getFilterKeeper,
                    'items_filter'          => $this->getFilterItems,
                    'mode'                  => 'print_xlsx'
                )
            ),
            'bi-filetype-xlsx',
            'menu_item_lists_export'
        );
        $this->addPageFunctionsMenuItem(
            'menu_item_lists_ods',
            $gL10n->get('SYS_ODF_SPREADSHEET'),
            SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array(
                    'items_filter_string'   => $this->getFilterString,
                    'items_filter_category' => $this->getFilterCategoryUUID,
                    'items_filter_keeper'   => $this->getFilterKeeper,
                    'items_filter'          => $this->getFilterItems,
                    'mode'                  => 'print_ods'
                )
            ),
            'bi-file-earmark-spreadsheet',
            'menu_item_lists_export'
        );
        $this->addPageFunctionsMenuItem(
            'menu_item_lists_csv_ms',
            $gL10n->get('SYS_CSV') . ' (' . $gL10n->get('SYS_ISO_8859_1') . ')',
            SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array(
                    'items_filter_string'   => $this->getFilterString,
                    'items_filter_category' => $this->getFilterCategoryUUID,
                    'items_filter_keeper'   => $this->getFilterKeeper,
                    'items_filter'          => $this->getFilterItems,
                    'mode'                  => 'print_csv-ms'
                )
            ),
            'bi-filetype-csv',
            'menu_item_lists_export'
        );
        $this->addPageFunctionsMenuItem(
            'menu_item_lists_csv',
            $gL10n->get('SYS_CSV') . ' (' . $gL10n->get('SYS_UTF8') . ')',
            SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array(
                    'items_filter_string'   => $this->getFilterString,
                    'items_filter_category' => $this->getFilterCategoryUUID,
                    'items_filter_keeper'   => $this->getFilterKeeper,
                    'items_filter'          => $this->getFilterItems,
                    'mode'                  => 'print_csv-oo'
                )
            ),
            'bi-filetype-csv',
            'menu_item_lists_export'
        );
        $this->addPageFunctionsMenuItem(
            'menu_item_lists_pdf',
            $gL10n->get('SYS_PDF') . ' (' . $gL10n->get('SYS_PORTRAIT') . ')',
            SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array(
                    'items_filter_string'   => $this->getFilterString,
                    'items_filter_category' => $this->getFilterCategoryUUID,
                    'items_filter_keeper'   => $this->getFilterKeeper,
                    'items_filter'          => $this->getFilterItems,
                    'mode'                  => 'print_pdf'
                )
            ),
            'bi-filetype-pdf',
            'menu_item_lists_export'
        );
        $this->addPageFunctionsMenuItem(
            'menu_item_lists_pdfl',
            $gL10n->get('SYS_PDF') . ' (' . $gL10n->get('SYS_LANDSCAPE') . ')',
            SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array(
                    'items_filter_string'   => $this->getFilterString,
                    'items_filter_category' => $this->getFilterCategoryUUID,
                    'items_filter_keeper'   => $this->getFilterKeeper,
                    'items_filter'          => $this->getFilterItems,
                    'mode'                  => 'print_pdfl'
                )
            ),
            'bi-filetype-pdf',
            'menu_item_lists_export'
        );

        // add javascript for the export dropdown menu to change the URL of the export link
        $this->addJavascript('
            $(document).ready(function(){
                var buttons = {
                    xlsx:    "print_xlsx",
                    ods:     "print_ods",
                    csv_ms:  "print_csv-ms",
                    csv:     "print_csv-oo",
                    pdf:     "print_pdf",
                    pdfl:    "print_pdfl"
                };

                $.each(buttons, function(suffix, modeValue){
                    var selector = "#menu_item_lists_" + suffix;
                    $(selector).on("click", function(e){
                        var textFilter = $("#items_filter_string").val()            || "";
                        var category   = $("#items_filter_category").val()         || "";
                        var keeper     = $("#items_filter_keeper").val()           || "";
                        var filterItems = $("#items_filter").val()     || "";
                        var base = this.href.split("?")[0];
                        var qs = [
                        "items_filter_string="   + encodeURIComponent(textFilter),
                        "items_filter_category=" + encodeURIComponent(category),
                        "items_filter_keeper="   + encodeURIComponent(keeper),
                        "items_filter="          + encodeURIComponent(filterItems),
                        "mode="                  + modeValue
                        ].join("&");
                        this.href = base + "?" + qs;
                    });
                });
            });',
            true
        );
    }

    /**
     * Create the list of all items in the inventory. This method is used to display the items in a table format.
     * It prepares the data for the table and handles the print view if required.
     *
     * @return void
     * @throws Exception
     */
    public function createList() : void
    {
        global $gSettingsManager;

        if (!$this->printView) {
            $this->createHeader();
            $templateData = $this->prepareData('html');

            // initialize and set the parameter for DataTables
            $dataTables = new DataTables($this, 'adm_inventory_table');
            if ($this->getFilterItems == 2) {
                // add the checkbox for selecting items and action buttons
                $this->addJavascript('
                    $(document).ready(function() {
						var $table = $("#adm_inventory_table");
						
						$table.one("init.dt", function() {
							var tableApi = $table.DataTable();

							// base URLs
							var editUrlBase = "' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . "/inventory.php", array("mode" => "item_edit")) . '";
							var explainDeleteUrlBase = "' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . "/inventory.php", array("mode" => "item_delete_explain_msg")) . '";

							// cache jQuery objects
							var $editButton    = $("#edit-selected").css("display","block");
							var $deleteButon    = $("#delete-selected").css("display","block");
							var $headChk        = $table.find("thead input[type=checkbox]");
							var $rowChks        = function(){ return $table.find("tbody input[type=checkbox]"); };
							var $actions        = $("#adm_inventory_table_select_actions");

                            // master list of selected IDs
                            var selectedIds = [];

                            function anySelected() {
                                return selectedIds.length > 0;
                            }

                            function refreshActions() {
                                $editButton.prop("disabled", !anySelected());
                                $deleteButon.prop("disabled", !anySelected());
                            }

                            function updateHeaderState() {
                                var total   = $rowChks().length;
                                var checked = $rowChks().filter(":checked").length;
                                if (checked === 0) {
                                    $headChk.prop({ checked: false, indeterminate: false });
                                }
                                else if (checked === total) {
                                    $headChk.prop({ checked: true,  indeterminate: false });
                                }
                                else {
                                    $headChk.prop({ checked: false, indeterminate: true });
                                }
                            }

                            // header-checkbox → select/unselect *all* rows
                            $headChk.on("change", function(){
                                var checkAll = this.checked;
                                selectedIds = [];

                                if (checkAll) {
                                    // grab every row (even on other pages)
                                    tableApi.rows().every(function(){
                                        if ($(this.node()).is(":visible")){
                                            selectedIds.push(this.node().id.replace(/^adm_inventory_item_/, ""));
                                        }
                                    });
                                }

                                // toggel checked state of all row checkboxes
                                $rowChks().prop("checked", checkAll);

                                updateHeaderState();
                                refreshActions();
                            });

                            // individual row-checkbox → toggle just that ID
                            $table.on("change", "tbody input[type=checkbox]", function(){
                                var id  = this.closest("tr").id.replace(/^adm_inventory_item_/, "");
                                var idx = selectedIds.indexOf(id);
                                if (this.checked && idx === -1) {
                                    selectedIds.push(id);
                                }
                                else if (!this.checked && idx !== -1) {
                                    selectedIds.splice(idx,1);
                                }

                                updateHeaderState();
                                refreshActions();
                            });

                            // bulk-delete button → fire Admidio’s openPopup against explain_msg URL
                            $actions.off("click", "#delete-selected").on("click", "#delete-selected", function(){
                                // build uuids[] querystring
                                var qs = selectedIds.map(function(id){
                                    return "item_uuids[]=" + encodeURIComponent(id);
                                }).join("&");

                                // full URL to your explain_msg endpoint
                                var popupUrl = explainDeleteUrlBase + "&" + qs;

                                // create a temporary <a class="openPopup"> to invoke Admidio’s AJAX popup loader
                                $("<a>", {
                                    href: "javascript:void(0);",
                                    class: "admidio-icon-link openPopup",
                                    "data-href": popupUrl
                                }).appendTo("body")
                                .click()    // trigger the built-in openPopup handler
                                .remove();
                                
                                // when the popup closes, unselect all items
                                $(document).one("hidden.bs.modal", function() {
                                    selectedIds = [];
                                    $headChk.prop({ checked: false, indeterminate: false });
                                    $rowChks().prop("checked", false);
                                    
                                    // initialize button states
                                    updateHeaderState();
                                    refreshActions();
                                });
                            });
                            
                            // bulk-edit button → fire Admidio’s openPopup against item_edit URL
                            $actions.off("click", "#edit-selected").on("click", "#edit-selected", function(){
                                // build uuids[] querystring
                                var qs = selectedIds.map(function(id){
                                    return "item_uuids[]=" + encodeURIComponent(id);
                                }).join("&");

                                // full URL to the edit endpoint
                                var editUrl = editUrlBase + "&" + qs;

                                // open the editUrl directly in the current window
                                window.location.href = editUrl;
                            });

                            // initialize button states
                            refreshActions();
                        });
                    });'
                    , true
                );

                $dataTables->disableColumnsSort(array(1, count($templateData['headers'])));
                $dataTables->setColumnsNotHideResponsive(array(1, count($templateData['headers'])));
                $dataTables->setRowsPerPage(-1); // show all items
            }
            else {
                $this->addJavascript('
                    // button add style="display: none;"
                    $("#delete-selected").css("display", "none");
                ', false);

                $dataTables->disableColumnsSort(array(count($templateData['headers'])));
                $dataTables->setColumnsNotHideResponsive(array(count($templateData['headers'])));
                $dataTables->setRowsPerPage($gSettingsManager->getInt('inventory_items_per_page'));
            }
            $dataTables->createJavascript(count($templateData['rows']), count($templateData['headers']));
            $dataTables->setColumnAlignByArray($templateData['column_align']);
        }
        else {
            $templateData = $this->prepareData('print');
        }
        
        $this->smarty->assign('list', $templateData);
        $this->smarty->assign('print', $this->printView);
        $this->pageContent .= $this->smarty->fetch('modules/inventory.list.tpl');
    }

    /**
     * Check if the keeper is authorized to edit spezific item data
     * 
     * @param int|null $keeper 			The user ID of the keeper
     * @return bool 					true if the keeper is authorized
     */
    private function isKeeperAuthorizedToEdit(?int $keeper = null): bool
    {
        global $gSettingsManager, $gCurrentUser;
        if (($gSettingsManager->getInt('inventory_module_enabled') !== 3 && $gSettingsManager->getBool('inventory_allow_keeper_edit'))  || ($gSettingsManager->getInt('inventory_module_enabled') === 3 && $gCurrentUser->isAdministratorInventory())) {
            if (isset($keeper) && $keeper === $gCurrentUser->getValue('usr_id')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the current user is the keeper of an item.
     * This method checks if the current user is listed as a keeper in the inventory item data.
     *
     * @return bool Returns true if the current user is a keeper, false otherwise.
     */
    private function isCurrentUserKeeper(): bool
    {
        global $gCurrentUser, $gDb;

        $sql = 'SELECT COUNT(*) as count FROM '.TBL_INVENTORY_ITEM_DATA.' WHERE ind_value = ? AND ind_inf_id = ?';
        $params = array($gCurrentUser->getValue('usr_id'), $this->itemsData->getProperty('KEEPER', 'inf_id'));
        $result =$gDb->queryPrepared($sql, $params);
        $row = $result->fetch();
        if ($row['count'] > 0) {
            return true;
        }
        return false;

    }

    /**
     * Populate the inventory table with the data of the inventory items.
     * This method supports various output formats and fills the table based on the
     * provided display mode. The mode parameter allows selecting different table
     * representations such as HTML, PDF, CSV, ODS, or XLSX.
     *
     * @param string $mode Mode of the table (html, pdf, csv, ods, xlsx)
     * @return array Returns an array with the following keys:
     *               - column_align: array indicating the alignment for each column
     *               - headers: array of header labels for the table
     *               - export_headers: array of headers used for export formats
     *               - rows: array containing all the table rows data
     *               - strikethroughs: array indicating which rows should have strikethrough formatting
     * @throws Exception
     */
    public function prepareData(string $mode = 'html') : array
    {
        global $gCurrentUser, $gL10n, $gDb, $gCurrentOrganization, $gProfileFields, $gCurrentSession, $gSettingsManager;

        // Initialize the result array
        $preparedData = array(
            'column_align'    => array(),
            'headers'         => array(),
            'export_headers'  => array(),
            'rows'            => array(),
            'strikethroughs'  => array()
        );

        // Set default alignment and headers for the first column (abbreviation)
        $columnAlign[] = ($this->getFilterItems === 2) ? 'center' : 'end';
        $headers     =  ($this->getFilterItems === 2) ? array(0 => '<input type="checkbox" id="select-all" data-bs-toggle="tooltip" data-bs-original-title="' . $gL10n->get('SYS_SELECT_ALL') . '"/>') : array();
        $exportHeaders = array();
        $columnNumber = 1;
        //array with the internal field names of the lend fields
        $lendFieldNames = array('IN_INVENTORY', 'LAST_RECEIVER', 'RECEIVED_ON', 'RECEIVED_BACK_ON');

        // Build headers and column alignment for each item field
        foreach ($this->itemsData->getItemFields() as $itemField) {
            $infNameIntern = $itemField->getValue('inf_name_intern');
            $columnHeader  = $this->itemsData->getProperty($infNameIntern, 'inf_name');

            if($gSettingsManager->GetBool('inventory_items_disable_lending') && in_array($infNameIntern, $lendFieldNames)) {
                continue; // skip lending fields if lending is disabled
            }

            // For the first column, add specific header configurations for export modes
            if ($columnNumber === 1) {
                if ($this->getFilterItems === 2) {
                    $columnAlign[] = 'end';
                }
                
                if (in_array($mode, ['csv', 'ods', 'xlsx'])) {
                    $exportHeaders[$gL10n->get('SYS_ABR_NO')] = 'string';
                }
                else {
                    $headers[] = $gL10n->get('SYS_ABR_NO');
                }
            }

            // Decide alignment based on inf_type
            switch ($this->itemsData->getProperty($infNameIntern, 'inf_type')) {
                case 'CHECKBOX':
                case 'RADIO_BUTTON':
                case 'GENDER':
                    $columnAlign[] = 'center';
                    break;
                case 'NUMBER':
                case 'DECIMAL':
                    $columnAlign[] = 'end';
                    break;
                default:
                    $columnAlign[] = 'start';
                    break;
            }

            // Add header depending on mode
            if (in_array($mode, ['csv', 'ods', 'xlsx'])) {
                $exportHeaders[$columnHeader] = 'string';
            } else {
                $headers[] = $columnHeader;
            }

            $columnNumber++;
        }

        $preparedData['headers']         = $headers;
        $preparedData['export_headers']  = $exportHeaders;
        $preparedData['column_align']    = $columnAlign;

        // Create a user object for later use
        $user = new User($gDb, $gProfileFields);

        $rows = array();
        $strikethroughs = array();
        $listRowNumber = 1;
        $actionsHeaderAdded = false;

        // Iterate over each item to fill the table rows
        foreach ($this->itemsData->getItems() as $item) {
            $this->itemsData->readItemData($item['ini_uuid']);
            $rowValues = array();
            $rowValues['item_uuid'] = $item['ini_uuid'];
            $strikethrough = $item['ini_former'];
            $columnNumber = 1;

            foreach ($this->itemsData->getItemFields() as $itemField) {
                $infNameIntern = $itemField->getValue('inf_name_intern');

                if($gSettingsManager->GetBool('inventory_items_disable_lending') && in_array($infNameIntern, $lendFieldNames)) {
                    continue; // skip lending fields if lending is disabled
                }

                // Apply filters for CATEGORY and KEEPER
                if (
                    ($this->getFilterCategoryUUID !== '' && $infNameIntern === 'CATEGORY' && $this->getFilterCategoryUUID != $this->itemsData->getValue($infNameIntern, 'database')) ||
                    ($this->getFilterKeeper !== 0 && $infNameIntern === 'KEEPER' && $this->getFilterKeeper != $this->itemsData->getValue($infNameIntern)) ||
                    ($this->getFilterItems === 0 && $item['ini_former']) ||
                    ($this->getFilterItems === 1 && !$item['ini_former'])
                ) {
                    // skip to the next iteration of the next-outer loop
                    continue 2;
                }

                if ($columnNumber === 1) {
                    if ($this->getFilterItems === 2) {
                        $rowValues['data'][] = '<input type="checkbox"/>';
                    }
                    $rowValues['data'][] = $listRowNumber;
                }

                $content = $this->itemsData->getValue($infNameIntern, 'database');
                $infType = $this->itemsData->getProperty($infNameIntern, 'inf_type');

                // Process ITEMNAME column
                if ($infNameIntern === 'ITEMNAME' && strlen($content) > 0) {
                    if ($mode === 'html' && (($gCurrentUser->isAdministratorInventory() || $this->isKeeperAuthorizedToEdit((int)$this->itemsData->getValue('KEEPER', 'database'))) && !$item['ini_former'])) {
                        $content = '<a href="' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_edit', 'item_uuid' => $item['ini_uuid'], 'item_former' => $item['ini_former'])) . '">' . SecurityUtils::encodeHTML($content) . '</a>';
                    } else {
                        $content = SecurityUtils::encodeHTML($content);
                    }
                }

                // Process KEEPER column
                if ($infNameIntern === 'KEEPER' && strlen($content) > 0) {
                    $found = $user->readDataById($content);
                    if (!$found) {
                        $orgName = '"' . $gCurrentOrganization->getValue('org_longname') . '"';
                        $content = $mode === 'html'
                            ? '<i>' . SecurityUtils::encodeHTML(StringUtils::strStripTags($gL10n->get('SYS_NOT_MEMBER_OF_ORGANIZATION', [$orgName]))) . '</i>'
                            : '<i>' . $gL10n->get('SYS_NOT_MEMBER_OF_ORGANIZATION', [$orgName]) . '</i>';
                    } else {
                        if ($mode === 'html') {
                            $content = '<a href="' . SecurityUtils::encodeUrl(
                                ADMIDIO_URL . FOLDER_MODULES . '/profile/profile.php',
                                ['user_uuid' => $user->getValue('usr_uuid')]
                            ) . '">' . $user->getValue('LAST_NAME') . ', ' . $user->getValue('FIRST_NAME') . '</a>';
                        } else {
                            $sql = $this->itemsData->getSqlOrganizationsUsersComplete();
                            $result = $gDb->queryPrepared($sql);
                            $content = $user->getValue('LAST_NAME') . ', ' . $user->getValue('FIRST_NAME');
                            while ($row = $result->fetch()) {
                                if ($row['usr_id'] == $user->getValue('usr_id')) {
                                    $content = $row['name'];
                                    break;
                                }
                            }
                        }
                    }
                }

                // Process LAST_RECEIVER column
                if ($infNameIntern === 'LAST_RECEIVER' && strlen($content) > 0 && is_numeric($content)) {
                    $found = $user->readDataById($content);
                    if ($found) {
                        if ($mode === 'html') {
                            $content = '<a href="' . SecurityUtils::encodeUrl(
                                ADMIDIO_URL . FOLDER_MODULES . '/profile/profile.php',
                                ['user_uuid' => $user->getValue('usr_uuid')]
                            ) . '">' . $user->getValue('LAST_NAME') . ', ' . $user->getValue('FIRST_NAME') . '</a>';
                        } else {
                            $sql = $this->itemsData->getSqlOrganizationsUsersComplete();
                            $result = $gDb->queryPrepared($sql);
                            $content = $user->getValue('LAST_NAME') . ', ' . $user->getValue('FIRST_NAME');
                            while ($row = $result->fetch()) {
                                if ($row['usr_id'] == $user->getValue('usr_id')) {
                                    $content = $row['name'];
                                    break;
                                }
                            }
                        }
                    }
                }

                // Format content based on the field type
                if ($infType === 'CHECKBOX') {
                    $content = ($content != 1) ? 0 : 1;
                    $content = in_array($mode, ['csv', 'pdf', 'xlsx', 'ods'])
                        ? ($content == 1 ? $gL10n->get('SYS_YES') : $gL10n->get('SYS_NO'))
                        : $this->itemsData->getHtmlValue($infNameIntern, $content);
                } elseif (in_array($infType, ['DATE', 'DROPDOWN'])) {
                    $content = $this->itemsData->getHtmlValue($infNameIntern, $content);
                } elseif ($infType === 'RADIO_BUTTON') {
                    $content = $mode === 'html'
                        ? $this->itemsData->getHtmlValue($infNameIntern, $content)
                        : $this->itemsData->getValue($infNameIntern, 'database');
                } elseif ($infType === 'CATEGORY') {
                    $content = $mode === 'database'
                        ? $this->itemsData->getValue($infNameIntern, 'database')
                        : $this->itemsData->getHtmlValue($infNameIntern, $content);
                }

                $rowValues['data'][] = ($strikethrough && !in_array($mode, ['csv', 'ods', 'xlsx']))
                    ? '<s>' . $content . '</s>'
                    : $content;
                $columnNumber++;
            }

            // Append admin action column for HTML mode
            if ($mode === 'html') {
                $historyButton = ChangelogService::displayHistoryButtonTable(
                    'inventory_items,inventory_item_data,inventory_item_lend_data',
                    $gCurrentUser->isAdministratorInventory(),
                    ['uuid' => $item['ini_uuid']]
                );

                if (!empty($historyButton)) {
                    $rowValues['actions'][] = $historyButton;
                }

                if ($gCurrentUser->isAdministratorInventory() || $this->isKeeperAuthorizedToEdit((int)$this->itemsData->getValue('KEEPER', 'database'))) {
                    if (($gCurrentUser->isAdministratorInventory() || $this->isKeeperAuthorizedToEdit((int)$this->itemsData->getValue('KEEPER', 'database'))) && !$item['ini_former']) {
                        // Add edit action
                        $rowValues['actions'][] = array(
                            'url' => SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php',array('mode' => 'item_edit', 'item_uuid' => $item['ini_uuid'], 'item_former' => $item['ini_former'])),
                            'icon' => 'bi bi-pencil-square',
                            'tooltip' => $gL10n->get('SYS_INVENTORY_ITEM_EDIT')
                        );

                        // Add lend action
                        if (!$item['ini_former'] && !$gSettingsManager->GetBool('inventory_items_disable_lending')) {
                            // check if the item is in inventory
                            if ($this->itemsData->getValue('IN_INVENTORY', 'database') === '1') {
                                $itemLended = false;
                                $icon ='bi bi-box-arrow-right';
                                $tooltip = $gL10n->get('SYS_INVENTORY_ITEM_LEND');
                            }
                            else {
                                $itemLended = true;
                                $icon = 'bi bi-box-arrow-in-left';
                                $tooltip = $gL10n->get('SYS_INVENTORY_ITEM_RETURN');
                            }
                            $rowValues['actions'][] = array(
                                'url' => SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php',array('mode' => 'item_edit_lend', 'item_uuid' => $item['ini_uuid'], 'item_lended' => $itemLended)),
                                'icon' => $icon,
                                'tooltip' =>$tooltip
                            );
                        }

                        // Add copy action
                        $rowValues['actions'][] = array(
                            'url' => SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php',array('mode' => 'item_edit', 'item_uuid' => $item['ini_uuid'], 'copy' => true)),
                            'icon' => 'bi bi-file-earmark-plus',
                            'tooltip' => $gL10n->get('SYS_INVENTORY_ITEM_COPY')
                        );
                    }

                    if ($item['ini_former']) {
                        $dataMessage = ($this->isKeeperAuthorizedToEdit((int)$this->itemsData->getValue('KEEPER', 'database'))) ? $gL10n->get('SYS_INVENTORY_KEEPER_ITEM_UNDO_FORMER_DESC', array('SYS_INVENTORY_ITEM_UNDO_FORMER_CONFIRM')) : $gL10n->get('SYS_INVENTORY_ITEM_UNDO_FORMER_CONFIRM');
                        // Add undo former action
                        $rowValues['actions'][] = array(
                            'dataHref' => 'callUrlHideElement(\'adm_inventory_item_' . $item['ini_uuid'] . '\', \'' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_undo_former', 'item_uuid' => $item['ini_uuid'], 'item_former' => $item['ini_former'])) . '\', \'' . $gCurrentSession->getCsrfToken() . '\')',
                            'dataMessage' => $dataMessage,
                            'icon' => 'bi bi-eye',
                            'tooltip' => $gL10n->get('SYS_INVENTORY_ITEM_UNDO_FORMER')
                        );
                    }

                    if ($this->isKeeperAuthorizedToEdit((int)$this->itemsData->getValue('KEEPER', 'database'))) {
                        if (!$item['ini_former']) {
                            // Add make former action
                            $rowValues['actions'][] = array(
                                'popup' => true,
                                'dataHref' => SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_delete_keeper_explain_msg', 'item_uuid' => $item['ini_uuid'])),
                                'icon' => 'bi bi-trash',
                                'tooltip' => $gL10n->get('SYS_INVENTORY_ITEM_DELETE')
                            );
                        }
                    }
                    else {
                        // Add delete/make former action
                        $rowValues['actions'][] = array(
                            'popup' => true,
                            'dataHref' => SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_delete_explain_msg', 'item_uuid' => $item['ini_uuid'], 'item_former' => $item['ini_former'])),
                            'icon' => 'bi bi-trash',
                            'tooltip' => $gL10n->get('SYS_INVENTORY_ITEM_DELETE')
                        );
                    }

                    // add actions column to header
                    if (!$actionsHeaderAdded && ($gCurrentUser->isAdministratorInventory() || $this->isKeeperAuthorizedToEdit((int)$this->itemsData->getValue('KEEPER', 'database')))) {
                        $actionsHeaderAdded = true;
                        $preparedData['column_align'][] = 'end';
                        $preparedData['headers'][] = '&nbsp;';
                    }
                }
            }

            // Filter rows based on filter string
            $showRow = true;

            if ($mode !== 'html') {
                $showRow = ($this->getFilterString === '');
                if ($this->getFilterString !== '') {
                    $showRowException = false;
                    $filterArray = array_map('trim', explode(',', $this->getFilterString));
                    $filterColumnValues = array_map(function ($value) {
                        $parts = explode(',', $value);
                        return count($parts) > 1 ? implode(',', array_slice($parts, 0, 2)) : $value;
                    }, $rowValues);

                    foreach ($filterArray as $filterString) {
                        if (strpos($filterString, '-') === 0) {
                            $cleanFilter = substr($filterString, 1);
                            if (stripos(implode('', $filterColumnValues), $cleanFilter) !== false) {
                                $showRowException = true;
                            }
                        }
                        if (stripos(implode(' ', $filterColumnValues), $filterString) !== false) {
                            $showRow = true;
                        }
                    }
                    if ($showRowException) {
                        $showRow = false;
                    }
                }
            }

            if ($showRow) {
                $rows[] = $rowValues;
                if (in_array($mode, ['csv', 'xlsx', 'ods'])) {
                    $strikethroughs[] = $strikethrough;
                }
            }

            $listRowNumber++;
        }

        // check if actionHeader was set, if so, make shure every row has an actions column
        if ($actionsHeaderAdded) {
            foreach ($rows as &$row) {
                if (!isset($row['actions'])) {
                    $row['actions'] = array();
                }
            }
        }
        
        $preparedData['rows'] = $rows;
        $preparedData['strikethroughs'] = $strikethroughs;

        return $preparedData;
    }

    /**
     * Populate the inventory table with the data of the inventory items in HTML mode.
     * This method uses a predefined ItemsData element and always returns the HTML version
     * of the table.
     *
     * @return array Returns an array with the following keys:
     *               - headers: array of header labels for the table
     *               - column_align: array indicating the alignment for each column
     *               - rows: array containing all the table rows data
     *               - strikethroughs: array indicating which rows should have strikethrough formatting
     * @throws Exception
     */
    public function prepareDataProfile(ItemsData $itemsData, string $itemFieldFilter = 'KEEPER') : array
    {
        global $gCurrentUser, $gL10n, $gDb, $gCurrentOrganization, $gProfileFields, $gCurrentSession, $gSettingsManager;

        // Create a user object for later use
        $user = new User($gDb, $gProfileFields);

        // Initialize the result array
        $preparedData = array(
            'headers'         => array(),
            'column_align'    => array(),
            'rows'            => array(),
            'strikethroughs'  => array()
        );

        // Build headers and set column alignment (only for HTML mode)
        $columnAlign[] = 'end'; // first column alignment
        $headers     = array();
        $columnNumber = 1;
        //array with the internal field names of the lend fields
        $lendFieldNames = array('IN_INVENTORY', 'LAST_RECEIVER', 'RECEIVED_ON', 'RECEIVED_BACK_ON');

        // create array with all column heading values
        $profileItemFields = array('ITEMNAME');

        foreach (explode(',', $gSettingsManager->getString('inventory_profile_view')) as $itemField) {
            // we are in the keeper view, so we dont need the keeper field in the table
            if ($itemField !== $itemFieldFilter && $itemField !== "0") {
                $profileItemFields[] = $itemField;
            }
        }

        foreach ($itemsData->getItemFields() as $itemField) {
            $infNameIntern = $itemField->getValue('inf_name_intern');

            if (!in_array($infNameIntern, $profileItemFields, true) || ($gSettingsManager->GetBool('inventory_items_disable_lending') && in_array($infNameIntern, $lendFieldNames))) {
                continue;
            }

            $columnHeader  = $itemsData->getProperty($infNameIntern, 'inf_name');

            // Decide alignment based on field type
            switch ($itemsData->getProperty($infNameIntern, 'inf_type')) {
                case 'CHECKBOX':
                case 'RADIO_BUTTON':
                case 'GENDER':
                    $columnAlign[] = 'center';
                    break;
                case 'NUMBER':
                case 'DECIMAL':
                    $columnAlign[] = 'end';
                    break;
                default:
                    $columnAlign[] = 'start';
                    break;
            }

            // For the first column, add a specific header
            if ($columnNumber === 1) {
                $headers[] = $gL10n->get('SYS_ABR_NO');
            }

            $headers[] = $columnHeader;
            $columnNumber++;
        }

        // Append the admin action column
        if ($gCurrentUser->isAdministratorInventory() || $this->isKeeperAuthorizedToEdit((int)$this->itemsData->getValue('KEEPER', 'database'))) {
            $columnAlign[] = 'end';
            $headers[]     = '&nbsp;';
        }

        $preparedData['headers']      = $headers;
        $preparedData['column_align'] = $columnAlign;

        // Build table rows from the predefined ItemsData element (HTML mode only)
        $rows          = array();
        $strikethroughs = array();
        $listRowNumber = 1;

        foreach ($itemsData->getItems() as $item) {
            $itemsData->readItemData($item['ini_uuid']);
            $rowValues     = array();
            $rowValues['item_uuid'] = $item['ini_uuid'];
            $strikethrough = $item['ini_former'];
            $columnNumber  = 1;

            foreach ($itemsData->getItemFields() as $itemField) {
                $infNameIntern = $itemField->getValue('inf_name_intern');

                if (!in_array($infNameIntern, $profileItemFields, true) || ($gSettingsManager->GetBool('inventory_items_disable_lending') && in_array($infNameIntern, $lendFieldNames))) {
                    continue;
                }
                
                // For the first column, add a row number
                if ($columnNumber === 1) {
                    $rowValues['data'][] = $listRowNumber;
                }

                $content = $itemsData->getValue($infNameIntern, 'database');
                $infType = $itemsData->getProperty($infNameIntern, 'inf_type');

                // Process the KEEPER column
                if ($infNameIntern === 'KEEPER' && strlen($content) > 0) {
                    $found = $user->readDataById($content);
                    if (!$found) {
                        $orgName = '"' . $gCurrentOrganization->getValue('org_longname') . '"';
                        $content = '<i>' . SecurityUtils::encodeHTML(StringUtils::strStripTags($gL10n->get('SYS_NOT_MEMBER_OF_ORGANIZATION', [$orgName]))) . '</i>';
                    } else {
                        $content = '<a href="' . SecurityUtils::encodeUrl(
                            ADMIDIO_URL . FOLDER_MODULES . '/profile/profile.php',
                            ['user_uuid' => $user->getValue('usr_uuid')]
                        ) . '">' . $user->getValue('LAST_NAME') . ', ' . $user->getValue('FIRST_NAME') . '</a>';
                    }
                }

                // Process the LAST_RECEIVER column
                if ($infNameIntern === 'LAST_RECEIVER' && strlen($content) > 0 && is_numeric($content)) {
                    $found = $user->readDataById($content);
                    if ($found) {
                        $content = '<a href="' . SecurityUtils::encodeUrl(
                            ADMIDIO_URL . FOLDER_MODULES . '/profile/profile.php',
                            ['user_uuid' => $user->getValue('usr_uuid')]
                        ) . '">' . $user->getValue('LAST_NAME') . ', ' . $user->getValue('FIRST_NAME') . '</a>';
                    }
                }

                // Format the content based on the field type
                if ($infType === 'CHECKBOX') {
                    $content = ($content != 1) ? 0 : 1;
                    $content = $itemsData->getHtmlValue($infNameIntern, $content);
                } elseif (in_array($infType, ['DATE', 'DROPDOWN'])) {
                    $content = $itemsData->getHtmlValue($infNameIntern, $content);
                } elseif ($infType === 'RADIO_BUTTON') {
                    $content = $itemsData->getHtmlValue($infNameIntern, $content);
                } elseif ($infType === 'CATEGORY') {
                    $content = $itemsData->getHtmlValue($infNameIntern, $content);
                }

                $rowValues['data'][] = ($strikethrough) ? '<s>' . $content . '</s>' : $content;
                $columnNumber++;
            }

            // Append admin action column
            $historyButton = ChangelogService::displayHistoryButtonTable(
                'inventory_items,inventory_item_data,inventory_item_lend_data',
                $gCurrentUser->isAdministratorInventory(),
                ['uuid' => $item['ini_uuid']]
            );

            if (!empty($historyButton)) {
                $rowValues['actions'][] = $historyButton;
            }

            if ($gCurrentUser->isAdministratorInventory() || $this->isKeeperAuthorizedToEdit((int)$this->itemsData->getValue('KEEPER', 'database'))) {
                if ($gCurrentUser->isAdministratorInventory() || ($this->isKeeperAuthorizedToEdit((int)$this->itemsData->getValue('KEEPER', 'database')) && !$item['ini_former'])) {
                    // Add edit action
                    $rowValues['actions'][] = array(
                        'url' => SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php',array('mode' => 'item_edit', 'item_uuid' => $item['ini_uuid'], 'item_former' => $item['ini_former'])),
                        'icon' => 'bi bi-pencil-square',
                        'tooltip' => $gL10n->get('SYS_INVENTORY_ITEM_EDIT')
                    );

                    // Add lend action
                    if (!$item['ini_former'] && !$gSettingsManager->GetBool('inventory_items_disable_lending')) {
                        // check if the item is in inventory
                        if ($this->itemsData->getValue('IN_INVENTORY', 'database') === '1') {
                            $itemLended = false;
                            $icon ='bi bi-box-arrow-right';
                            $tooltip = $gL10n->get('SYS_INVENTORY_ITEM_LEND');
                        }
                        else {
                            $itemLended = true;
                            $icon = 'bi bi-box-arrow-in-left';
                            $tooltip = $gL10n->get('SYS_INVENTORY_ITEM_RETURN');
                        }
                        $rowValues['actions'][] = array(
                            'url' => SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php',array('mode' => 'item_edit_lend', 'item_uuid' => $item['ini_uuid'], 'item_lended' => $itemLended)),
                            'icon' => $icon,
                            'tooltip' =>$tooltip
                        );
                    }

                    // Add copy action
                    $rowValues['actions'][] = array(
                        'url' => SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php',array('mode' => 'item_edit', 'item_uuid' => $item['ini_uuid'], 'copy' => true)),
                        'icon' => 'bi bi-file-earmark-plus',
                        'tooltip' => $gL10n->get('SYS_INVENTORY_ITEM_COPY')
                    );
                }

                if ($item['ini_former']) {
                    $dataMessage = ($this->isKeeperAuthorizedToEdit((int)$this->itemsData->getValue('KEEPER', 'database'))) ? $gL10n->get('SYS_INVENTORY_KEEPER_ITEM_UNDO_FORMER_DESC', array('SYS_INVENTORY_ITEM_UNDO_FORMER_CONFIRM')) : $gL10n->get('SYS_INVENTORY_ITEM_UNDO_FORMER_CONFIRM');
                    // Add undo former action
                    $rowValues['actions'][] = array(
                        'dataHref' => 'callUrlHideElement(\'adm_inventory_item_' . $item['ini_uuid'] . '\', \'' . SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_undo_former', 'item_uuid' => $item['ini_uuid'], 'item_former' => $item['ini_former'])) . '\', \'' . $gCurrentSession->getCsrfToken() . '\')',
                        'dataMessage' => $dataMessage,
                        'icon' => 'bi bi-eye',
                        'tooltip' => $gL10n->get('SYS_INVENTORY_ITEM_UNDO_FORMER')
                    );
                }

                if ($this->isKeeperAuthorizedToEdit((int)$this->itemsData->getValue('KEEPER', 'database'))) {
                    if (!$item['ini_former']) {
                        // Add make former action
                        $rowValues['actions'][] = array(
                            'popup' => true,
                            'dataHref' => SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_delete_keeper_explain_msg', 'item_uuid' => $item['ini_uuid'])),
                            'icon' => 'bi bi-trash',
                            'tooltip' => $gL10n->get('SYS_INVENTORY_ITEM_DELETE')
                        );
                    }
                }
                else {
                    // Add delete/make former action
                    $rowValues['actions'][] = array(
                        'popup' => true,
                        'dataHref' => SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/inventory.php', array('mode' => 'item_delete_explain_msg', 'item_uuid' => $item['ini_uuid'], 'item_former' => $item['ini_former'])),
                        'icon' => 'bi bi-trash',
                        'tooltip' => $gL10n->get('SYS_INVENTORY_ITEM_DELETE')
                    );
                }
            }

            $rows[] = $rowValues;
            $strikethroughs[] = $strikethrough;
            $listRowNumber++;
        }

        $preparedData['rows'] = $rows;
        $preparedData['strikethroughs'] = $strikethroughs;

        return $preparedData;
    }
}