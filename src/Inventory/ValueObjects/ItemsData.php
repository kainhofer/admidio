<?php

namespace Admidio\Inventory\ValueObjects;

// Admidio namespaces
use Admidio\Infrastructure\Database;
use Admidio\Infrastructure\Exception;
use Admidio\Infrastructure\Email;
use Admidio\Infrastructure\Image;
use Admidio\Infrastructure\Language;
use Admidio\Infrastructure\Entity\Entity;
use Admidio\Infrastructure\Utils\StringUtils;
use Admidio\Inventory\Entity\Item;
use Admidio\Inventory\Entity\ItemData;
use Admidio\Inventory\Entity\ItemField;
use Admidio\Inventory\Entity\ItemLendData;
use Admidio\Categories\Entity\Category;

// PHP namespaces
use DateTime;

/**
 * @brief Reads the user fields structure out of database and give access to it
 *
 * When an object is created than the actual profile fields structure will
 * be read. In addition to this structure you can read the user values for
 * all fields if you call @c readUserData . If you read field values than
 * you will get the formatted output. It's also possible to set user data and
 * save this data to the database
 *
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 */
class ItemsData
{
    private bool $mItemCreated = false;                   ///< flag if a new item was created
    private bool $mItemChanged = false;                   ///< flag if a new item was changed
    private bool $mItemDeleted = false;                   ///< flag if a item was deleted
    private bool $mItemMadeFormer = false;                ///< flag if a item was made to former item
    private bool $mItemUndoMadeFormer = false;             ///< flag if a item was made to normal again
    private bool $mItemImported = false;                   ///< flag if a item was imported
    private bool $showFormerItems = true;               ///< if true, than former items will be showed
    private int $organizationId = -1;                ///< ID of the organization for which the item field structure should be read
    private array $lendFieldNames = array('LAST_RECEIVER', 'RECEIVED_ON', 'RECEIVED_BACK_ON');  ///< array with the internal field names of the lend fields

    /**
     * @var Database An object of the class Database for communication with the database
     */
    protected Database $mDb;
    /**
     * @var array<string,ItemField> Array with all profile fields represented by a user fields objects.
     *      The key is the usf_name_intern and the value is an object of class ItemField
     *      $mItemFields = [
     *          'LAST_NAME' => {ItemField}
     *          'FIRST_NAME' => {ItemField}
     *          'STREET' => {ItemField}
     *      ]
     */
    protected array $mItemFields = array();
    /**
     * @var array<string,ItemField> Array with all profile fields represented by a user fields objects.
     *      The key is the usf_name_intern and the value is an object of class ItemField
     *      $itemFieldsSort = [
     *          'LAST_NAME' => 'inf_sequence'
     *          'FIRST_NAME' => 'inf_sequence'
     *          'STREET' => 'inf_sequence'
     *      ]
     */
    protected array $itemFieldsSort = array();
    /**
     * @var array<int,ItemData> Array with all user data objects
     */
    protected array $mItemData = array();
    /**
     * @var array<int,ItemData> Array with all changed item data objects for notification
     */
    protected array $mChangedItemData = array();
    /**
     * @var array<int,Item> Array with all item objects
     */
    protected array $mItems = array();
    /**
     * @var int UserId of the current user of this object
     */
    protected int $mItemId = 0;
    /**
     * @var string UUID of the current item of this object
     */
    protected string $mItemUUID = '';
    /**
     * @var bool flag if a value of one field had changed
     */
    protected bool $columnsValueChanged = false;

    /**
     * constructor that will initialize variables and read the profile field structure
     * @param Database $database Database object (should be **$gDb**)
     * @param int $organizationId The id of the organization for which the profile field structure should be read
     * @throws Exception
     */
    public function __construct(Database $database, int $organizationId)
    {
        $this->mDb = &$database;
        $this->organizationId = $organizationId;
        $this->readItemFields();
    }

    /**
     * A wakeup add the current database object to this class
     */
    public function __wakeup()
    {
        global $gDb;

        if ($gDb instanceof Database) {
            $this->mDb = $gDb;
        }
    }

    /**
     * Item data of all item fields will be initialized
     * the fields array will not be renewed
     * 
     * @return void
     */
    public function clearItemData(): void
    {
        $this->mChangedItemData = array();
        $this->mItemData = array();
        $this->mItemId = 0;
        $this->columnsValueChanged = false;
    }

    /**
     * Reads the item fields structure out of database table @b adm_inventory_fields
     * and adds an object for each field structure to the @b mItemFields array.
     * 
     * @param string $orderBy           The field by which the item fields should be sorted
     * @return void
     */
    public function readItemFields($orderBy = 'inf_id'): void
    {
        // first initialize existing data
        $this->mItemFields = array();
        $this->clearItemData();

        $sql = 'SELECT * FROM ' . TBL_INVENTORY_FIELDS . '
                WHERE (inf_org_id IS NULL OR inf_org_id = ?)
                ORDER BY ' . $orderBy . ';';
        $statement = $this->mDb->queryPrepared($sql, array($this->organizationId));

        while ($row = $statement->fetch()) {
            if (!array_key_exists($row['inf_name_intern'], $this->mItemFields)) {
                $this->mItemFields[$row['inf_name_intern']] = new ItemField($this->mDb);
            }
            $this->mItemFields[$row['inf_name_intern']]->setArray($row);
            $this->itemFieldsSort[$row['inf_name_intern']] = $row['inf_sequence'];
        }

        array_multisort($this->itemFieldsSort, SORT_ASC, $this->mItemFields);
    }

    /**
     * Reads the item data of all item fields out of database table @b adm_inventory_manager_data
     * and @b adm_inventory_manager_items_lend
     * and adds an object for each field data to the @b mItemData array.
     * If profile fields structure wasn't read, this will be done before.
     * 
     * @param string $itemUUID               The uuid of the item for which the item data should be read.
     * @return void
     */
    public function readItemData(string $itemUUID = ''): void
    {
        if (count($this->mItemFields) === 0) {
            $this->readItemFields();
        }

        $this->mItemData = array();

        if ($itemUUID !== '') {
            $item = new Item($this->mDb, $this);
            $item->readDataByUuid($itemUUID);
            $itemId = $item->getValue('ini_id');

            // remember the item
            $this->mItemId = $itemId;
            $this->mItemUUID = $itemUUID;

            // read all item data
            $sql = 'SELECT * FROM ' . TBL_INVENTORY_ITEM_DATA . '
                    INNER JOIN ' . TBL_INVENTORY_FIELDS . '
                        ON inf_id = ind_inf_id
                    WHERE ind_ini_id = ?;';
            $itemDataStatement = $this->mDb->queryPrepared($sql, array($itemId));

            while ($row = $itemDataStatement->fetch()) {
                if (!array_key_exists($row['ind_inf_id'], $this->mItemData)) {
                    $this->mItemData[$row['ind_inf_id']] = new ItemData($this->mDb, $this, $row['ind_inf_id']);
                }
                $this->mItemData[$row['ind_inf_id']]->setArray($row);
            }

            // read all item lend data
            $sql = 'SELECT * FROM ' . TBL_INVENTORY_ITEM_LEND_DATA . '
                    INNER JOIN ' . TBL_INVENTORY_FIELDS . '
                        ON inf_id = inl_inf_id
                    WHERE inl_ini_id = ?;';
            $itemLendStatement = $this->mDb->queryPrepared($sql, array($itemId));
            
            while ($row = $itemLendStatement->fetch()) {
                if (!array_key_exists($row['inl_inf_id'], $this->mItemData)) {
                    $this->mItemData[$row['inl_inf_id']] = new ItemLendData($this->mDb, $this, $row['inl_inf_id']);
                }
                $this->mItemData[$row['inl_inf_id']]->setArray($row);
            }        } else {
            $this->mItemCreated = true;
        }
    }

    /**
     * Reads the items out of database table @b adm_inventory_manager_items
     * and stores the values to the @b items array.
     * 
     * @return void
     */
    public function readItems(): void
    {
        // first initialize existing data
        $this->mItems = array();

        $sqlWhereCondition = '';
        if (!$this->showFormerItems) {
            $sqlWhereCondition .= 'AND ini_former = 0';
        }

        $sql = 'SELECT DISTINCT ini_id, ini_uuid, ini_cat_id, ini_former FROM ' . TBL_INVENTORY_ITEMS . '
                INNER JOIN ' . TBL_INVENTORY_ITEM_DATA . '
                    ON ind_ini_id = ini_id
                WHERE ini_org_id IS NULL
                OR ini_org_id = ?
                ' . $sqlWhereCondition . ';';
        $statement = $this->mDb->queryPrepared($sql, array($this->organizationId));

        while ($row = $statement->fetch()) {
            $this->mItems[] = array('ini_id' => $row['ini_id'], 'ini_uuid' => $row['ini_uuid'], 'ini_cat_id' => $row['ini_cat_id'], 'ini_former' => $row['ini_former']);
        }
    }

    /**
     * Reads the items for a user out of database table @b adm_inventory_manager_items
     * and stores the values to the @b items array.
     * 
     * @param int $userId               The id of the user for which the items should be read.
     * @param array $fieldNames         The internal unique profile field names for which the items should be read
     * @return void
     */
    public function readItemsByUser($userId, $fieldNames = array('KEEPER')): void
    {
        // first initialize existing data
        $this->mItems = array();

        $sqlWhereCondition = '';
        if (!$this->showFormerItems) {
            $sqlWhereCondition .= 'AND ini_former = 0';
        }

        $sqlImfIds = 'AND (';
        if (count($fieldNames) > 0) {
            foreach ($fieldNames as $fieldNameIntern) {
                $sqlImfIds .= 'inf_id = ' . $this->getProperty($fieldNameIntern, 'inf_id') . ' OR ';
            }
            $sqlImfIds = substr($sqlImfIds, 0, -4) . ')';
        }

        // first read all item data for the given user
        $sql = 'SELECT DISTINCT ini_id, ini_uuid, ini_cat_id, ini_former FROM ' . TBL_INVENTORY_ITEM_DATA . '
                INNER JOIN ' . TBL_INVENTORY_FIELDS . '
                    ON inf_id = ind_inf_id
                    ' . $sqlImfIds . '
                INNER JOIN ' . TBL_INVENTORY_ITEMS . '
                    ON ini_id = ind_ini_id
                WHERE (ini_org_id IS NULL
                    OR ini_org_id = ?)
                AND ind_value = ?
                ' . $sqlWhereCondition . ';';
        $statement = $this->mDb->queryPrepared($sql, array($this->organizationId, $userId));

        while ($row = $statement->fetch()) {
            $this->mItems[] = array('ini_id' => $row['ini_id'], 'ini_uuid' => $row['ini_uuid'], 'ini_cat_id' => $row['ini_cat_id'], 'ini_former' => $row['ini_former']);
        }

        // now read the item lend data for each item
        $sql = 'SELECT DISTINCT ini_id, ini_uuid, ini_cat_id, ini_former FROM ' . TBL_INVENTORY_ITEM_LEND_DATA . '
                INNER JOIN ' . TBL_INVENTORY_FIELDS . '
                    ON inf_id = inl_inf_id
                    ' . $sqlImfIds . '
                INNER JOIN ' . TBL_INVENTORY_ITEMS . '
                    ON ini_id = inl_ini_id
                WHERE (ini_org_id IS NULL
                    OR ini_org_id = ?)
                AND inl_value = ?
                ' . $sqlWhereCondition . ';';
        $statement = $this->mDb->queryPrepared($sql, array($this->organizationId, $userId));
        // check if a item already exists in the items array
        while ($row = $statement->fetch()) {
            // check if item already exists in the items array
            $itemExists = false;
            foreach ($this->mItems as $item) {
                if ($item['ini_id'] === $row['ini_id']) {
                    $itemExists = true;
                    break;
                }
            }
            // if item doesn't exist, then add it to the items array
            if (!$itemExists) {
                $this->mItems[] = array('ini_id' => $row['ini_id'], 'ini_uuid' => $row['ini_uuid'], 'ini_cat_id' => $row['ini_cat_id'], 'ini_former' => $row['ini_former']);
            }
        }
    }

    /**
     * Returns an array with all profile fields represented by a user fields objects.
     * The key is the usf_name_intern and the value is an object of class ProfileField
     * 
     * @return array<string,ProfileField> $mProfileFields = [
     *      'LAST_NAME' => {ProfileField}
     *      'FIRST_NAME' => {ProfileField}
     *      'STREET' => {ProfileField}
     *  ]
     */
    public function getItemFields(): array
    {
        return $this->mItemFields;
    }

    /**
     * Returns an array with all profile fields represented by a user fields objects.
     * The key is the usf_name_intern and the value is an object of class ProfileField
     * 
     * @return array<string,ProfileField> $mProfileFields = [
     *      'LAST_NAME' => {ProfileField}
     *      'FIRST_NAME' => {ProfileField}
     *      'STREET' => {ProfileField}
     *  ]
     */
    public function getItems(): array
    {
        return $this->mItems;
    }

    /**
     * Retrieves the ID of the item
     *
     * @return int The ID of the item
     */
    public function getItemId(): int
    {
        return $this->mItemId;
    }

    /**
     * Returns the item data of all item fields
     * 
     * @return array<int,Entity> Array with all item data objects
     */
    public function getItemData(): array
    {
        return $this->mItemData;
    }
    
    /**
     * Returns the value of a column from the table adm_inventory_fields for a given internal field name
     * 
     * @param string $fieldNameIntern   Expects the @b inf_name_intern of table @b adm_inventory_fields
     * @param string $column            The column name of @b adm_inventory_fields for which you want the value
     * @param string $format            Optional the format (is necessary for timestamps)
     * @param bool $withObsoleteEnries  If set to **false** then the obsolete entries of the item field will not be considered.
     * @return array|string             Returns the value for the column
     */
    public function getProperty($fieldNameIntern, $column, $format = '', bool $withObsoleteEnries = true)
    {
        if (!array_key_exists($fieldNameIntern, $this->mItemFields)) {
            // if id-field not exists then return zero
            return (strpos($column, '_id') > 0) ? 0 : '';
        }

        $value = $this->mItemFields[$fieldNameIntern]->getValue($column, $format, $withObsoleteEnries);

        return $value;
    }

    /**
     * Returns the value of a column from the table adm_inventory_fields for a given field ID
     * 
     * @param int    $fieldId           Expects the @b inf_id of table @b adm_inventory_fields
     * @param string $column            The column name of @b adm_inventory_fields for which you want the value
     * @param string $format            Optional the format (is necessary for timestamps)
     * @return string                   Returns the value for the column.
     */
    public function getPropertyById($fieldId, $column, $format = ''): string
    {
        foreach ($this->mItemFields as $field) {
            if ((int) $field->getValue('inf_id') === (int) $fieldId) {
                return $field->getValue($column, $format);
            }
        }

        return '';
    }

    /**
     * Get all users with their id, name, and address
     * 
     * @return string 					SQL query to get all users with their ID and name
     */
    public function getSqlOrganizationsUsersComplete(): string
    {
        global $gProfileFields, $gCurrentOrgId;

        return 'SELECT usr_id, CONCAT(last_name.usd_value, \', \', first_name.usd_value, COALESCE(CONCAT(\', \', postcode.usd_value),\'\'), COALESCE(CONCAT(\' \', city.usd_value),\'\'), COALESCE(CONCAT(\', \', street.usd_value),\'\') ) as name
                FROM ' . TBL_USERS . '
                JOIN ' . TBL_USER_DATA . ' as last_name ON last_name.usd_usr_id = usr_id AND last_name.usd_usf_id = ' . $gProfileFields->getProperty('LAST_NAME', 'usf_id') . '
                JOIN ' . TBL_USER_DATA . ' as first_name ON first_name.usd_usr_id = usr_id AND first_name.usd_usf_id = ' . $gProfileFields->getProperty('FIRST_NAME', 'usf_id') . '
                LEFT JOIN ' . TBL_USER_DATA . ' as postcode ON postcode.usd_usr_id = usr_id AND postcode.usd_usf_id = ' . $gProfileFields->getProperty('POSTCODE', 'usf_id') . '
                LEFT JOIN ' . TBL_USER_DATA . ' as city ON city.usd_usr_id = usr_id AND city.usd_usf_id = ' . $gProfileFields->getProperty('CITY', 'usf_id') . '
                LEFT JOIN ' . TBL_USER_DATA . ' as street ON street.usd_usr_id = usr_id AND street.usd_usf_id = ' . $gProfileFields->getProperty('ADDRESS', 'usf_id') . '
                WHERE usr_valid = true AND EXISTS (SELECT 1 FROM ' . TBL_MEMBERS . ', ' . TBL_ROLES . ', ' . TBL_CATEGORIES . ' WHERE mem_usr_id = usr_id AND mem_rol_id = rol_id AND mem_begin <= \'' . DATE_NOW . '\' AND mem_end > \'' . DATE_NOW . '\' AND rol_valid = true AND rol_cat_id = cat_id AND (cat_org_id = ' . $gCurrentOrgId . ' OR cat_org_id IS NULL)) ORDER BY last_name.usd_value, first_name.usd_value;';
    }

    /**
     * Get all users with their id and name
     * 
     * @return string 					SQL query to get all users with their ID and name
     */
    public function getSqlOrganizationsUsersShort(): string
    {
        global $gProfileFields, $gCurrentOrgId;

        return 'SELECT usr_id, CONCAT(last_name.usd_value, \', \', first_name.usd_value) as name
                FROM ' . TBL_USERS . '
                JOIN ' . TBL_USER_DATA . ' as last_name ON last_name.usd_usr_id = usr_id AND last_name.usd_usf_id = ' . $gProfileFields->getProperty('LAST_NAME', 'usf_id') . '
                JOIN ' . TBL_USER_DATA . ' as first_name ON first_name.usd_usr_id = usr_id AND first_name.usd_usf_id = ' . $gProfileFields->getProperty('FIRST_NAME', 'usf_id') . '
                WHERE usr_valid = true AND EXISTS (SELECT 1 FROM ' . TBL_MEMBERS . ', ' . TBL_ROLES . ', ' . TBL_CATEGORIES . ' WHERE mem_usr_id = usr_id AND mem_rol_id = rol_id AND mem_begin <= \'' . DATE_NOW . '\' AND mem_end > \'' . DATE_NOW . '\' AND rol_valid = true AND rol_cat_id = cat_id AND (cat_org_id = ' . $gCurrentOrgId . ' OR cat_org_id IS NULL)) ORDER BY last_name.usd_value, first_name.usd_value;';
    }

    /**
     * Returns the value of the field in html format with consideration of all layout parameters
     * 
     * @param string $fieldNameIntern   Internal item field name of the field that should be html formatted
     * @param string|null $value        The value that should be formatted must be committed so that layout
     *                                  is also possible for values that aren't stored in database
     * @return string                   Returns an html formatted string that considered the profile field settings
     */
    public function getHtmlValue($fieldNameIntern, $value): string
    {
        global $gSettingsManager, $gL10n;

        if (!array_key_exists($fieldNameIntern, $this->mItemFields)) {
            return (string)$value;
        }

        // if value is empty or null, then do nothing
        if ($value != '' && $value != null) {
            // create html for each field type
            $htmlValue = $value;

            $infType = $this->mItemFields[$fieldNameIntern]->getValue('inf_type');
            switch ($infType) {
                case 'CHECKBOX':
                    $htmlValue = $value == 1 ? '<i class="bi bi-check-square"></i>' : '<i class="bi bi-square"></i>';
                    break;

                case 'DATE':
                    if ($value !== '') {
                        // date must be formatted
                        if ($gSettingsManager->get('inventory_field_date_time_format') === 'datetime') {
                            //check if date is datetime or only date
                            if (strpos($value, ' ') === false) {
                                $value .=  ' 00:00';
                            }
                            $date = DateTime::createFromFormat('Y-m-d H:i', $value);
                            if ($date instanceof DateTime) {
                                $htmlValue = $date->format($gSettingsManager->getString('system_date') . ' ' . $gSettingsManager->getString('system_time'));
                            }
                        } else {
                            // check if date is date or datetime
                            if (strpos($value, ' ') !== false) {
                                $value = substr($value, 0, 10);
                            }
                            $date = DateTime::createFromFormat('Y-m-d', $value);
                            if ($date instanceof DateTime) {
                                $htmlValue = $date->format($gSettingsManager->getString('system_date'));
                            }
                        }
                    }
                    break;

                case 'DROPDOWN':
                case 'RADIO_BUTTON':
                    $arrOptionValuesWithKeys = array(); // array with option values and keys that represents the internal value
                    $arrOptions = $this->mItemFields[$fieldNameIntern]->getValue('ifo_inf_options', 'database', false);

                    foreach ($arrOptions as $option) {
                        // if value is imagefile or imageurl then show image
                        if ($infType === 'RADIO_BUTTON' && (Image::isBootstrapIcon($option['value'])
                            || StringUtils::strContains($option['value'], '.png', false) || StringUtils::strContains($option['value'], '.jpg', false))) {
                            // if there is imagefile and text separated by | then explode them
                            if (StringUtils::strContains($option['value'], '|')) {
                                list($optionValueImage, $optionValueText) = explode('|', $option['value']);
                            } else {
                                $optionValueImage = $option['value'];
                                $optionValueText = '';
                            }

                            // if text is a translation-id then translate it
                            $optionValueText = Language::translateIfTranslationStrId($optionValueText);

                            // get html snippet with image tag
                            $option['value'] = Image::getIconHtml($optionValueImage, $optionValueText);
                        }

                        // if text is a translation-id then translate it
                        $option['value'] = Language::translateIfTranslationStrId($option['value']);

                        // save values in new array that starts with item = 1
                        $arrOptionValuesWithKeys[$option['id']] = $option['value'];
                    }

                    if (array_key_exists($value, $arrOptionValuesWithKeys)) {
                        $htmlValue = $arrOptionValuesWithKeys[$value];
                    } else {
                        // if value is not in list then delete the value
                        $htmlValue = '<i>' . $gL10n->get('SYS_DELETED_ENTRY') . '</i>';

                    }
                    break;

                case 'TEXT_BIG':
                    $htmlValue = nl2br($value);
                    break;

                case 'CATEGORY':
                    $category = new Category($this->mDb);
                    $category->readDataByUuid($value);
                    if ($category->getValue('cat_id') > 0) {
                        $htmlValue = $category->getValue('cat_name');
                    } else {
                        $htmlValue = $value;
                    }
                    break;
            }

            $value = $htmlValue;
        } else {
            // special case for type CHECKBOX and no value is there, then show unchecked checkbox
            if ($this->mItemFields[$fieldNameIntern]->getValue('inf_type') === 'CHECKBOX') {
                $value = '<i class="bi bi-square"></i>';
            }
        }

        return (string)$value;
    }

    public function getExportValue($fieldNameIntern, $value): string
    {
        global $gL10n;

        if (!array_key_exists($fieldNameIntern, $this->mItemFields)) {
            return (string)$value;
        }

        // if value is empty or null, then do nothing
        if ($value != '' && $value != null) {
            $value = $this->getValue($fieldNameIntern, 'text');
        } else {
            // special case for type CHECKBOX and no value is there, checkbox is unchecked
            if ($this->mItemFields[$fieldNameIntern]->getValue('inf_type') === 'CHECKBOX') {
                $value = $gL10n->get('SYS_NO');
            }
        }

        return (string)$value;
    }

    /**
     * Returns the item value for this column
     * 
     * format = 'html'  :               returns the value in html-format if this is necessary for that field type
     * format = 'database' :            returns the value that is stored in database with no format applied
     * @param string $fieldNameIntern   Expects the @b inf_name_intern of table @b adm_inventory_fields
     * @param string $format            Returns the field value in a special format @b text, @b html, @b database
     *                                  or datetime (detailed description in method description)
     * @return string|int|bool          Returns the value for the column
     */
    public function getValue($fieldNameIntern, $format = '')
    {
        global $gSettingsManager;
        $value = '';

        // exists a item field with that name ?
        // then check if item has a data object for this field and then read value of this object
        if (array_key_exists($fieldNameIntern, $this->mItemFields)) {
            if ($fieldNameIntern === 'CATEGORY') {
                // special case for category
                $item = new Item($this->mDb, $this, $this->mItemId);
                $catID = $item->getValue('ini_cat_id');
                if ($catID > 0) {
                    $category = new Category($this->mDb);
                    $category->readDataById($catID);
                    if ($format === 'database') {
                        $value = $category->getValue('cat_uuid');
                    }else {
                        $value = $category->getValue('cat_name');
                    }
                }
            }
            elseif (array_key_exists($this->mItemFields[$fieldNameIntern]->getValue('inf_id'), $this->mItemData)) {
                $prefix = 'ind';
                if ($this->mItemData[$this->mItemFields[$fieldNameIntern]->getValue('inf_id')] instanceof ItemLendData) {
                    // if field is a lend field then use 'inl_' as prefix
                    $prefix = 'inl';
                }
                $value = $this->mItemData[$this->mItemFields[$fieldNameIntern]->getValue('inf_id')]->getValue($prefix . '_value', $format);

                if ($format === 'database') {
                    return $value;
                }

                switch ($this->mItemFields[$fieldNameIntern]->getValue('inf_type')) {
                    case 'DATE':
                        if ($value !== '') {
                            // if date field then the current date format must be used
                            if ($gSettingsManager->get('inventory_field_date_time_format') === 'datetime') {
                                //check if date is datetime or only date
                                if (strpos($value, ' ') === false) {
                                    $value .= ' 00:00';
                                }
                                $date = DateTime::createFromFormat('Y-m-d H:i', $value);
                            } else {
                                // check if date is date or datetime
                                if (strpos($value, ' ') !== false) {
                                    $value = substr($value, 0, 10);
                                }
                                $date = DateTime::createFromFormat('Y-m-d', $value);
                            }

                            if ($date === false) {
                                return $value;
                            }

                            // if no format or html is set then show date format from Admidio settings
                            if ($format === '' || $format === 'html') {
                                if ($gSettingsManager->get('inventory_field_date_time_format') === 'datetime') {
                                    $value = $date->format($gSettingsManager->getString('system_date') . ' ' . $gSettingsManager->getString('system_time'));
                                } else {
                                    $value = $date->format($gSettingsManager->getString('system_date'));
                                }
                            } else {
                                $value = $date->format($format);
                            }
                        }
                        break;

                    case 'DROPDOWN':
                    case 'RADIO_BUTTON':
                        // the value in db is only the position, now search for the text
                        if ($value > 0 && $format !== 'html') {
                            $arrOptions = $this->mItemFields[$fieldNameIntern]->getValue('ifo_inf_options', $format, false);
                            $value = $arrOptions[$value];
                        }
                        break;
                }
            }
        }

        // get html output for that field type and value
        if ($format === 'html') {
            $value = $this->getHtmlValue($fieldNameIntern, $value);
        }

        return $value;
    }

    /**
     * Marks an item as imported.
     * 
     * @return void
     */
    public function setImportedItem(): void
    {
        $this->mItemImported = true;
    }

    /**
     * This method reads or stores the variable for showing former items.
     * The values will be stored in database without any inspections!
     * 
     * @param bool|null $newValue       If set, then the new value will be stored in @b showFormerItems.
     * @return bool                     Returns the current value of @b showFormerItems
     */
    public function showFormerItems($newValue = null): bool
    {
        if ($newValue !== null) {
            $this->showFormerItems = $newValue;
        }
        return $this->showFormerItems;
    }

    /**
     * If the recordset is new and wasn't read from database or was not stored in database
     * then this method will return true otherwise false
     * 
     * @return bool                     Returns @b true if record is not stored in database
     */
    public function isNewItem(): bool
    {
        return $this->mItemCreated;
    }

    /**
     * If the recordset was deleted from database then this method will return true otherwise false
     * 
     * @return bool                     Returns @b true if record is removed from databaseIf the recordset was deleted from database then this method will return true otherwise false
     */
    public function isDeletedItem(): bool
    {
        return $this->mItemDeleted;
    }

    /**
     * Set a new value for the item field of the table adm_inventory_manager_data.
     * If the user log is activated then the change of the value will be logged in @b adm_inventory_manager_log.
     * The value is only saved in the object. You must call the method @b save to store the new value to the database
     * 
     * @param string $fieldNameIntern   The internal unique profile field name
     * @param mixed $newValue           The new value that should be stored in the database field
     * @return bool                     Returns @b true if the value is stored in the current object and @b false if a check failed
     */
    public function setValue($fieldNameIntern, $newValue): bool
    {
        global $gSettingsManager;

        $infId = $this->mItemFields[$fieldNameIntern]->getValue('inf_id');
        $oldFieldValue = '';
        // default prefix is 'ind_' for item data
        // if field is a lend field then use 'inl_' as prefix
        $prefix = 'ind';
        if (in_array($fieldNameIntern, $this->lendFieldNames)) {
            $prefix = 'inl';
        }

        if (array_key_exists($infId, $this->mItemData)) {
            $oldFieldValue = $this->mItemData[$infId]->getValue($prefix .'_value');
        }

        // check if new value only contains spaces
        $newValue = (trim((string)$newValue) !== '') ? (string)$newValue : '';

        // save old and new data for notification
        if (array_key_exists($infId, $this->mItemData)) {
            $this->mChangedItemData[] = array($this->mItemData[$infId]->getValue('inf_name_intern') => array('oldValue' => $oldFieldValue, 'newValue' => $newValue));
        } else {
            $this->mChangedItemData[] = array($this->mItemFields[$fieldNameIntern]->getValue('inf_name_intern') => array('oldValue' => $oldFieldValue, 'newValue' => $newValue));
        }

        // format of date will be local but database has stored Y-m-d format must be changed for compare
        if ($this->mItemFields[$fieldNameIntern]->getValue('inf_type') === 'DATE') {
            if ($newValue !== '') {
                if ($gSettingsManager->get('inventory_field_date_time_format') === 'datetime') {
                    //check if date is datetime or only date
                    if (strpos($newValue, ' ') === false) {
                        $newValue .=  ' 00:00';
                    }
                    $date = DateTime::createFromFormat('Y-m-d H:i', $newValue);
                    if ($date !== false) {
                        $newValue = $date->format('Y-m-d H:i');
                    }
                } else {
                    // check if date is date or datetime
                    if (strpos($newValue, ' ') !== false) {
                        $newValue = substr($newValue, 0, 10);
                    }
                    $date = DateTime::createFromFormat('Y-m-d', $newValue);
                    if ($date !== false) {
                        $newValue = $date->format('Y-m-d');
                    }
                }
            }
        }

        // only do an update if value has changed
        if (strcmp($oldFieldValue, $newValue) === 0) {
            return true;
        }

        // if item data object for this field does not exist then create it
        if (!array_key_exists($infId, $this->mItemData)) {
            if (in_array($fieldNameIntern, $this->lendFieldNames)) {
                $this->mItemData[$infId] = new ItemLendData($this->mDb, $this);
            } else {
                $this->mItemData[$infId] = new ItemData($this->mDb, $this);
            }
            $this->mItemData[$infId]->setValue($prefix . '_inf_id', $infId);
            $this->mItemData[$infId]->setValue($prefix . '_ini_id', $this->mItemId);
        }
        
        return $this->mItemData[$infId]->setValue($prefix . '_value', $newValue);
    }

    /**
     * Generates a new ItemId. The new value will be stored in mItemId.
     * 
     * @return int mItemId
     */
    public function createNewItem(string $catUUID): void
    {
        // If an error occurred while generating an item, there is an ItemId but no data for that item.
        // the following routine deletes these unused ItemIds
        $sql = 'SELECT * FROM ' . TBL_INVENTORY_ITEMS . '
                LEFT JOIN ' . TBL_INVENTORY_ITEM_DATA . '
                    ON ind_ini_id = ini_id
                WHERE ind_ini_id is NULL;';
        $statement = $this->mDb->queryPrepared($sql);

        while ($row = $statement->fetch()) {
            $delItem = new Item($this->mDb, $this, $row['ini_id']);
            $delItem->delete();
        }

        // generate a new ItemId
        if ($this->mItemCreated) {
            $category = new Category($this->mDb);
            $category->readDataByUuid($catUUID);

            $newItem = new Item($this->mDb, $this, 0);
            $newItem->setValue('ini_org_id', $this->organizationId);
            $newItem->setValue('ini_former', 0);
            $newItem->setValue('ini_cat_id', $category->getValue('cat_id'));
            $newItem->save();

            $this->mItemId = $newItem->getValue('ini_id');
            $this->mItemUUID = $newItem->getValue('ini_uuid');

            // update item table
            $this->readItems();
        }
    }

    /**
     * delete an item
     * 
     * @param int $itemId               The id of the item that should be deleted
     * @return void
     */
    public function deleteItem(): void
    {
        // Log record deletion, then delete
        $item = new Item($this->mDb, $this, $this->mItemId);
        $item->logDeletion();

        // delete all item data
        $sql = 'DELETE FROM ' . TBL_INVENTORY_ITEM_DATA . ' WHERE ind_ini_id = ?;';
        $this->mDb->queryPrepared($sql, array($this->mItemId));
        // delete all item lend data
        $sql = 'DELETE FROM ' . TBL_INVENTORY_ITEM_LEND_DATA . ' WHERE inl_ini_id = ?;';
        $this->mDb->queryPrepared($sql, array($this->mItemId));
        // delete item
        $sql = 'DELETE FROM ' . TBL_INVENTORY_ITEMS . ' WHERE ini_id = ? AND (ini_org_id = ? OR ini_org_id IS NULL);';
        $this->mDb->queryPrepared($sql, array($this->mItemId, $this->organizationId));

        $this->mItemDeleted = true;
    }

    /**
     * Marks an item as former
     * 
     * @param int $itemId 		    The ID of the item to be marked as former.
     * @return void
     */
    public function makeItemFormer(): void
    {
        $item = new Item($this->mDb, $this, $this->mItemId);
        $item->setValue('ini_former', 1);
        $item->save();

        $this->mItemMadeFormer = true;
        $this->mItemUndoMadeFormer = false;
    }

    /**
     * Marks an item as no longer former
     * 
     * @param int $itemId               The ID of the item to be marked as no longer former.
     * @return void
     */
    public function undoItemFormer(): void
    {
        $item = new Item($this->mDb, $this, $this->mItemId);
        $item->setValue('ini_former', 0);
        $item->save();

        $this->mItemMadeFormer = false;
        $this->mItemUndoMadeFormer = true;
    }

    /**
     * Save data of every item data field
     * 
     * @return void
     */
    public function saveItemData(): void
    {
        global $gCurrentUser;
        $this->mDb->startTransaction();

        // safe item data
        foreach ($this->mItemData as $value) {
            if ($value->hasColumnsValueChanged()) {
                $this->columnsValueChanged = true;
                $this->mItemChanged = true;
            }
            
            // dont safe CATEGORY field to items data
            if ($value instanceof ItemData && $value->getValue('ind_inf_id') === 2) {
                $category = new Category($this->mDb);
                $category->readDataByUuid($value->getValue('ind_value'));
                $catID = $category->getValue('cat_id');

                $item = new Item($this->mDb, $this, $this->mItemId);
                $item->setValue('ini_cat_id', $catID);
                $item->save();
                $value->delete();
            }
            elseif ($value instanceof ItemData) {
                // if value exists and new value is empty then delete entry
                if ($value->getValue('ind_id') > 0 && $value->getValue('ind_value') === '') {
                    $value->delete();
                } else {
                    $value->save();
                }
            }
            elseif ($value instanceof ItemLendData) {
                // if value exists and new value is empty then delete entry
                if ($value->getValue('inl_id') > 0 && $value->getValue('inl_value') === '') {
                    $value->delete();
                } else {
                    $value->save();
                }
            }
        }

        // for updateFingerPrint a change in db must be executed
        // why !$this->mItemCreated -> updateFingerPrint will be done in getNewItemId
        if (!$this->mItemCreated && $this->columnsValueChanged) {
            $updateItem = new Item($this->mDb, $this, $this->mItemId);
            $updateItem->setValue('ini_usr_id_change', $gCurrentUser->getValue('usr_id'), false);
            $updateItem->save();
        }

        $this->columnsValueChanged = false;
        $this->readItemData($this->mItemUUID);
        $this->mDb->endTransaction();
    }

    /**
     * Send a notification email that a new item was created, changed, deleted, or marked as former
     * to all members of the notification role. This role is configured within the global preference
     * **system_notifications_role**. The email contains the item name, the name of the current user,
     * the timestamp, and the details of the changes.
     *
     * @param array $importData The data of the imported items
     * @return bool                     Returns **true** if the notification was sent
     * @throws AdmException             'SYS_EMAIL_NOT_SEND'
     * @throws Exception
     */
    public function sendNotification($importData = null): bool
    {
        global $gCurrentUser, $gSettingsManager, $gL10n;

        // check if notifications are enabled
        if ($gSettingsManager->getBool('system_notifications_new_entries')) {
            $notification = new Email();
            $messageDateText = 'SYS_CHANGED_AT';

            if ($this->mItemImported && $importData === null) {
                return false;
            } elseif ($this->mItemImported) {
                $messageTitleText = 'SYS_INVENTORY_NOTIFICATION_SUBJECT_ITEMS_IMPORTED';
                $messageHead = 'SYS_INVENTORY_NOTIFICATION_MESSAGE_ITEMS_IMPORTED';
            } elseif ($this->mItemCreated) {
                $messageTitleText = 'SYS_INVENTORY_NOTIFICATION_SUBJECT_ITEM_CREATED';
                $messageHead = 'SYS_INVENTORY_NOTIFICATION_MESSAGE_ITEM_CREATED';
            } elseif ($this->mItemDeleted) {
                $messageTitleText = 'SYS_INVENTORY_NOTIFICATION_SUBJECT_ITEM_DELETED';
                $messageHead = 'SYS_INVENTORY_NOTIFICATION_MESSAGE_ITEM_DELETED';
            } elseif ($this->mItemMadeFormer) {
                $messageTitleText = 'SYS_INVENTORY_NOTIFICATION_SUBJECT_ITEM_MADE_FORMER';
                $messageHead = 'SYS_INVENTORY_NOTIFICATION_MESSAGE_ITEM_MADE_FORMER';
            } elseif ($this->mItemUndoMadeFormer) {
                $messageTitleText = 'SYS_INVENTORY_NOTIFICATION_SUBJECT_ITEM_UNDO_FORMER';
                $messageHead = 'SYS_INVENTORY_NOTIFICATION_MESSAGE_ITEM_UNDO_FORMER';
            } elseif ($this->mItemChanged) {
                $messageTitleText = 'SYS_INVENTORY_NOTIFICATION_SUBJECT_ITEM_CHANGED';
                $messageHead = 'SYS_INVENTORY_NOTIFICATION_MESSAGE_ITEM_CHANGED';
            } else {
                return false;
            }

            // if items were imported then sent a message with all itemnames, the user and the date
            // if item was created or changed then sent a message with all changed fields in a table
            // if item was deleted or made former then sent a message with the item name, the user and the date
            if ($this->mItemImported || $this->mItemCreated || $this->mItemChanged) {
                $format_hdr = "<tr><th> %s </th><th> %s </th><th> %s </th></tr>\n";
                $format_row = "<tr><th> %s </th><td> %s </td><td> %s </td></tr>\n";
                $table_begin = "<style>table, th, td {border: 1px solid black;}</style>"
                    . "<table>";
                $table_end = '</table><br>';

                // create message header
                if ($this->mItemImported) {
                    $message = $gL10n->get($messageHead, array($gCurrentUser->getValue('FIRST_NAME') . ' ' . $gCurrentUser->getValue('LAST_NAME'))) . '<br/>'
                        . '<b>' . $gL10n->get($messageDateText) . ':</b> ' . date($gSettingsManager->getString('system_date') . ' ' . $gSettingsManager->getString('system_time')) . '<br/><br/>';
                    $itemData = $importData;
                } else {
                    $message = $gL10n->get($messageHead, array($this->getValue('ITEMNAME', 'html'), $gCurrentUser->getValue('FIRST_NAME') . ' ' . $gCurrentUser->getValue('LAST_NAME'))) . '<br/>'
                        . '<b>' . $gL10n->get($messageDateText) . ':</b> ' . date($gSettingsManager->getString('system_date') . ' ' . $gSettingsManager->getString('system_time')) . '<br/><br/>';
                    $itemData[] = $this->mChangedItemData;
                }

                $itemName = "";
                $changes = array();
                foreach ($itemData as $items) {
                    foreach ($items as $data) {
                        foreach ($data as $key => $value) {
                            if ($value['oldValue'] != $value['newValue']) {
                                $options = $this->getProperty($key, 'ifo_inf_options');
                                if ($key === 'ITEMNAME') {
                                    $itemName = $value['newValue'];
                                } elseif ($key === 'KEEPER') {
                                    $sql = $this->getSqlOrganizationsUsersComplete();

                                    $statement = $this->mDb->query($sql);
                                    foreach ($statement->fetchAll() as $user) {
                                        $users[$user['usr_id']] = $user['name'];
                                    }

                                    $textOld = $gL10n->get('SYS_NO_USER_FOUND');
                                    $textNew = '';
                                    if ($this->mItemImported) {
                                        $textOld = '';
                                        $textNew = $gL10n->get('SYS_NO_USER_FOUND');
                                    }

                                    $changes[] = array(
                                        $key,
                                        isset($users[$value['oldValue']]) ? $users[$value['oldValue']] : $textOld,
                                        isset($users[$value['newValue']]) ? $users[$value['newValue']] : $textNew
                                    );
                                } elseif ($key === 'LAST_RECEIVER') {
                                    $sql = $this->getSqlOrganizationsUsersComplete();

                                    $statement = $this->mDb->query($sql);
                                    foreach ($statement->fetchAll() as $user) {
                                        $users[$user['usr_id']] = $user['name'];
                                    }

                                    $changes[] = array(
                                        $key,
                                        isset($users[$value['oldValue']]) ? $users[$value['oldValue']] : $value['oldValue'],
                                        isset($users[$value['newValue']]) ? $users[$value['newValue']] : $value['newValue']
                                    );
                                } elseif ($key === 'IN_INVENTORY') {
                                    $changes[] = array(
                                        $key,
                                        $value['oldValue'] == 1 ? $gL10n->get('SYS_YES') : ($value['oldValue'] == 0 ? $gL10n->get('SYS_NO') : $value['oldValue']),
                                        $value['newValue'] == 1 ? $gL10n->get('SYS_YES') : ($value['newValue'] == 0 ? $gL10n->get('SYS_NO') : $value['newValue'])
                                    );
                                } elseif ($options !== '') {
                                    $changes[] = array(
                                        $key,
                                        isset($options[$value['oldValue']]) ? $options[$value['oldValue']] : '',
                                        isset($options[$value['newValue']]) ? $options[$value['newValue']] : ''
                                    );
                                } else {
                                    $changes[] = array($key, $value['oldValue'], $value['newValue']);
                                }
                            }
                        }
                    }

                    if ($changes) {
                        if ($itemName === "") {
                            $itemName = $this->getValue('ITEMNAME', 'html');
                        }
                        $message .= '<p style="font-size:120%;""><b><u>' . $itemName . ':</u></b></p>';
                        $message .= $table_begin
                            . sprintf(
                                $format_hdr,
                                $gL10n->get('SYS_INVENTORY_ITEMFIELD'),
                                $gL10n->get('SYS_PREVIOUS_VALUE'),
                                $gL10n->get('SYS_NEW_VALUE')
                            );
                        foreach ($changes as $c) {
                            $fieldName = $this->getProperty($c[0], 'inf_name');
                            $message .= sprintf($format_row, $fieldName, $c[1], $c[2]);
                        }

                        $message .= $table_end;
                        $changes = array();
                    }
                }
            } else {
                $messageUserText = 'SYS_CHANGED_BY';
                $messageDateText = 'SYS_CHANGED_AT';
                $fieldName = $this->getProperty('ITEMNAME', 'inf_name');

                $message = $gL10n->get($messageHead) . '<br/><br/>'
                    . '<b>' . ((substr($fieldName, 3, 1) === '_') ? $gL10n->get($fieldName) : $fieldName)  . ':</b> ' . $this->getValue('ITEMNAME', 'html') . '<br/>'
                    . '<b>' . $gL10n->get($messageUserText) . ':</b> ' . $gCurrentUser->getValue('FIRST_NAME') . ' ' . $gCurrentUser->getValue('LAST_NAME') . '<br/>'
                    . '<b>' . $gL10n->get($messageDateText) . ':</b> ' . date($gSettingsManager->getString('system_date') . ' ' . $gSettingsManager->getString('system_time')) . '<br/>';
            }

            return $notification->sendNotification(
                $gL10n->get($messageTitleText, array($this->getValue('ITEMNAME', 'html'))),
                $message
            );
        }
        return false;
    }
}
