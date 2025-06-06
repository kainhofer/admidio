<?php

namespace Admidio\Documents\Entity;

use Admidio\Infrastructure\Database;
use Admidio\Infrastructure\Exception;
use Admidio\Roles\Entity\RolesRights;
use Admidio\Infrastructure\Entity\Entity;
use Admidio\Infrastructure\Utils\FileSystemUtils;
use Admidio\Infrastructure\Utils\StringUtils;
use Admidio\Changelog\Entity\LogChanges;

/**
 * @brief Class manages access to database table adm_folders
 *
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 */
class Folder extends Entity
{
    /**
     * @var RolesRights|null Object with all roles that could view the current folder
     */
    protected ?RolesRights $folderViewRolesObject;
    /**
     * @var RolesRights|null Object with all roles that could upload files to the current folder
     */
    protected ?RolesRights $folderUploadRolesObject;

    /**
     * Constructor that will create an object of a recordset of the table adm_folders.
     * If the id is set, then the specific folder will be loaded.
     * @param Database $database Object of the class Database. This should be the default global object **$gDb**.
     * @param int $folId The recordset of the folder with this id will be loaded. If id isn't set, then an empty object of the table is created.
     * @throws Exception
     */
    public function __construct(Database $database, int $folId = 0)
    {
        parent::__construct($database, TBL_FOLDERS, 'fol', $folId);
    }

    /**
     * @param array<string,array<int,array<string,mixed>>> $completeFolder
     * @return array<string,array<int,array<string,mixed>>>
     * @throws Exception
     */
    public function addAdditionalToFolderContents(array $completeFolder): array
    {
        global $gCurrentUser;

        // If the user hasn't isAdministratorDocumentsFiles, don't add more data
        if (!$gCurrentUser->isAdministratorDocumentsFiles()) {
            return $completeFolder;
        }

        // Check if the folder exists
        $folderPath = $this->getFullFolderPath();
        if (!is_dir($folderPath)) {
            return $completeFolder;
        }

        // User has isAdministratorDocumentsFiles and folder exists, so look up the physical directory for items that aren't in the DB
        $dirHandle = @opendir($folderPath);
        if ($dirHandle) {
            while (($entry = readdir($dirHandle)) !== false) {
                if ($entry === '.' || $entry === '..' || str_starts_with($entry, '.')) {
                    continue;
                }

                $alreadyAdded = false;

                // Check if entry is folder or file
                $entryFolderPath = $folderPath . '/' . $entry;

                if (is_dir($entryFolderPath)) {
                    // Check if the folder is already in the regular folders
                    foreach ($completeFolder['folders'] as $folder) {
                        if ($folder['fol_name'] === $entry) {
                            $alreadyAdded = true;
                            break;
                        }
                    }

                    // If isn't already in, add it
                    if (!$alreadyAdded) {
                        $completeFolder['additionalFolders'][] = array('fol_name' => $entry);
                    }
                } elseif (is_file($entryFolderPath)) {
                    // Check if the file is already in the regular files
                    foreach ($completeFolder['files'] as $file) {
                        if ($file['fil_name'] === $entry) {
                            $alreadyAdded = true;
                            break;
                        }
                    }

                    // If isn't already in, add it
                    if (!$alreadyAdded) {
                        $completeFolder['additionalFiles'][] = array(
                            'fil_name' => $entry,
                            'fil_size' => filesize($entryFolderPath)
                        );
                    }
                }
            }

            closedir($dirHandle);
        }

        return $completeFolder;
    }

    /**
     * Add a new file or subfolder of the current folder to the database. If a folder is added, all files and
     * subfolders of this folder will be added recursively with this method. The configured rights for viewing and
     * uploading will be adapted to the subfolders.
     * @param string $newFolderFileName Name of the folder or file that should be added to the database.
     * @throws Exception
     */
    public function addFolderOrFileToDatabase(string $newFolderFileName): void
    {
        $newFolderFileName = urldecode($newFolderFileName);
        $newObjectPath = $this->getFullFolderPath() . '/' . $newFolderFileName;
        $folderId = (int)$this->getValue('fol_id');

        // check if a file or folder should be created
        if (is_file($newObjectPath)) {
            // add the file to the database
            $newFile = new File($this->db);
            $newFile->setValue('fil_fol_id', $folderId);
            $newFile->setValue('fil_name', $newFolderFileName);
            $newFile->setValue('fil_locked', $this->getValue('fol_locked'));
            $newFile->setValue('fil_counter', 0);
            $newFile->save();

        } elseif (is_dir($newObjectPath)) {
            // add the folder to the database
            $newFolder = new Folder($this->db);
            $newFolder->setValue('fol_fol_id_parent', $folderId);
            $newFolder->setValue('fol_type', 'DOCUMENTS');
            $newFolder->setValue('fol_name', $newFolderFileName);
            $newFolder->setValue('fol_path', $this->getFolderPath());
            $newFolder->setValue('fol_locked', $this->getValue('fol_locked'));
            $newFolder->setValue('fol_public', $this->getValue('fol_public'));
            $newFolder->save();

            // get the role rights of the parent folder
            $rightParentFolderView = new RolesRights($this->db, 'folder_view', $folderId);
            $newFolder->addRolesOnFolder('folder_view', $rightParentFolderView->getRolesIds());
            $rightParentFolderUpload = new RolesRights($this->db, 'folder_upload', $folderId);
            $newFolder->addRolesOnFolder('folder_upload', $rightParentFolderUpload->getRolesIds());

            // now look for all files and folder within that new folder and add them also to the database
            $dirHandle = @opendir($newObjectPath);
            if ($dirHandle) {
                while (($entry = readdir($dirHandle)) !== false) {
                    if ($entry === '.' || $entry === '..' || str_starts_with($entry, '.')) {
                        continue;
                    }

                    // call recursively
                    $newFolder->addFolderOrFileToDatabase($entry);
                }
                closedir($dirHandle);
            }
        }
    }

    /**
     * Add all roles of the array to the current folder and all the subfolders. The
     * roles will be assigned to the right that was set through parameter $rolesRightNameIntern.
     * @param string $rolesRightNameIntern Name of the right where the roles should be added
     *                                     e.g. **folder_view** or **folder_upload**
     * @param array<int,int> $rolesArray Array with all role IDs that should be added.
     * @param bool $recursive If set to **true** than the rights will be set recursive to all subfolders
     * @throws Exception
     */
    public function addRolesOnFolder(string $rolesRightNameIntern, array $rolesArray, bool $recursive = true): void
    {
        $this->editRolesOnFolder('add', $rolesRightNameIntern, $rolesArray, $recursive);
    }

    /**
     * Legt einen neuen Ordner im Dateisystem an
     * @param string $folderName
     * @return null|array<string,string>
     * @throws Exception
     */
    public function createFolder(string $folderName): ?array
    {
        $baseFolder = $this->getFullFolderPath();

        try {
            FileSystemUtils::createDirectoryIfNotExists($baseFolder . '/' . $folderName);
        } catch (\RuntimeException $exception) {
            return array(
                'text' => 'SYS_FOLDER_NOT_CREATED',
                'path' => $baseFolder . '/' . $folderName
            );
        }

        return null;
    }

    /**
     * Deletes the selected record of the table and all references in other tables.
     * Also, all files, subfolders and the selected folder will be deleted in the file system.
     * After that the class will be initialized.
     * @return bool **true** if no error occurred
     * @throws Exception
     */
    public function delete(): bool
    {
        global $gLogger;

        if ($this->getValue('fol_name') === '') {
            return false;
        }

        $folderId = (int)$this->getValue('fol_id');
        $folderPath = $this->getFullFolderPath();

        $this->db->startTransaction();

        $subfoldersStatement = $this->getSubfolderStatement($folderId);

        while ($rowFolId = (int)$subfoldersStatement->fetchColumn()) {
            // rekursiver Aufruf mit jedem einzelnen Unterordner
            $subfolder = new Folder($this->db, $rowFolId);
            $subfolder->delete();
        }

        $files = $this->getFilesWithProperties();
        foreach ($files as $f) {
            $fl = new File($this->db, $f['fil_id']);
            $fl->delete();
        }

        // delete all role assignments that have the right to view this folder
        $this->folderViewRolesObject->delete();
        $this->folderUploadRolesObject->delete();

        // physically delete the directory from the disk
        if ($folderPath !== '') {
            try {
                FileSystemUtils::deleteDirectoryIfExists($folderPath, true);
            } catch (\RuntimeException $exception) {
                $gLogger->error('Could not delete directory!', array('directoryPath' => $folderPath));
                // TODO
            }
        }

        // Even if the physical deletion fails, everything is deleted in the DB...
        $returnCode = parent::delete();

        $this->db->endTransaction();

        return $returnCode;
    }

    /**
     * Add all roles of the array to the current folder and all the subfolders. The
     * roles will be assigned to the right that was set through parameter $rolesRightNameIntern.
     * @param string $mode "mode" could be "add" or "remove"
     * @param string $rolesRightNameIntern Name of the right where the roles should be added
     * @param array<int,int> $rolesArray
     * @param bool $recursive If set to **true** than the rights will be set recursive to all subfolders
     * @param int $folderId The folder id of the subfolder if this method is called recursive
     * @throws Exception
     */
    private function editRolesOnFolder(string $mode, string $rolesRightNameIntern, array $rolesArray, bool $recursive, int $folderId = 0): void
    {
        if (count($rolesArray) === 0) {
            return;
        }

        if ($folderId === 0) {
            $folderId = (int)$this->getValue('fol_id');
        }

        $this->db->startTransaction();

        if ($recursive) {
            $subfoldersStatement = $this->getSubfolderStatement($folderId);

            while ($folId = (int)$subfoldersStatement->fetchColumn()) {
                // recursive call for every subfolder
                $this->editRolesOnFolder($mode, $rolesRightNameIntern, $rolesArray, true, $folId);
            }
        }

        // add new rights to the folder
        $folderRolesRights = new RolesRights($this->db, $rolesRightNameIntern, $folderId);
        if ($mode === 'add') {
            $folderRolesRights->addRoles($rolesArray);
        } else {
            $folderRolesRights->removeRoles($rolesArray);
        }

        $this->db->endTransaction();
    }

    /**
     * Set the public flag to a folder and all subfolders.
     * @param bool $publicFlag If set to **1 **, then all users could see this folder.
     * @throws Exception
     */
    public function editPublicFlagOnFolder(bool $publicFlag): void
    {
        $folderId = (int)$this->getValue('fol_id');
        $this->setValue('fol_public', (int)$publicFlag);

        $subfoldersStatement = $this->getSubfolderStatement($folderId);

        while ($folId = (int)$subfoldersStatement->fetchColumn()) {
            $subfolder = new Folder($this->db, $folId);
            $subfolder->editPublicFlagOnFolder($publicFlag);
            $subfolder->save();
        }
    }

    /**
     * Gets the path of the folder (with folder-name)
     * @return string
     * @throws Exception
     */
    public function getFolderPath(): string
    {
        return $this->getValue('fol_path') . '/' . $this->getValue('fol_name');
    }

    /**
     * Gets the absolute path of the folder (with folder-name)
     * @return string
     * @throws Exception
     */
    public function getFullFolderPath(): string
    {
        return ADMIDIO_PATH . $this->getFolderPath();
    }

    /**
     * @return array<int,array<string,mixed>> All files with their properties
     * @throws Exception
     */
    public function getFilesWithProperties(): array
    {
        global $gCurrentUser;

        $files = array();

        // Get all files of the current folder
        $sqlFiles = 'SELECT *
                       FROM ' . TBL_FILES . '
                      INNER JOIN ' . TBL_FOLDERS . ' ON fol_id = fil_fol_id
                      WHERE fil_fol_id = ? -- $this->getValue(\'fol_id\')
                   ORDER BY fil_name';
        $filesStatement = $this->db->queryPrepared($sqlFiles, array((int)$this->getValue('fol_id')));

        // jetzt noch die Dateien ins Array packen:
        while ($rowFiles = $filesStatement->fetch()) {
            $filePath = $this->getFullFolderPath() . '/' . $rowFiles['fil_name'];
            $fileExists = is_file($filePath);

            $fileSize = 0;
            if ($fileExists) {
                $fileSize = filesize($filePath);
            }

            $addToArray = false;

            // If the file exists and the file isn't locked or the user has isAdministratorDocumentsFiles, show it
            if (($fileExists && !$rowFiles['fil_locked']) || $gCurrentUser->isAdministratorDocumentsFiles()) {
                $addToArray = true;
            }

            if ($addToArray) {
                $files[] = array(
                    'fil_id' => $rowFiles['fil_id'],
                    'fil_uuid' => $rowFiles['fil_uuid'],
                    'fil_name' => $rowFiles['fil_name'],
                    'fil_description' => $rowFiles['fil_description'],
                    'fil_timestamp' => $rowFiles['fil_timestamp'],
                    'fil_locked' => $rowFiles['fil_locked'],
                    'fil_exists' => $fileExists,
                    'fil_size' => $fileSize,
                    'fil_counter' => $rowFiles['fil_counter'],
                    'fol_id' => $rowFiles['fol_id'],
                    'fol_name' => $rowFiles['fol_name'],
                    'fol_path' => $rowFiles['fol_path']
                );
            }
        }

        return $files;
    }

    /**
     * Reads the folder recordset from database table **adm_folders** and throws an
     * Exception if the user has no right to see the folder, or the folder id doesn't exist.
     * @param string $folderUuid The UUID of the folder. If the UUID is empty, then the root folder will be shown.
     * @return true Returns **true** if everything is ok otherwise, an Exception is thrown.
     * @throws Exception Exception with the relevant message text. If the message text = 'LOGIN', then
     *                   login page should be shown.
     * @throws Exception
     */
    public function getFolderForDownload(string $folderUuid): bool
    {
        global $gCurrentUser, $gCurrentOrgId, $gValidLogin;

        if ($folderUuid !== '') {
            // get folder of the parameter
            $condition = ' fol_uuid   = ? -- $folderUuid
                       AND fol_type = \'DOCUMENTS\' ';
            $queryParams = array($folderUuid);
        } else {
            // get first folder of current organization
            $condition = ' fol_fol_id_parent IS NULL
                       AND fol_org_id = ? -- $gCurrentOrgId
                       AND fol_type   = \'DOCUMENTS\' ';
            $queryParams = array($gCurrentOrgId);
        }
        $this->readData($condition, $queryParams);

        // Check if a dataset is found
        if ((int)$this->getValue('fol_id') === 0) {
            throw new Exception('SYS_FOLDER_NOT_FOUND', array($folderUuid));
        }

        // If the current user has download-admin-rights => allow
        if ($gCurrentUser->isAdministratorDocumentsFiles()) {
            return true;
        }

        // If the folder is public (and the file is not locked) => allow
        if ($this->getValue('fol_public') && !$this->getValue('fol_locked')) {
            return true;
        }

        // check if the user has a membership in a role that is assigned to the current folder
        if ($this->folderViewRolesObject->hasRight($gCurrentUser->getRoleMemberships())
            && !$this->getValue('fol_locked')) {
            return true;
        }

        $this->clear();
        if ($gValidLogin) {
            throw new Exception('SYS_FOLDER_NO_RIGHTS');
        } else {
            if ($folderUuid !== '') {
                throw new Exception('LOGIN');
            } else {
                throw new Exception('SYS_FOLDER_NO_FILES_VISITOR');
            }
        }
    }

    /**
     * Create a unique folder name for the root folder of the download module that contains
     * the shortname of the current organization.
     * @param string $type The folder type of which the root should be determined.
     *                                      If no type is set, then **documents** will be set.
     * @param string $organizationShortname The shortname of the organization for which the folder name should be returned
     *                                      If no shortname is set, then a shortname of the current organization will be set.
     * @return string Returns the root folder name for the download module.
     * @throws Exception
     */
    public static function getRootFolderName(string $type = 'documents', string $organizationShortname = ''): string
    {
        global $gCurrentOrganization;

        if ($organizationShortname === '') {
            $organizationShortname = $gCurrentOrganization->getValue('org_shortname');
        }

        $organizationShortname = FileSystemUtils::getSanitizedPathEntry($organizationShortname);

        return StringUtils::strToLower($type) . '_' . strtolower($organizationShortname);
    }

    /**
     * Returns an array with all role IDs that have the right to view the folder.
     * @return array<int,int> Returns an array with all role ids that have the right to view the folder.
     */
    public function getViewRolesIds(): array
    {
        return $this->folderViewRolesObject->getRolesIds();
    }

    /**
     * Returns an array with all role names that have the right to view the folder. If no role is assigned to the
     *  folder, then everyone (also visitors) can view the folder. In this case the array will contain 1 entry with
     * "All (also visitors)".
     * @return array<int,int> Returns an array with all role names that have the right to view the folder.
     * @throws Exception
     */
    public function getViewRolesNames(): array
    {
        global $gL10n;

        $roleNames = $this->folderViewRolesObject->getRolesNames();
        if (count($roleNames) === 0) {
            $roleNames[] = $gL10n->get('SYS_ALL') . ' (' . $gL10n->get('SYS_ALSO_VISITORS') . ')';
        }
        return $roleNames;
    }

    /**
     * Returns an array with all role IDs that have the right to upload files to the folder.
     * @return array<int,int> Returns an array with all role ids that have the right to upload files to the folder.
     */
    public function getUploadRolesIds(): array
    {
        return $this->folderUploadRolesObject->getRolesIds();
    }

    /**
     * Return PDOStatement with all subfolders of a parent folder id
     * @param int $folderId Folder ID
     * @param array<int,string> $columns The columns that should be in the statement
     * @return false|\PDOStatement Subfolder statement with fol_id column
     * @throws Exception
     */
    private function getSubfolderStatement(int $folderId, array $columns = array('fol_id')): false|\PDOStatement
    {
        // select all subfolders of the current folder
        $sql = 'SELECT ' . implode(',', $columns) . '
                  FROM ' . TBL_FOLDERS . '
                 WHERE fol_fol_id_parent = ? -- $folderId';

        return $this->db->queryPrepared($sql, array($folderId));
    }

    /**
     * @return array<int,array<string,mixed>> All subfolders with their properties
     * @throws Exception
     */
    public function getSubfoldersWithProperties(): array
    {
        global $gCurrentUser, $gValidLogin;

        // Get all subfolders of the current folder
        $sqlFolders = 'SELECT *
                         FROM ' . TBL_FOLDERS . '
                        WHERE fol_type          = \'DOCUMENTS\'
                          AND fol_fol_id_parent = ? -- $this->getValue(\'fol_id\')
                          AND fol_org_id        = ? -- $GLOBALS[\'gCurrentOrgId\']
                     ORDER BY fol_name';
        $foldersStatement = $this->db->queryPrepared($sqlFolders, array((int)$this->getValue('fol_id'), $GLOBALS['gCurrentOrgId']));

        $folders = array();

        while ($rowFolders = $foldersStatement->fetch()) {
            $folderExists = is_dir(ADMIDIO_PATH . $rowFolders['fol_path'] . '/' . $rowFolders['fol_name']);

            $addToArray = false;

            // If the user has isAdministratorDocumentsFiles, show it
            if ($gCurrentUser->isAdministratorDocumentsFiles()) {
                $addToArray = true;
            } // If the user hasn't isAdministratorDocumentsFiles, only show if the folder exists
            elseif ($folderExists) {
                // If the folder is public and not locked, show it
                if ($rowFolders['fol_public'] && !$rowFolders['fol_locked']) {
                    $addToArray = true;
                } // If the user has a membership in a role that is assigned to the current subfolder, show it
                elseif ($gValidLogin) {
                    $subfolderViewRolesObject = new RolesRights($this->db, 'folder_view', $rowFolders['fol_id']);

                    if ($subfolderViewRolesObject->hasRight($gCurrentUser->getRoleMemberships())) {
                        $addToArray = true;
                    }
                }
            }

            if ($addToArray) {
                $folders[] = array(
                    'fol_id' => $rowFolders['fol_id'],
                    'fol_uuid' => $rowFolders['fol_uuid'],
                    'fol_name' => $rowFolders['fol_name'],
                    'fol_description' => $rowFolders['fol_description'],
                    'fol_path' => $rowFolders['fol_path'],
                    'fol_timestamp' => $rowFolders['fol_timestamp'],
                    'fol_public' => $rowFolders['fol_public'],
                    'fol_exists' => $folderExists,
                    'fol_locked' => $rowFolders['fol_locked']
                );
            }
        }

        return $folders;
    }

    /**
     * Get the value of a column of the database table.
     * If the value was manipulated before with **setValue**, then the manipulated value is returned.
     * @param string $columnName The name of the database column whose value should be read
     * @param string $format For date or timestamp columns the format should be the date/time format e.g. **d.m.Y = '02.04.2011'**.
     *                           For text columns the format can be **database** that would return the original database value without any transformations
     * @return mixed Returns the value of the database column.
     *         If the value was manipulated before with **setValue**, then the manipulated value is returned.
     * @throws Exception
     */
    public function getValue(string $columnName, string $format = ''): mixed
    {
        $value = parent::getValue($columnName, $format);

        if ($columnName === 'fol_name') {
            // Convert HTML entity back to letters
            $value = html_entity_decode($value, ENT_QUOTES, 'UTF-8');
        }

        return $value;
    }

    /**
     * Checks if the current user has the right to upload files to the current folder.
     * @return bool Return **true** if the user has the right to upload files
     * @throws Exception
     */
    public function hasUploadRight(): bool
    {
        global $gCurrentUser;

        return $this->folderUploadRolesObject->hasRight($gCurrentUser->getRoleMemberships()) || $gCurrentUser->isAdministratorDocumentsFiles();
    }

    /**
     * Checks if the current user has the right to view files of the current folder.
     * @return bool Return **true** if the user has the right to view files
     * @throws Exception
     */
    public function hasViewRight(): bool
    {
        global $gCurrentUser;

        return $this->folderViewRolesObject->hasRight($gCurrentUser->getRoleMemberships()) || $gCurrentUser->isAdministratorDocumentsFiles();
    }

    /**
     * Move this folder to the folder that is set with the parameter $destFolderUUID. The method
     * will check if the user has the right to upload files to that folder and then move the folder
     * within the file system and the database structure. The role rights for viewing and uploading will then be
     * adopted recursively from the destination folder.
     * @param string $destFolderUUID UUID of the destination folder to which this folder is to be moved.
     * @return void
     * @throws Exception
     * @throws \RuntimeException
     * @throws \UnexpectedValueException
     * @throws Exception
     */
    public function moveToFolder(string $destFolderUUID): void
    {
        $folder = new Folder($this->db);
        $folder->readDataByUuid($destFolderUUID);

        if ($folder->hasUploadRight()) {
            FileSystemUtils::moveDirectory($this->getFullFolderPath(), $folder->getFullFolderPath() . '/' . $this->getValue('fol_name'));

            $this->db->startTransaction();
            // save the new parent folder
            $this->setValue('fol_fol_id_parent', $folder->getValue('fol_id'));
            $this->setValue('fol_path', $folder->getValue('fol_path') . '/' . $folder->getValue('fol_name'));
            $this->setValue('fol_public', $folder->getValue('fol_public'));
            $this->setValue('fol_locked', $folder->getValue('fol_locked'));
            $this->save();

            // set the new path to all subfolders
            $this->rename($this->getValue('fol_name'), $folder->getValue('fol_path') . '/' . $folder->getValue('fol_name'));

            // adopt the role rights of the new parent folder
            $this->removeRolesOnFolder('folder_view', $this->getViewRolesIds());
            $this->removeRolesOnFolder('folder_upload', $this->getUploadRolesIds());
            $this->addRolesOnFolder('folder_view', $folder->getViewRolesIds());
            $this->addRolesOnFolder('folder_upload', $folder->getUploadRolesIds());
            $this->db->endTransaction();
        }
    }

    /**
     * Reads a record out of the table in the database selected by the conditions of the param **$sqlWhereCondition** out of the table.
     * If the SQL finds more than one record, the method returns **false**.
     * Per default, all columns of the default table will be read and stored in the object.
     * @param string $sqlWhereCondition Conditions for the table to select one record
     * @param array<int,mixed> $queryParams The query params for the prepared statement
     * @return bool Returns **true** if one record is found
     * @throws Exception
     * @see Entity#readDataByUuid
     * @see Entity#readDataByColumns
     * @see Entity#readDataById
     */
    protected function readData(string $sqlWhereCondition, array $queryParams = array()): bool
    {
        if (parent::readData($sqlWhereCondition, $queryParams)) {
            $folId = (int)$this->getValue('fol_id');
            $this->folderViewRolesObject = new RolesRights($this->db, 'folder_view', $folId);
            $this->folderUploadRolesObject = new RolesRights($this->db, 'folder_upload', $folId);

            return true;
        }

        return false;
    }

    /**
     * Remove all roles of the array from the current folder and all the subfolders. The
     * roles will be removed from the right that was set through parameter $rolesRightNameIntern.
     * @param string $rolesRightNameIntern Name of the right where the roles should be removed
     *                                     e.g. **folder_view** or **folder_upload**
     * @param array<int,int> $rolesArray Array with all role IDs that should be removed.
     * @param bool $recursive If set to **true** than the rights will be set recursive to all subfolders.
     * @throws Exception
     */
    public function removeRolesOnFolder(string $rolesRightNameIntern, array $rolesArray, bool $recursive = true): void
    {
        $this->editRolesOnFolder('remove', $rolesRightNameIntern, $rolesArray, $recursive);
    }

    /**
     * Renames a folder instance and ensures that the path is adjusted for all subfolders
     * @param string $newName
     * @param string $newPath
     * @throws Exception
     */
    public function rename(string $newName, string $newPath): void
    {
        $folderId = (int)$this->getValue('fol_id');
        $this->setValue('fol_name', $newName);
        $this->setValue('fol_path', newValue: $newPath);
        $this->save();

        $this->db->startTransaction();

        $subfoldersStatement = $this->getSubfolderStatement($folderId, array('fol_id', 'fol_name'));

        while ($rowSubfolders = $subfoldersStatement->fetch()) {
            // recursive call with every subfolder
            $subfolder = new Folder($this->db, $rowSubfolders['fol_id']);
            $subfolder->rename($rowSubfolders['fol_name'], $newPath . '/' . $newName);
        }

        $this->db->endTransaction();
    }

    /**
     * Save all changed columns of the recordset in the table of the database. Therefore, the class remembers if it's
     * a new record or if only an update is necessary. The update statement will only update
     * the changed columns. If the table has columns for the creator or the editor, then these columns
     * with their timestamp will be updated.
     * For new records the user, organization and timestamp will be set per default.
     * @param bool $updateFingerPrint Default **true**. Will update the creator or editor of the recordset if the table has columns like **usr_id_create** or **usr_id_changed**
     * @return bool If an update or insert into the database was done, then return true, otherwise false.
     * @throws Exception
     */
    public function save(bool $updateFingerPrint = true): bool
    {
        if ($this->newRecord) {
            $this->setValue('fol_timestamp', DATETIME_NOW);
            $this->setValue('fol_usr_id', $GLOBALS['gCurrentUserId']);
            $this->setValue('fol_org_id', $GLOBALS['gCurrentOrgId']);
        }

        return parent::save($updateFingerPrint);
    }

    /**
     * Retrieve the list of database fields that are ignored for the changelog.
     * Some tables contain columns _usr_id_create, timestamp_create, etc. We do not want
     * to log changes to these columns.
     * The folder table also contains fol_usr_id and fol_timestamp. Also, for now fol_type will always be DOCUMENTS.
     * When a folder is created, we also don't need to log some columns because they are already
     * in the creation log record.
     *
     * @return array Returns the list of database columns to be ignored for logging.
     */
    public function getIgnoredLogColumns(): array
    {
        $ignored = parent::getIgnoredLogColumns();
        $ignored = array_merge($ignored, ['fol_type', 'fol_usr_id', 'fol_timestamp']);
        if ($this->insertRecord) {
            $ignored = array_merge($ignored, ['fol_org_id', 'fol_fol_id_parent', 'fol_name', 'fol_public']);
        }
        return $ignored;
    }

    /**
     * Adjust the changelog entry for this db record: Add the parent folder as a related object
     * @param LogChanges $logEntry The log entry to adjust
     * @return void
     * @throws Exception
     */
    protected function adjustLogEntry(LogChanges $logEntry): void
    {
        if (!empty($this->getValue('fol_fol_id_parent'))) {
            $folEntry = new Folder($this->db, $this->getValue('fol_fol_id_parent'));
            $logEntry->setLogRelated($folEntry->getValue('fol_uuid'), $folEntry->getValue('fol_name'));
        }
    }
}
