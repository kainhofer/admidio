<?php
/**
 ***********************************************************************************************
 * Create or edit a user profile
 *
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 ***********************************************************************************************
 */

/******************************************************************************
 * Parameters:
 *
 * user_uuid   : Uuid of the user who should be edited
 * mode - html : Show form to create or edit a user profile
 *      - save : Save all data of the user profile form
 * copy        : true - The user of the user_id will be copied and the base for this new user
 * accept_registration : If set to true, another forward url to role assignment will be set.
 * lastname    : (Optional) Lastname could be set and will than be preassigned for new users
 * firstname   : (Optional) First name could be set and will than be preassigned for new users
 *
 *****************************************************************************/
use Admidio\Infrastructure\Exception;
use Admidio\Infrastructure\Utils\PasswordUtils;
use Admidio\Infrastructure\Utils\SecurityUtils;
use Admidio\UI\Presenter\FormPresenter;
use Admidio\UI\Presenter\PagePresenter;
use Admidio\Users\Entity\User;
use Admidio\Users\Entity\UserRegistration;
use Admidio\Changelog\Service\ChangelogService;

try {
    require_once(__DIR__ . '/../../system/common.php');

    // Initialize and check the parameters
    $getUserUuid = admFuncVariableIsValid($_GET, 'user_uuid', 'uuid');
    $getMode = admFuncVariableIsValid($_GET, 'mode', 'string', array('defaultValue' => 'html', 'validValues' => array('html', 'save')));
    $getCopy = admFuncVariableIsValid($_GET, 'copy', 'bool');
    $getAcceptRegistration = admFuncVariableIsValid($_GET, 'accept_registration', 'bool');

    $registrationOrgId = $gCurrentOrgId;

    // read user data
    if (!$gValidLogin || $getAcceptRegistration) {
        // create user registration object and set requested organization
        $user = new UserRegistration($gDb, $gProfileFields);
        $user->readDataByUuid($getUserUuid);
        if (isset($_POST['adm_org_id'])) {
            $user->setOrganization((int)$_POST['adm_org_id']);
        }
    } else {
        $user = new User($gDb, $gProfileFields);
        $user->readDataByUuid($getUserUuid);
    }

    // check if module may be called
    if (!$gValidLogin) {
        // Registration disabled, so also lock this mode
        if (!$gSettingsManager->getBool('registration_module_enabled')) {
            throw new Exception('SYS_MODULE_DISABLED');
        }
    } else {
        if ($getUserUuid === '') {
            // checks if the user has the necessary rights to create new users
            if (!$gCurrentUser->isAdministratorUsers()) {
                throw new Exception('SYS_NO_RIGHTS');
            }

            if (isset($_GET['lastname']) && isset($_GET['firstname'])) {
                // If last name and first name are passed, then these are already preassigned
                $user->setValue('LAST_NAME', stripslashes($_GET['lastname']));
                $user->setValue('FIRST_NAME', stripslashes($_GET['firstname']));
            }
        } else {
            // checks if the user has the necessary rights to change the corresponding profile
            if (!$gCurrentUser->hasRightEditProfile($user)) {
                throw new Exception('SYS_NO_RIGHTS');
            }
        }
    }

    if ($getMode === 'html') {
        // set headline of the script
        if ($getCopy) {
            // if we want to copy the user than set id = 0
            $user->setValue('usr_id', 0);
            $getUserUuid = '';
            $headline = $gL10n->get('SYS_COPY_VAR', array($user->getValue('FIRST_NAME') . ' ' . $user->getValue('LAST_NAME')));
        } elseif ($getUserUuid === '' && $gValidLogin) {
            $headline = $gL10n->get('SYS_CREATE_MEMBER');
        } elseif ($getUserUuid === '' && !$gValidLogin) {
            $headline = $gL10n->get('SYS_REGISTRATION');
        } elseif ($user->getValue('usr_id') === $gCurrentUserId) {
            $headline = $gL10n->get('SYS_EDIT_MY_PROFILE');
        } else {
            $headline = $gL10n->get('SYS_EDIT_PROFILE');
        }

        $gNavigation->addUrl(CURRENT_URL, $headline);

        // create html page object
        $page = PagePresenter::withHtmlIDAndHeadline('admidio-profile-edit', $headline);

        // show link to view profile field change history
        ChangelogService::displayHistoryButton($page, 'profile', 'users,user_data,user_relations,members', !empty($getUserUuid) && $gCurrentUser->hasRightEditProfile($user), array('uuid' => $getUserUuid));

        // create html form
        $form = new FormPresenter(
            'adm_profile_edit_form',
            'modules/profile.edit.tpl',
            SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/profile/profile_new.php', array('user_uuid' => $getUserUuid, 'mode' => 'save', 'accept_registration' => $getAcceptRegistration)),
            $page
        );

        // *******************************************************************************
        // Loop over all categories and profile fields
        // *******************************************************************************

        $category = '';
        $showLoginData = true;

        foreach ($gProfileFields->getProfileFields() as $field) {
            $showField = false;
            $category = $field->getValue('cat_name');

            // at registration check if the field is enabled for registration
            if (!$gValidLogin && $field->getValue('usf_registration') == 1) {
                $showField = true;
            } // check if the current user has the right to edit this profile field of the selected user
            elseif ($gValidLogin && $gCurrentUser->allowedEditProfileField($user, $field->getValue('usf_name_intern'))) {
                $showField = true;
            }

            // at category basic data show login information fields
            // if it's a new record or administrator or approval of new registration
            if ($field->getValue('cat_name_intern') === 'BASIC_DATA' && $showLoginData
                && (($user->getValue('usr_id') > 0 && $gCurrentUser->isAdministrator()) || $getUserUuid === '')) {
                $showLoginData = false;
                $fieldProperty = FormPresenter::FIELD_DEFAULT;

                if (!$gValidLogin || $getAcceptRegistration) {
                    $fieldProperty = FormPresenter::FIELD_REQUIRED;
                }

                $form->addInput(
                    'usr_login_name',
                    $gL10n->get('SYS_USERNAME'),
                    $user->getValue('usr_login_name'),
                    array(
                        'maxLength' => 254,
                        'property' => $fieldProperty,
                        'helpTextId' => 'SYS_USERNAME_DESCRIPTION',
                        'class' => 'form-control-small',
                        'autocomplete' => 'username',
                        'category' => $category
                    )
                );

                if (!$gValidLogin) {
                    // at registration add password and password confirm to form
                    $form->addInput(
                        'usr_password',
                        $gL10n->get('SYS_PASSWORD'),
                        '',
                        array(
                            'type' => 'password',
                            'property' => FormPresenter::FIELD_REQUIRED,
                            'minLength' => PASSWORD_MIN_LENGTH,
                            'passwordStrength' => true,
                            'helpTextId' => 'SYS_PASSWORD_DESCRIPTION',
                            'class' => 'form-control-small',
                            'autocomplete' => 'new-password',
                            'category' => $category
                        )
                    );
                    $form->addInput(
                        'adm_password_confirm',
                        $gL10n->get('SYS_CONFIRM_PASSWORD'),
                        '',
                        array(
                            'type' => 'password',
                            'property' => FormPresenter::FIELD_REQUIRED,
                            'minLength' => PASSWORD_MIN_LENGTH,
                            'class' => 'form-control-small',
                            'autocomplete' => 'new-password',
                            'category' => $category
                        )
                    );

                    // show selectbox with all organizations of database
                    if ($gCurrentOrganization->getValue('org_show_org_select')) {
                        $sql = 'SELECT org_id, org_longname
                                  FROM ' . TBL_ORGANIZATIONS . '
                              ORDER BY org_longname, org_shortname';
                        $form->addSelectBoxFromSql(
                            'adm_org_id',
                            $gL10n->get('SYS_ORGANIZATION'),
                            $gDb,
                            $sql,
                            array(
                                'property' => FormPresenter::FIELD_REQUIRED,
                                'defaultValue' => $registrationOrgId,
                                'category' => $category
                            )
                        );
                    }
                }
            }

            // only show fields that are enabled for registration or the user has permission to edit that field
            if ($showField) {
                // add profile fields to form
                $fieldProperty = FormPresenter::FIELD_DEFAULT;
                $helpId = '';
                $usfNameIntern = $field->getValue('usf_name_intern');

                if ($gProfileFields->getProperty($usfNameIntern, 'usf_disabled') == 1
                    && !$gCurrentUser->hasRightEditProfile($user, false) && $getUserUuid !== '') {
                    // disable field if this is configured in profile field configuration
                    $fieldProperty = FormPresenter::FIELD_DISABLED;
                } elseif ($gProfileFields->hasRequiredInput($usfNameIntern, $user->getValue('usr_id'), !$gValidLogin || $getAcceptRegistration)) {
                    $fieldProperty = FormPresenter::FIELD_REQUIRED;
                }

                if (strlen($gProfileFields->getProperty($usfNameIntern, 'usf_description')) > 0) {
                    $helpId = $gProfileFields->getProperty($gProfileFields->getProperty($usfNameIntern, 'usf_name_intern'), 'usf_description');
                    if (Admidio\Infrastructure\Language::isTranslationStringId($helpId)) {
                        $helpId = array($helpId, array($gProfileFields->getProperty($usfNameIntern, 'usf_name')));
                    }
                }

                // code for different field types
                if ($gProfileFields->getProperty($usfNameIntern, 'usf_type') === 'CHECKBOX') {
                    $form->addCheckbox(
                        $gProfileFields->getProperty($usfNameIntern, 'usf_name_intern'),
                        $gProfileFields->getProperty($usfNameIntern, 'usf_name'),
                        (bool)$user->getValue($usfNameIntern),
                        array(
                            'property' => $fieldProperty,
                            'helpTextId' => $helpId,
                            'icon' => 'bi-' . $gProfileFields->getProperty($usfNameIntern, 'usf_icon', 'database'),
                            'category' => $category
                        )
                    );
                } elseif ($gProfileFields->getProperty($usfNameIntern, 'usf_type') === 'DROPDOWN' || $gProfileFields->getProperty($usfNameIntern, 'usf_type') === 'DROPDOWN_MULTISELECT' || $usfNameIntern === 'COUNTRY') {
                    // set array with values and set default value
                    if ($usfNameIntern === 'COUNTRY') {
                        $arrOptions = $gL10n->getCountries();
                        $defaultValue = null;

                        if ((int)$user->getValue('usr_id') === 0 && strlen($gSettingsManager->getString('default_country')) > 0) {
                            $defaultValue = $gSettingsManager->getString('default_country');
                        } elseif ($user->getValue('usr_id') > 0 && strlen($user->getValue($usfNameIntern)) > 0) {
                            $defaultValue = $user->getValue($usfNameIntern, 'database');
                        }
                    } else {
                        $arrOptions = $gProfileFields->getProperty($usfNameIntern, 'ufo_usf_options', '', false);
                        $defaultValue = $user->getValue($usfNameIntern, 'database');
                        // if the field is a dropdown multiselect then convert the values to an array
                        if ($gProfileFields->getProperty($usfNameIntern, 'usf_type') === 'DROPDOWN_MULTISELECT') {
                            // prevent adding an empty string to the selectbox
                            $defaultValue = ($defaultValue !== "") ? explode(',', $defaultValue) : array();
                        }
                    }
                    
                    $form->addSelectBox(
                        $gProfileFields->getProperty($usfNameIntern, 'usf_name_intern'),
                        $gProfileFields->getProperty($usfNameIntern, 'usf_name'),
                        $arrOptions,
                        array(
                            'property' => $fieldProperty,
                            'defaultValue' => $defaultValue,
                            'helpTextId' => $helpId,
                            'icon' => 'bi-' . $gProfileFields->getProperty($usfNameIntern, 'usf_icon', 'database'),
                            'category' => $category,
                            'multiselect' => ($gProfileFields->getProperty($usfNameIntern, 'usf_type') === 'DROPDOWN_MULTISELECT') ? true : false,
                            'maximumSelectionNumber' => ($gProfileFields->getProperty($usfNameIntern, 'usf_type') === 'DROPDOWN_MULTISELECT') ? count($arrOptions) : 0,
                        )
                    );
                } elseif ($gProfileFields->getProperty($usfNameIntern, 'usf_type') === 'RADIO_BUTTON') {
                    $showDummyRadioButton = false;

                    if (!$gProfileFields->hasRequiredInput($usfNameIntern, $user->getValue('usr_id'), !$gValidLogin || $getAcceptRegistration)) {
                        $showDummyRadioButton = true;
                    }

                    $form->addRadioButton(
                        $gProfileFields->getProperty($usfNameIntern, 'usf_name_intern'),
                        $gProfileFields->getProperty($usfNameIntern, 'usf_name'),
                        $gProfileFields->getProperty($usfNameIntern, 'ufo_usf_options', 'html', false),
                        array(
                            'property' => $fieldProperty,
                            'defaultValue' => (int)$user->getValue($usfNameIntern, 'database'),
                            'showNoValueButton' => $showDummyRadioButton,
                            'helpTextId' => $helpId,
                            'icon' => 'bi-' . $gProfileFields->getProperty($usfNameIntern, 'usf_icon', 'database'),
                            'category' => $category
                        )
                    );
                } elseif ($gProfileFields->getProperty($usfNameIntern, 'usf_type') === 'TEXT_BIG') {
                    $form->addMultilineTextInput(
                        $gProfileFields->getProperty($usfNameIntern, 'usf_name_intern'),
                        $gProfileFields->getProperty($usfNameIntern, 'usf_name'),
                        $user->getValue($usfNameIntern),
                        3,
                        array(
                            'maxLength' => 4000,
                            'property' => $fieldProperty,
                            'helpTextId' => $helpId,
                            'icon' => 'bi-' . $gProfileFields->getProperty($usfNameIntern, 'usf_icon', 'database'),
                            'category' => $category
                        )
                    );
                } else {
                    $fieldType = 'text';

                    if ($gProfileFields->getProperty($usfNameIntern, 'usf_type') === 'DATE') {
                        $fieldType = 'date';
                        $maxlength = '10';
                    } elseif ($gProfileFields->getProperty($usfNameIntern, 'usf_type') === 'EMAIL') {
                        // email could not be longer than 254 characters
                        $fieldType = 'email';
                        $maxlength = '254';
                    } elseif ($gProfileFields->getProperty($usfNameIntern, 'usf_type') === 'URL') {
                        // maximal browser compatible url length will be 2000 characters
                        $maxlength = '2000';
                    } elseif ($gProfileFields->getProperty($usfNameIntern, 'usf_type') === 'NUMBER') {
                        $fieldType = 'number';
                        $maxlength = array(0, 9999999999, 1);
                    } elseif ($gProfileFields->getProperty($usfNameIntern, 'cat_name_intern') === 'SOCIAL_NETWORKS') {
                        $maxlength = '255';
                    } else {
                        $maxlength = '100';
                    }

                    $form->addInput(
                        $gProfileFields->getProperty($usfNameIntern, 'usf_name_intern'),
                        $gProfileFields->getProperty($usfNameIntern, 'usf_name'),
                        $user->getValue($usfNameIntern),
                        array(
                            'type' => $fieldType,
                            'maxLength' => $maxlength,
                            'property' => $fieldProperty,
                            'helpTextId' => $helpId,
                            'icon' => 'bi-' . $gProfileFields->getProperty($usfNameIntern, 'usf_icon', 'database'),
                            'category' => $category
                        )
                    );
                }
            }
        }

        // if captchas are enabled then visitors of the website must resolve this
        if (!$gValidLogin && $gSettingsManager->getBool('registration_enable_captcha')) {
            $form->addCaptcha('adm_captcha_code');
        }

        if (!$gValidLogin) {
            // Registration
            $form->addSubmitButton('adm_button_save', $gL10n->get('SYS_SEND'), array('icon' => 'bi-envelope-fill'));
        } else {
            $form->addSubmitButton('adm_button_save', $gL10n->get('SYS_SAVE'), array('icon' => 'bi-check-lg'));
        }

        if ($getUserUuid !== '') {
            // show information about user who creates the recordset and changed it
            $page->assignSmartyVariable('userCreatedName', $user->getNameOfCreatingUser());
            $page->assignSmartyVariable('userCreatedTimestamp', $user->getValue('ann_timestamp_create'));
            $page->assignSmartyVariable('lastUserEditedName', $user->getNameOfLastEditingUser());
            $page->assignSmartyVariable('lastUserEditedTimestamp', $user->getValue('ann_timestamp_change'));
        }

        $form->addToHtmlPage();
        $gCurrentSession->addFormObject($form);

        $page->show();
    } elseif ($getMode === 'save') {
        // ------------------------------------------------------------
        // Save all data of the profile form to the user object
        // ------------------------------------------------------------

        // check form field input and sanitized it from malicious content
        $profileEditForm = $gCurrentSession->getFormObject($_POST['adm_csrf_token']);
        $formValues = $profileEditForm->validate($_POST);

        // Login name and password must be checked during registration
        if (!$gValidLogin) {
            // Passwort muss mindestens 8 Zeichen lang sein
            if (strlen($_POST['usr_password']) < PASSWORD_MIN_LENGTH) {
                throw new Exception('SYS_PASSWORD_LENGTH');
            }

            // both password fields must be identical
            if ($_POST['usr_password'] !== $_POST['adm_password_confirm']) {
                throw new Exception('SYS_PASSWORDS_NOT_EQUAL');
            }

            if (PasswordUtils::passwordStrength($_POST['usr_password'], $user->getPasswordUserData()) < $gSettingsManager->getInt('password_min_strength')) {
                throw new Exception('SYS_PASSWORD_NOT_STRONG_ENOUGH');
            }
        }

        // write all profile fields to the user object
        foreach ($formValues as $key => $value) {
            if (strpos($key, 'usr_') !== 0 && !in_array($key, array('adm_password_confirm', 'adm_org_id', 'adm_captcha_code'))) {
                $user->setValue($key, $value);
            }
        }

        if (isset($_POST['usr_login_name']) && ($gCurrentUser->isAdministrator() || $getUserUuid === '')) {
            // Only administrators could change login name or within a new registration
            if ($_POST['usr_login_name'] !== $user->getValue('usr_login_name')) {
                if (strlen($_POST['usr_login_name']) > 0) {
                    // check if the username is already assigned
                    $sql = 'SELECT usr_uuid
                      FROM ' . TBL_USERS . '
                     WHERE usr_login_name = ?';
                    $pdoStatement = $gDb->queryPrepared($sql, array($_POST['usr_login_name']));

                    if ($pdoStatement->rowCount() > 0 && $pdoStatement->fetchColumn() !== $getUserUuid) {
                        throw new Exception('SYS_LOGIN_NAME_EXIST');
                    }
                }

                if (!$user->setValue('usr_login_name', $_POST['usr_login_name'])) {
                    throw new Exception('SYS_FIELD_INVALID_CHAR', array('SYS_USERNAME'));
                }
            }
        }

        // if registration, then still fill the corresponding fields
        if (!$gValidLogin) {
            $user->setPassword($_POST['usr_password']);
        }

        // ------------------------------------------------------------
        // Save user data to database
        // ------------------------------------------------------------
        $gDb->startTransaction();
        $user->save();
        $gDb->endTransaction();

        // if data of the logged-in user is changed, then update session variables
        if ((int)$user->getValue('usr_id') === $gCurrentUserId) {
            $gCurrentUser = $user;
        }

        // ------------------------------------------------------------
        // redirect to the correct page depending on the call mode
        // ------------------------------------------------------------

        if (!$gValidLogin) {
            // registration was successful then go to homepage
            $gNavigation->deleteLastUrl();
            echo json_encode(array(
                'status' => 'success',
                'message' => $gL10n->get('SYS_REGISTRATION_SAVED'),
                'url' => $gHomepage
            ));
            exit();
        } else {
            if ($getUserUuid === '' || $getAcceptRegistration) {
                // assign a registration or create a new user

                if ($getAcceptRegistration) {
                    // accept a registration, assign necessary roles and send a notification email
                    $user->acceptRegistration();
                    $messageId = 'SYS_ASSIGN_REGISTRATION_SUCCESSFUL';
                } else {
                    // a new user is created with the user management module
                    // then the user must get the necessary roles
                    $user->assignDefaultRoles();
                    $messageId = 'SYS_SAVE_DATA';
                }

                // if current user has the right to assign roles then show roles dialog
                // otherwise go to previous url (default roles are assigned automatically)
                if ($gCurrentUser->isAdministratorRoles()) {
                    echo json_encode(array(
                        'status' => 'success',
                        'url' => SecurityUtils::encodeUrl(
                            ADMIDIO_URL . FOLDER_MODULES . '/profile/roles.php',
                            array(
                                'user_uuid' => $user->getValue('usr_uuid'),
                                'accept_registration' => $getAcceptRegistration,
                                'new_user' => $getUserUuid === ''
                            ))
                    ));
                    exit();
                } else {
                    $gNavigation->deleteLastUrl();
                    echo json_encode(array(
                        'status' => 'success',
                        'message' => $messageId,
                        'url' => $gNavigation->getPreviousUrl()
                    ));
                    exit();
                }
            } elseif (!$user->getValue('usr_valid')) {
                // a registration was edited then go back to profile view
                $gNavigation->deleteLastUrl();
                echo json_encode(array('status' => 'success', 'url' => $gNavigation->getPreviousUrl()));
                exit();
            } else {
                // go back to profile view
                $gNavigation->deleteLastUrl();
                echo json_encode(array('status' => 'success', 'url' => $gNavigation->getUrl()));
                exit();
            }
        }
    }
} catch (Exception $e) {
    if ($getMode === 'save') {
        echo json_encode(array('status' => 'error', 'message' => $e->getMessage()));
    } else {
        $gMessage->show($e->getMessage());
    }
}
