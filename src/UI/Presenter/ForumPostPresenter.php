<?php

namespace Admidio\UI\Presenter;

use Admidio\Forum\Entity\Post;
use Admidio\Infrastructure\Exception;
use Admidio\Infrastructure\Utils\SecurityUtils;
use Admidio\Changelog\Service\ChangelogService;

/**
 * @brief Class with methods to display the module pages of the registration.
 *
 * This class adds some functions that are used in the registration module to keep the
 * code easy to read and short
 *
 * **Code example**
 * ```
 * // generate html output with available registrations
 * $page = new ModuleRegistration('admidio-registration', $headline);
 * $page->createRegistrationList();
 * $page->show();
 * ```
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 */
class ForumPostPresenter extends PagePresenter
{
    /**
     * @var string UUID of the post.
     */
    protected string $postUUID = '';

    /**
     * Constructor creates the page object and initialized all parameters.
     * @param string $postUUID UUID of the post.
     * @throws Exception
     */
    public function __construct(string $postUUID = '')
    {
        $this->postUUID = $postUUID;
        parent::__construct($postUUID);
    }

    /**
     * Create the data for the edit form of a forum post.
     * @param string $topicUUID UUID of the topic that must be set if a new post is created.
     * @throws Exception
     */
    public function createEditForm(string $topicUUID = ''): void
    {
        global $gDb, $gL10n, $gCurrentSession;

        // create post object
        $post = new Post($gDb);

        if ($this->postUUID !== '') {
            $post->readDataByUuid($this->postUUID);
        }

        $this->setHtmlID('adm_forum_post_edit');
        if ($this->postUUID !== '') {
            $this->setHeadline($gL10n->get('SYS_EDIT_POST'));
        } else {
            $this->setHeadline($gL10n->get('SYS_CREATE_POST'));
        }

        // show form
        $form = new FormPresenter(
            'adm_forum_post_edit_form',
            'modules/forum.posts.edit.tpl',
            SecurityUtils::encodeUrl(ADMIDIO_URL . FOLDER_MODULES . '/forum.php',
                array(
                    'post_uuid' => $this->postUUID,
                    'topic_uuid' => $topicUUID,
                    'mode' => 'post_save'
                )
            ),
            $this
        );
        global $gCurrentUser;
        ChangelogService::displayHistoryButton($this, 'forum', 'forum_posts',
                $this->postUUID !== '' && $gCurrentUser->isAdministratorForum(), ['uuid' => $this->postUUID]);
        $form->addEditor(
            'fop_text',
            $gL10n->get('SYS_TEXT'),
            $post->getValue('fop_text'),
            array('property' => FormPresenter::FIELD_REQUIRED)
        );
        $form->addSubmitButton(
            'adm_button_save',
            $gL10n->get('SYS_SAVE'),
            array('icon' => 'bi-check-lg')
        );

        $this->smarty->assign('userCreatedName', $post->getNameOfCreatingUser());
        $this->smarty->assign('userCreatedTimestamp', $post->getValue('fot_timestamp_create'));
        $this->smarty->assign('lastUserEditedName', $post->getNameOfLastEditingUser());
        $this->smarty->assign('lastUserEditedTimestamp', $post->getValue('fop_timestamp_change'));
        $form->addToHtmlPage();
        $gCurrentSession->addFormObject($form);
    }
}
