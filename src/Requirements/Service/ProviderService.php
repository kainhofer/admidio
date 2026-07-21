<?php
/**
 * @copyright The Admidio Team
 * @see https://www.admidio.org/
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License v2.0 only
 */

namespace Admidio\Requirements\Service;

use Admidio\Components\Entity\Component;
use Admidio\Infrastructure\Database;
use Admidio\Infrastructure\Exception;
use Admidio\Requirements\Entity\Provider;
use Admidio\UI\Presenter\FormPresenter;

class ProviderService
{
    protected Database $db;
    protected Provider $provider;

    /**
     * Constructor.
     *
     * @param Database $database     Database object.
     * @param string   $providerUuid UUID of the provider.
     *
     * @throws Exception
     */
    public function __construct(Database $database, string $providerUuid = '')
    {
        $this->db = $database;
        $this->provider = new Provider($database);

        if ($providerUuid !== '') {
            $this->provider->readDataByUuid($providerUuid);
        }
    }

    /**
     * Save data from the provider form into the database.
     *
     * @throws Exception
     */
    public function save(): void
    {
        global $gCurrentOrgId, $gCurrentSession;

        $providerEditForm = $gCurrentSession->getFormObject($_POST['adm_csrf_token']);
        $formValues = $providerEditForm->validate($_POST);

        if (!empty($this->provider->getValue('rqp_id'))) {
            if (!$this->provider->isEditable()) {
                throw new Exception('SYS_NO_RIGHTS');
            }
        } else {
            $this->provider->setValue('rqp_org_id', $gCurrentOrgId);
        }

        $this->db->startTransaction();

        foreach ($formValues as $key => $value) {
            if (
                str_starts_with($key, 'rqp_')
                && !in_array($key, array('rqp_public', 'rqp_editable', 'rqp_qualified'), true)
            ) {
                $this->provider->setValue($key, $value);
            }
        }

        if (Component::isAdministrable('REQUIREMENTS')) {
            $this->provider->setValue('rqp_qualified', isset($_POST['rqp_qualified']));
        } elseif (empty($this->provider->getValue('rqp_id'))) {
            $this->provider->setValue('rqp_qualified', false);
        }

        if (
            empty($this->provider->getValue('rqp_id'))
            || $this->provider->canChangeVisibilityFlags()
        ) {
            $this->provider->setValue('rqp_public', isset($_POST['rqp_public']));
            $this->provider->setValue('rqp_editable', isset($_POST['rqp_editable']));
        }

        $this->provider->save();

        $this->db->endTransaction();
    }
}
