<form {foreach $attributes as $attribute}
        {$attribute@key}="{$attribute}"
    {/foreach}>
    <div class="admidio-form-required-notice"><span>{$l10n->get('SYS_REQUIRED_INPUT')}</span></div>

    {include 'sys-template-parts/form.input.tpl' data=$elements['adm_csrf_token']}
    <div class="card admidio-field-group">
        <div class="card-header">{$l10n->get('SYS_SSO_AUTO_SETUP')}</div>
        <div class="card-body">
            {include 'sys-template-parts/form.input.tpl' data=$elements['smc_metadata_url']}
            {include 'sys-template-parts/form.button.tpl' data=$elements['adm_button_metadata_setup']}
        </div>
    </div>
    <div class="card admidio-field-group">
        <div class="card-header">{$l10n->get('SYS_NAME')} &amp; {$l10n->get('SYS_PROPERTIES')}</div>
        <div class="card-body">
            {include 'sys-template-parts/form.input.tpl' data=$elements['smc_client_name']}
            {include 'sys-template-parts/form.input.tpl' data=$elements['smc_client_id']}
            {include 'sys-template-parts/form.input.tpl' data=$elements['smc_acs_url']}
            {include 'sys-template-parts/form.input.tpl' data=$elements['smc_slo_url']}
            {include 'sys-template-parts/form.multiline.tpl' data=$elements['smc_x509_certificate']}
            {include 'sys-template-parts/form.select.tpl' data=$elements['sso_saml_roles']}
        </div>
    </div>
    <div class="form-alert" style="display: none;">&nbsp;</div>
    {include 'sys-template-parts/form.button.tpl' data=$elements['adm_button_save']}
    {include file="sys-template-parts/system.info-create-edit.tpl"}
</form>
