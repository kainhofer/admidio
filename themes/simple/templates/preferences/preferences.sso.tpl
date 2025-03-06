<form {foreach $attributes as $attribute}
        {$attribute@key}="{$attribute}"
    {/foreach}>
    {include 'sys-template-parts/form.input.tpl' data=$elements['adm_csrf_token']}

    {include 'sys-template-parts/form.custom-content.tpl' data=$elements['sso_keys']}

    {$elements['sso_saml_settings'].content}
    {include 'sys-template-parts/form.checkbox.tpl' data=$elements['sso_saml_enabled']}
    {include 'sys-template-parts/form.input.tpl' data=$elements['sso_saml_entity_id']}
    {include 'sys-template-parts/form.select.tpl' data=$elements['sso_saml_signing_key']}
    {include 'sys-template-parts/form.select.tpl' data=$elements['sso_saml_encryption_key']}

    {include 'sys-template-parts/form.custom-content.tpl' data=$elements['sso_saml_sso_staticsettings']}
    {include 'sys-template-parts/form.custom-content.tpl' data=$elements['sso_saml_clients']}

    {$elements['sso_oidc_settings'].content}
    {include 'sys-template-parts/form.checkbox.tpl' data=$elements['sso_oidc_enabled']}
    {include 'sys-template-parts/form.custom-content.tpl' data=$elements['sso_oidc_clients']}

    {include 'sys-template-parts/form.button.tpl' data=$elements['adm_button_save_sso']}
    <div class="form-alert" style="display: none;">&nbsp;</div>
</form>
