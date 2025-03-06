<script type="text/javascript">
    $("#adm_password_edit_form").submit(formSubmit);
</script>

<div class="modal-header">
    <h3 class="modal-title">{$l10n->get('SYS_SSO_EXPORT_PASSWORD')}</h3>
    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
</div>
<div class="modal-body">
    <form {foreach $attributes as $attribute}
            {$attribute@key}="{$attribute}"
        {/foreach}>
        <div class="admidio-form-required-notice"><span>{$l10n->get('SYS_REQUIRED_INPUT')}</span></div>

        {include 'sys-template-parts/form.input.tpl' data=$elements['adm_csrf_token']}
        {include 'sys-template-parts/form.input.tpl' data=$elements['key_password']}
        <div class="form-alert" style="display: none;">&nbsp;</div>
        {include 'sys-template-parts/form.button.tpl' data=$elements['adm_button_save']}
    </form>
</div>
