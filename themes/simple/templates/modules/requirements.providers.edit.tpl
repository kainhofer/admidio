<form {foreach $attributes as $attribute}
        {$attribute@key}="{$attribute}"
    {/foreach}>
    <div class="admidio-form-required-notice"><span>{$l10n->get('SYS_REQUIRED_INPUT')}</span></div>

    <div class="card admidio-field-group">
        <div class="card-header">{$l10n->get('SYS_REQ_PROVIDER_INFO')}</div>
        <div class="card-body">
            {include 'sys-template-parts/form.input.tpl' data=$elements['adm_csrf_token']}

            {include 'sys-template-parts/form.input.tpl' data=$elements['rqp_name']}
            {include 'sys-template-parts/form.input.tpl' data=$elements['rqp_short_name']}
            {include 'sys-template-parts/form.multiline.tpl' data=$elements['rqp_address']}
            {include 'sys-template-parts/form.input.tpl' data=$elements['rqp_url']}
            {include 'sys-template-parts/form.multiline.tpl' data=$elements['rqp_description']}
        </div>
    </div>
    <div class="card admidio-field-group">
        <div class="card-header">{$l10n->get('SYS_PROPERTIES')}</div>
        <div class="card-body">

            {if {array_key_exists array=$elements key='rqp_qualified'}}
                {include 'sys-template-parts/form.checkbox.tpl' data=$elements['rqp_qualified']}
            {/if}
            {if {array_key_exists array=$elements key='rqp_public'}}
                {include 'sys-template-parts/form.checkbox.tpl' data=$elements['rqp_public']}
            {/if}
            {if {array_key_exists array=$elements key='rqp_editable'}}
                {include 'sys-template-parts/form.checkbox.tpl' data=$elements['rqp_editable']}
            {/if}
        </div>
    </div>

    <div class="form-alert" style="display: none;">&nbsp;</div>
    {include 'sys-template-parts/form.button.tpl' data=$elements['adm_button_save']}
    {include file="sys-template-parts/system.info-create-edit.tpl"}
</form>
