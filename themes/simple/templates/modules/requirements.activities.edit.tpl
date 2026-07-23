<form {foreach $attributes as $attribute}
        {$attribute@key}="{$attribute}"
    {/foreach}>
    <div class="admidio-form-required-notice"><span>{$l10n->get('SYS_REQUIRED_INPUT')}</span></div>

    {include 'sys-template-parts/form.input.tpl' data=$elements['adm_csrf_token']}
    <div class="card admidio-field-group">
        <div class="card-header">{$l10n->get('SYS_VISIBILITY')} &amp; {$l10n->get('SYS_REGISTRATION')}</div>
        <div class="card-body">
            {include 'sys-template-parts/form.input.tpl' data=$elements['rqa_title']}
            {include 'sys-template-parts/form.multiline.tpl' data=$elements['rqa_description']}
            {include 'sys-template-parts/form.input.tpl' data=$elements['rqa_url']}
            {include 'sys-template-parts/form.multiline.tpl' data=$elements['rqa_location']}
            {include 'sys-template-parts/form.select.tpl' data=$elements['rqa_provider_id']}
        </div>
    </div>
    <div class="card admidio-field-group">
        <div class="card-header">{$l10n->get('SYS_PERIOD')}</div>
        <div class="card-body">

            {include 'sys-template-parts/form.checkbox.tpl' data=$elements['rqa_full_day']}
            <div id="adm_req_activity_period">
                {include 'sys-template-parts/form.input.tpl' data=$elements['rqa_begin']}
                {include 'sys-template-parts/form.input.tpl' data=$elements['rqa_end']}
            </div>

            {include 'sys-template-parts/form.input.tpl' data=$elements['rqa_attendance']}
        </div>
    </div>
    <div class="card admidio-field-group">
        <div class="card-header">{$l10n->get('SYS_COMMENT')}, {$l10n->get('SYS_REQ_STATUS')} & {$l10n->get('SYS_REQ_REVIEW')}</div>
        <div class="card-body">
            {include 'sys-template-parts/form.multiline.tpl' data=$elements['rqa_comments']}
            {if {array_key_exists array=$elements key='rqa_status'}}
                {include 'sys-template-parts/form.select.tpl' data=$elements['rqa_status']}
            {/if}
            {if {array_key_exists array=$elements key='rqa_review_status'}}
                {include 'sys-template-parts/form.select.tpl' data=$elements['rqa_review_status']}
            {/if}
            {if {array_key_exists array=$elements key='rqa_review_comments'}}
                {include 'sys-template-parts/form.multiline.tpl' data=$elements['rqa_review_comments']}
            {/if}
        </div>
    </div>
    {include 'sys-template-parts/form.button.tpl' data=$elements['adm_button_save']}
    {include file="sys-template-parts/system.info-create-edit.tpl"}
</form>
