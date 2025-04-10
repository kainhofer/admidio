
<div id="{$data.id}_group" class="admidio-form-group
    {if $formType neq "vertical" and $formType neq "navbar"}row{/if}
    {if $formType neq "navbar"} mb-3{/if}
    {if $data.property eq 1} admidio-form-group-required{/if}">
    <label for="{$data.id}" class="{if $formType neq "vertical" and $formType neq "navbar"}col-sm-3 col-form-label{else}form-label{/if}">
        {include file="sys-template-parts/parts/form.part.icon.tpl"}
        {$data.label}
    </label>
    <div {if $formType neq "vertical" and $formType neq "navbar"} class="col-sm-9"{/if}>
        <p id="{$data.id}" class="form-control-static {$data.class}">{$data.value}</p>

        {if $formType eq "navbar"}
            {include file="sys-template-parts/parts/form.part.iconhelp.tpl"}
        {else}
            {include file="sys-template-parts/parts/form.part.helptext.tpl"}
        {/if}
        {include file="sys-template-parts/parts/form.part.warning.tpl"}
    </div>
</div>
