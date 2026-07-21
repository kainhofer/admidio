<div class="card admidio-field-group mb-3">
    <div class="card-body">
        <form method="get" action="{$urlProviderList}" class="row g-2">
            <input type="hidden" name="mode" value="list">

            <div class="col">
                <input
                    type="text"
                    name="query"
                    value="{$query}"
                    class="form-control"
                    placeholder="{$l10n->get('SYS_REQ_PROVIDER_SEARCH')}">
            </div>

            <div class="col-auto">
                <button type="submit" class="btn btn-secondary">
                    <i class="bi bi-search"></i>{$l10n->get('SYS_SEARCH')}
                </button>
            </div>
        </form>
    </div>
</div>

<table class="table table-condensed table-hover">
    <thead>
        <tr>
            <th>{$l10n->get('SYS_NAME')}</th>
            <th>{$l10n->get('SYS_WEBSITE')}</th>
            <th>{$l10n->get('SYS_REQ_PROVIDER_QUALIFIED')}</th>
            <th>{$l10n->get('SYS_REQ_PROVIDER_PUBLIC')}</th>
            <th>{$l10n->get('SYS_REQ_PROVIDER_EDITABLE')}</th>
            <th>&nbsp;</th>
        </tr>
    </thead>
    <tbody>
        {foreach $providers as $provider}
            <tr id="adm_req_provider_{$provider.uuid}">
                <td>
                    <strong>{$provider.name}</strong>
                    {if $provider.description neq ''}
                        <div class="text-muted small">
                            {$provider.description}
                        </div>
                    {/if}
                </td>

                <td>
                    {if $provider.url neq ''}
                        <a href="{$provider.url}" target="_blank" rel="noopener">
                            {$provider.url}
                        </a>
                    {/if}
                </td>

                <td>
                    {if $provider.qualified}
                        <span class="badge bg-success">{$l10n->get('SYS_YES')}</span>
                    {else}
                        <span class="badge bg-secondary">{$l10n->get('SYS_NO')}</span>
                    {/if}
                </td>

                <td>
                    {if $provider.public}
                        {$l10n->get('SYS_YES')}
                    {else}
                        {$l10n->get('SYS_NO')}
                    {/if}
                </td>

                <td>
                    {if $provider.editable}
                        {$l10n->get('SYS_YES')}
                    {else}
                        {$l10n->get('SYS_NO')}
                    {/if}
                </td>

                <td class="text-end">
                    {foreach $provider.actions as $action}
                        {if isset($action.url)}
                            <a class="admidio-icon-link"
                               href="{$action.url}"
                               data-bs-toggle="tooltip"
                               title="{$action.tooltip}">
                                <i class="{$action.icon}"></i>
                            </a>
                        {else}
                            <a class="admidio-icon-link"
                               href="javascript:void(0);"
                               onclick="{$action.dataHref}"
                               data-bs-toggle="tooltip"
                               title="{$action.tooltip}"
                               data-message="{$action.dataMessage}">
                                <i class="{$action.icon}"></i>
                            </a>
                        {/if}
                    {/foreach}
                </td>
            </tr>
        {foreachelse}
            <tr>
                <td colspan="6">{$l10n->get('SYS_NO_ENTRIES')}</td>
            </tr>
        {/foreach}
    </tbody>
</table>
