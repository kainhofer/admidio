<div class="card admidio-field-group mb-3">
    <div class="card-body">
        <form method="get" action="{$urlActivityList}" class="row g-2">
            <input type="hidden" name="mode" value="list">

            <div class="col">
                <input
                    type="text"
                    name="query"
                    value="{$query}"
                    class="form-control"
                    placeholder="{$l10n->get('SYS_REQ_ACTIVITY_SEARCH')}">
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
            <th>{$l10n->get('SYS_TITLE')}</th>
            <th>{$l10n->get('SYS_REQ_PROVIDER')}</th>
            <th>{$l10n->get('SYS_DATE')}</th>
            <th>{$l10n->get('SYS_REQ_ATTENDANCE')}</th>
            <th>&nbsp;</th>
        </tr>
    </thead>
    <tbody>
        {foreach $activities as $activity}
            <tr id="adm_req_activity_{$activity.uuid}">
                <td>
                    <strong>{$activity.title}</strong>
                </td>

                <td>
                    {$activity.providerName}
                </td>

                <td>
                    {$activity.beginDate}
                    {if $activity.beginTime neq ''}
                        {$activity.beginTime}
                    {/if}

                    {if $activity.endDate neq ''}
                        &ndash; {$activity.endDate}
                        {if $activity.endTime neq ''}
                            {$activity.endTime}
                        {/if}
                    {/if}
                </td>

                <td>
                    {$activity.attendance}
                </td>

                <td class="text-end">
                    {foreach $activity.actions as $action}
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
                <td colspan="5">{$l10n->get('SYS_NO_ENTRIES')}</td>
            </tr>
        {/foreach}
    </tbody>
</table>