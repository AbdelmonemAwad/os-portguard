{#
 # SPDX-License-Identifier: BSD-2-Clause
 # Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 #
 # Firewall: Port Guard (XGS: Port Guard when os-xgs-npu is installed) - the devices blocked by their
 # MAC address, and the devices the firewall sees, each a click from being blocked.
 #}

<style>
    /* KIT-CSS-BEGIN */
    .xgs-cards { display: flex; flex-wrap: wrap; gap: 12px; padding: 15px; }
    .xgs-cards.xgs-top { padding: 0 0 15px; }
    .xgs-card { flex: 1 1 200px; min-width: 190px; border: 1px solid rgba(128, 128, 128, 0.25);
                border-inline-start: 4px solid #9e9e9e; border-radius: 3px; padding: 10px 14px;
                background-color: rgba(128, 128, 128, 0.04); }
    .xgs-card.ok { border-inline-start-color: #5cb85c; }
    .xgs-card.warn { border-inline-start-color: #f0ad4e; }
    .xgs-card.bad { border-inline-start-color: #d9534f; }
    .xgs-card .k { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; opacity: 0.6; }
    .xgs-card .v { font-size: 19px; font-weight: 600; line-height: 1.3; margin: 2px 0; }
    .xgs-card .s { font-size: 12px; opacity: 0.7; }
    .xgs-card .fa { opacity: 0.35; float: inline-end; font-size: 18px; margin-top: 2px; }
    .xgs-head { padding-top: 5px; padding-bottom: 5px; font-size: 16px; }
    /* KIT-CSS-END */
    /* A grid whose columns fill the width shows a one-pixel sideways bar when no vertical one takes
       the difference; wide screens never need to scroll it sideways. */
    @media (min-width: 768px) {
        #{{ formGridDevice['table_id'] }} .tabulator-tableholder, #grid-seen .tabulator-tableholder { overflow-x: hidden; }
    }
</style>

<script>
    $(document).ready(function () {
        /* KIT-JS-BEGIN */
        /* A string as OPNsense's API and Volt's lang._() hand it over - escaped - made plain for .text(). */
        function plain(value) {
            return $('<textarea/>').html(value === null || value === undefined ? '' : String(value)).text();
        }

        /* One card: cls '' (grey, no judgement), 'ok', 'warn' or 'bad'; icon a Font Awesome name. */
        function card(cls, icon, key, value, sub) {
            return $('<div class="xgs-card"/>').addClass(cls)
                .append($('<i class="fa"/>').addClass(icon))
                .append($('<div class="k"/>').text(plain(key)))
                .append($('<div class="v"/>').text(plain(value)))
                .append($('<div class="s"/>').text(plain(sub || ' ')));
        }

        /* Until the first reading: the same cards, their keys, and an ellipsis for every value. */
        function cards_wait(target, keys) {
            $(target).empty();
            $.each(keys, function (i, key) {
                $(target).append(card('', 'fa-ellipsis-h', key, '…', ''));
            });
        }

        /* The selected tab kept in the address, as on OPNsense's own tabbed pages. */
        function keep_tab() {
            if (window.location.hash !== '') {
                $('a[href="' + window.location.hash + '"]').tab('show');
            }
            $('.nav-tabs a').on('shown.bs.tab', function (e) {
                history.pushState(null, null, e.target.hash);
            });
        }
        /* KIT-JS-END */

        /* A device with several addresses - IPv4, IPv6, a link-local one - is a row of status.py's list
           for each; the cards count devices, by MAC address (2026-10-29: they counted rows, so a device
           with three addresses was three devices). */
        function devices(rows) {
            return new Set(rows.map(function (d) { return d.mac; })).size;
        }

        function draw(data) {
            const $cards = $('#pg-cards').empty();
            if (!data || data.error) {
                $cards.append(card('bad', 'fa-shield', "{{ lang._('Port Guard') }}", "{{ lang._('Status could not be read.') }}", ''));
                return;
            }
            const present = devices(data.seen.filter(function (d) { return d.listed; }));
            $cards.append(card(!data.enabled ? '' : (data.listed.length ? 'ok' : ''), 'fa-shield', "{{ lang._('Devices listed') }}",
                data.enabled ? String(data.listed.length) : "{{ lang._('off') }}",
                present + ' ' + "{{ lang._('of them seen now') }}"));
            $cards.append(card(data.blocked_now.length ? 'ok' : '', 'fa-ban', "{{ lang._('Addresses blocked now') }}",
                String(data.blocked_now.length), data.blocked_now.slice(0, 3).join(' ')));
            const packets = (data.counters.in || 0) + (data.counters.out || 0);
            $cards.append(card('', 'fa-filter', "{{ lang._('Blocked') }}", packets.toLocaleString(),
                "{{ lang._('packets since table loaded') }}"));
            $cards.append(card('', 'fa-sitemap', "{{ lang._('Devices seen') }}", String(devices(data.seen)),
                data.source === 'discovery' ? "{{ lang._('from host discovery') }}" : "{{ lang._('from the ARP and NDP tables') }}"));
        }

        function refresh() {
            ajaxGet('/api/portguard/service/status', {}, draw);
        }

        $("#{{ formGridDevice['table_id'] }}").UIBootgrid({
            search: '/api/portguard/settings/search_device',
            get: '/api/portguard/settings/get_device/',
            set: '/api/portguard/settings/set_device/',
            add: '/api/portguard/settings/add_device/',
            del: '/api/portguard/settings/del_device/',
            toggle: '/api/portguard/settings/toggle_device/'
        });

        /* The devices the firewall sees, from the same status script; the API escapes what it
           returns, so nothing here escapes it again. */
        $('#grid-seen').UIBootgrid({
            search: '/api/portguard/service/search_seen',
            options: {
                selection: false,
                formatters: {
                    mono: function (column, row) {
                        return '<code>' + row[column.id] + '</code>';
                    },
                    block: function (column, row) {
                        if (row.listed) {
                            return '<span class="label label-danger">' + "{{ lang._('blocked') }}" + '</span>';
                        }
                        const quoted = function (v) {
                            return String(v === null || v === undefined ? '' : v).replace(/"/g, '&quot;');
                        };
                        return '<button type="button" class="btn btn-default btn-xs pg-block" data-row-id="' + quoted(row.mac) +
                            '" data-ip="' + quoted(row.ip) + '" data-vendor="' + quoted(row.vendor) + '">' + "{{ lang._('Block') }}" + '</button>';
                    }
                }
            }
        });

        $(document).on('click', '.pg-block', function () {
            const mac = $(this).attr('data-row-id') || '';
            const ip = $(this).attr('data-ip') || '';
            const vendor = $(this).attr('data-vendor') || '';
            stdDialogConfirm("{{ lang._('Block this device') }}",
                "{{ lang._('Nothing will pass the firewall to or from it once applied - this page included, if it is the device you are using now.') }}" +
                '<br/><br/><code>' + $('<div/>').text(mac + '  ' + ip).html() + '</code>',
                "{{ lang._('Yes') }}", "{{ lang._('Cancel') }}", function () {
                    ajaxCall('/api/portguard/settings/add_device', {'device': {'enabled': '1', 'mac': mac,
                        'description': vendor + ' ' + ip}}, function (data) {
                        if (!data || data.result !== 'saved') {
                            /* Refused - listed already, though switched off, say: the model's reasons,
                               not the note that the list has changed, which it has not (2026-10-29). */
                            const reasons = data && data.validations ? Object.values(data.validations) : [];
                            if (reasons.length) {
                                stdDialogInform("{{ lang._('Block this device') }}",
                                    $('<div/>').text(reasons.map(plain).join(' ')).html(), "{{ lang._('Close') }}");
                            }
                            $("#{{ formGridDevice['table_id'] }}").bootgrid('reload');
                            return;
                        }
                        $("#{{ formGridDevice['table_id'] }}").bootgrid('reload');
                        $('#grid-seen').bootgrid('reload');
                        $('#pg-apply-needed').show();
                        refresh();
                    });
                });
        });

        /* Apply is the Settings form's own button: the note takes the reader there. */
        $('#pg-apply-go').click(function (e) {
            e.preventDefault();
            $('#maintabs a[href="#settings"]').tab('show');
        });

        /* the cards, and the list of the tab on screen */
        $('#refreshAct').click(function () {
            refresh();
            const tab = $('#maintabs li.active a').attr('href');
            if (tab === '#devices') {
                $("#{{ formGridDevice['table_id'] }}").bootgrid('reload');
            } else if (tab === '#seen') {
                $('#grid-seen').bootgrid('reload');
            }
        });

        mapDataToFormUI({'frm_general': '/api/portguard/settings/get'}).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });

        $('#applyAct').click(function () {
            const $button = $(this).prop('disabled', true);
            const $progress = $('#frm_general_progress').addClass('fa fa-spinner fa-pulse');
            const done = function () {
                $progress.removeClass('fa fa-spinner fa-pulse');
                $button.prop('disabled', false);
            };
            saveFormToEndpoint('/api/portguard/settings/set', 'frm_general', function () {
                ajaxCall('/api/portguard/service/apply', {}, function (data) {
                    done();
                    const lines = (data && data.changes ? data.changes : []).concat(data && data.errors ? data.errors : []);
                    $('#pg-result').attr('class', data && data.status === 'ok' ? 'text-muted' : 'alert alert-danger')
                        .text(plain(lines.length ? lines.join(' · ') : "{{ lang._('Nothing to change.') }}")).show();
                    $('#pg-apply-needed').hide();
                    refresh();
                    $('#grid-seen').bootgrid('reload');
                });
            }, false, done);
        });

        cards_wait('#pg-cards', ["{{ lang._('Devices listed') }}", "{{ lang._('Addresses blocked now') }}",
            "{{ lang._('Blocked') }}", "{{ lang._('Devices seen') }}"]);
        refresh();
        keep_tab();
    });
</script>

<div class="xgs-cards xgs-top" id="pg-cards"></div>
<div class="text-muted clearfix" style="padding: 0 0 10px;">
    <button id="refreshAct" class="btn btn-default btn-xs pull-right" type="button" title="{{ lang._('Refresh') }}"><i class="fa fa-fw fa-refresh"></i></button>
    {{ lang._('A listed device is stopped at the firewall: nothing it sends passes through it, and nothing reaches it through it. Two devices behind the same switch still reach each other - their frames never come to the firewall.') }}
</div>
<div id="pg-apply-needed" style="display: none; padding: 0 0 10px;">
    <a href="#settings" id="pg-apply-go" class="text-warning">{{ lang._('List changed; Apply puts it into the firewall.') }}</a>
</div>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#devices">{{ lang._('Blocked devices') }}</a></li>
    <li><a data-toggle="tab" href="#seen">{{ lang._('Devices seen') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="devices" class="tab-pane active">
        {{ partial('layout_partials/base_bootgrid_table', formGridDevice) }}
    </div>
    <div id="seen" class="tab-pane">
        <table id="grid-seen" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="id" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="interface" data-type="string">{{ lang._('Interface') }}</th>
                    <th data-column-id="mac" data-formatter="mono" data-type="string">{{ lang._('MAC address') }}</th>
                    <th data-column-id="ip" data-type="string">{{ lang._('IP address') }}</th>
                    <th data-column-id="vendor" data-type="string">{{ lang._('Maker') }}</th>
                    <th data-column-id="commands" data-formatter="block" data-sortable="false" data-width="7em">{{ lang._('Commands') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot></tfoot>
        </table>
    </div>
    <div id="settings" class="tab-pane">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general', 'apply_btn_id': 'applyAct']) }}
        <div style="padding: 0 15px 15px;"><div id="pg-result" style="display: none;"></div></div>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': deviceForm, 'id': formGridDevice['edit_dialog_id'], 'label': lang._('Edit device')]) }}

{{ partial("OPNsense/PortGuard/credit") }}
