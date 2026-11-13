{#
 # Copyright (C) 2026 Édouard Biton
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<script>
    $(document).ready(function () {
        mapDataToFormUI({'frm_general': '/api/shopguard/settings/get'}).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });

        function refreshStatus() {
            ajaxGet('/api/shopguard/service/status', {}, function (data) {
                if (data.status === 'ok') {
                    $('#st_worker').text('{{ lang._('Reachable') }} (' + data.version + ')');
                    $('#st_pending').text(data.pending);
                } else {
                    $('#st_worker').text(data.message || '{{ lang._('Unreachable') }}');
                    $('#st_pending').text('');
                }
                var c = data.collect;
                if (!c) {
                    $('#st_collect').text('{{ lang._('Not run yet') }}');
                } else {
                    var when = new Date(c.time * 1000).toLocaleString();
                    if (c.status === 'ok') {
                        $('#st_collect').text(when + ': ' + c.queued + ' {{ lang._('new domains sent') }}');
                    } else if (c.status === 'error') {
                        $('#st_collect').text(when + ': ' + c.message);
                    } else {
                        $('#st_collect').text(when + ': ' + c.status);
                    }
                }
            });
        }

        $('#btn_save').click(function () {
            saveFormToEndpoint('/api/shopguard/settings/set', 'frm_general', function () {
                // (re)creates or removes the collection cron job
                ajaxCall('/api/shopguard/service/reconfigure', {}, function () {
                    refreshStatus();
                });
            });
        });

        refreshStatus();

        // Text from the worker comes partly from hostile sites (certificate fields…):
        // always inserted as text, never as HTML.
        function esc(value) {
            return $('<div/>').text(value === null || value === undefined ? '' : String(value)).html()
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        function scoreClass(score) {
            if (score >= {{ threshold }}) return 'danger';
            if (score >= 50) return 'warning';
            return 'default';
        }

        $('#grid-verdicts').UIBootgrid({
            search: '/api/shopguard/service/verdicts',
            options: {
                sorting: false,
                selection: false,
                rowSelect: false,
                rowCount: [25, 50, 100, 500],
                requestHandler: function (request) {
                    request['min_score'] = parseInt($('#min_score').val(), 10) || 0;
                    return request;
                },
                responseHandler: function (response) {
                    $('#verdicts_message').text(response.message || '').toggle(!!response.message);
                    return response;
                },
                formatters: {
                    score: function (column, row) {
                        return '<span class="label label-' + scoreClass(row.score) + '">' + esc(row.score) + '</span>';
                    },
                    checked: function (column, row) {
                        return row.checked_at ? esc(new Date(row.checked_at * 1000).toLocaleString()) : '';
                    },
                    signals: function (column, row) {
                        return (row.signals || []).filter(function (s) { return s.weight !== 0; }).map(function (s) {
                            return esc(s.name) + ' ' + (s.weight > 0 ? '+' : '') + esc(s.weight);
                        }).join(', ');
                    },
                    details: function (column, row) {
                        return '<button type="button" class="btn btn-xs btn-default verdict-details" data-row-id="' +
                            esc(row.domain) + '" title="{{ lang._('Signals') }}"><span class="fa fa-fw fa-info-circle"></span></button>';
                    }
                }
            }
        }).on('loaded.rs.jquery.bootgrid', function () {
            var rows = $(this).bootgrid('getCurrentRows');
            $(this).find('.verdict-details').off('click').on('click', function () {
                var domain = $(this).data('row-id');
                var row = rows.filter(function (r) { return r.domain === domain; })[0];
                if (!row) return;
                var table = $('<table class="table table-condensed"/>');
                $('<tr/>')
                    .append($('<th/>').text('{{ lang._('Analyzer') }}'))
                    .append($('<th/>').text('{{ lang._('Signal') }}'))
                    .append($('<th/>').text('{{ lang._('Weight') }}'))
                    .append($('<th/>').text('{{ lang._('Detail') }}'))
                    .appendTo(table);
                (row.signals || []).forEach(function (s) {
                    $('<tr/>')
                        .append($('<td/>').text(s.source))
                        .append($('<td/>').text(s.name))
                        .append($('<td/>').text((s.weight > 0 ? '+' : '') + s.weight))
                        .append($('<td/>').text(s.detail))
                        .appendTo(table);
                });
                BootstrapDialog.show({
                    title: $('<span/>').text(row.domain + ' — {{ lang._('score') }} ' + row.score),
                    message: table,
                    size: BootstrapDialog.SIZE_WIDE,
                    buttons: [{label: '{{ lang._('Close') }}', action: function (dlg) { dlg.close(); }}]
                });
            });
        });

        $('#min_score').on('change', function () {
            $('#grid-verdicts').bootgrid('reload');
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#verdicts">{{ lang._('Verdicts') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
</ul>

<div class="tab-content content-box">
<div id="verdicts" class="tab-pane fade in active">
    <div class="form-inline" style="padding: 1em 1em 0;">
        <label for="min_score">{{ lang._('Minimum score') }}</label>
        <select id="min_score" class="form-control" style="width: auto; margin-left: .5em;">
            <option value="0" selected="selected">0 ({{ lang._('all') }})</option>
            <option value="1">1</option>
            <option value="30">30</option>
            <option value="50">50</option>
            <option value="{{ threshold }}">{{ threshold }} ({{ lang._('blocking threshold') }})</option>
        </select>
        <span id="verdicts_message" class="text-danger" style="margin-left: 1em; display: none;"></span>
    </div>
    <table id="grid-verdicts" class="table table-condensed table-hover table-striped">
        <thead>
            <tr>
                <th data-column-id="domain" data-type="string" data-identifier="true">{{ lang._('Domain') }}</th>
                <th data-column-id="score" data-type="numeric" data-width="6em" data-formatter="score">{{ lang._('Score') }}</th>
                <th data-column-id="signals" data-formatter="signals">{{ lang._('Signals') }}</th>
                <th data-column-id="checked_at" data-width="12em" data-formatter="checked">{{ lang._('Last check') }}</th>
                <th data-column-id="details" data-width="5em" data-formatter="details" data-sortable="false"></th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
</div>

<div id="settings" class="tab-pane fade">
<div style="padding-bottom: 1.5em;">
    <table class="table table-condensed">
        <thead>
            <tr><th colspan="2">{{ lang._('Worker') }}</th></tr>
        </thead>
        <tbody>
            <tr><td style="width:22%">{{ lang._('Status') }}</td><td id="st_worker"></td></tr>
            <tr><td>{{ lang._('Domains waiting for analysis') }}</td><td id="st_pending"></td></tr>
            <tr><td>{{ lang._('Last collection') }}</td><td id="st_collect"></td></tr>
        </tbody>
    </table>
</div>

    {{ partial('layout_partials/base_form', ['fields': generalForm, 'id': 'frm_general', 'apply_btn_id': 'btn_save']) }}
</div>
</div>
