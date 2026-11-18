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
        // translations come HTML-escaped (safe in HTML): decoded for .text() and dialogs
        function tr(text) {
            return $('<textarea/>').html(text).text();
        }

        // tr() with each %s replaced by the next argument
        function fmt(text) {
            var args = Array.prototype.slice.call(arguments, 1);
            return tr(text).replace(/%s/g, function () { return args.length ? String(args.shift()) : ''; });
        }
        mapDataToFormUI({'frm_general': '/api/shopguard/settings/get'}).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });

        function refreshStatus() {
            ajaxGet('/api/shopguard/service/status', {}, function (data) {
                if (data.status === 'ok') {
                    $('#st_worker').text(fmt('{{ sgLang._('Reachable (version %s)') }}', data.version));
                    $('#st_pending').text(data.pending);
                } else {
                    $('#st_worker').text(data.message || tr('{{ sgLang._('Unreachable') }}'));
                    $('#st_pending').text('');
                }
                if (data.mode === 'block') {
                    $('#st_blocked').text(fmt(data.applying
                        ? '{{ sgLang._('%s domains blocked in Unbound (being applied…)') }}'
                        : '{{ sgLang._('%s domains blocked in Unbound') }}', data.blocked));
                } else if (data.mode === 'observe') {
                    $('#st_blocked').text(tr('{{ sgLang._('Observe only: nothing blocked') }}'));
                } else {
                    $('#st_blocked').text(tr('{{ sgLang._('Disabled') }}'));
                }
                var c = data.collect;
                if (!c) {
                    $('#st_collect').text(tr('{{ sgLang._('Not run yet') }}'));
                } else {
                    var when = new Date(c.time * 1000).toLocaleString();
                    if (c.status === 'ok') {
                        $('#st_collect').text(fmt('{{ sgLang._('%s: %s new domains sent') }}', when, c.queued));
                    } else if (c.status === 'error') {
                        $('#st_collect').text(when + ': ' + c.message);
                    } else {
                        $('#st_collect').text(when + ': ' + c.status);
                    }
                }
            });
        }

        // Apply: spinner while saving and updating the blocklist, then what was applied
        function applying(on) {
            $('#btn_save').prop('disabled', on);
            $('#frm_general_progress').toggleClass('fa fa-spinner fa-pulse', on);
        }

        function applied(type, text) {
            $('#apply_result').removeClass('alert-success alert-warning').addClass('alert-' + type)
                .text(text).show();
        }

        $('#btn_save').click(function () {
            $('#apply_result').hide();
            applying(true);
            saveFormToEndpoint('/api/shopguard/settings/set', 'frm_general', function () {
                // (re)creates or removes the cron job, applies the mode to the blocklist
                ajaxCall('/api/shopguard/service/reconfigure', {}, function (data) {
                    applying(false);
                    if (data.status !== 'ok') {
                        applied('warning', tr('{{ sgLang._('Settings saved, but:') }}') + ' ' +
                            (data.message || tr('{{ sgLang._('the blocklist could not be updated.') }}')));
                    } else if (data.mode === 'block') {
                        applied('success', fmt('{{ sgLang._('Settings applied: %s domains blocked in Unbound.') }}',
                            data.blocked) + (data.pending
                            ? ' ' + tr('{{ sgLang._('Unbound applies the changes within 1 to 2 minutes.') }}') : ''));
                    } else if (data.mode === 'observe') {
                        applied('success', tr('{{ sgLang._('Settings applied: observe only, nothing is blocked.') }}'));
                    } else {
                        applied('success', tr('{{ sgLang._('Settings applied: ShopGuard is disabled.') }}'));
                    }
                    refreshStatus();
                });
            }, false, function () {
                // invalid fields: shown on the form
                applying(false);
            });
        });

        refreshStatus();

        // Text from the worker comes partly from hostile sites (certificate fields…):
        // always inserted as text, never as HTML.
        function esc(value) {
            return $('<div/>').text(value === null || value === undefined ? '' : String(value)).html()
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        function warn(message) {
            BootstrapDialog.show({
                type: BootstrapDialog.TYPE_WARNING,
                title: tr('{{ sgLang._('ShopGuard') }}'),
                message: $('<div/>').text(message)
            });
        }

        // the user's decision on a domain: fake (always blocked), legit (never), none
        // a decision is saved in a second or two (Unbound rebuilds its blocklists in the
        // background): the buttons wait with a spinner, one decision at a time
        // OPNsense's dark theme draws a disabled default button as an empty grey square:
        // the small grid buttons stay enabled and are ignored while a decision is saved
        var busy = false;

        function deciding(on, button) {
            busy = on;
            $('#decide_fake, #decide_legit').prop('disabled', on);
            $('#decide_progress, #decide_progress_grid').toggle(on);
            // the clicked button itself turns into a spinner: it is where the user looks
            var icon = button ? $(button).find('.fa').first() : $();
            if (on) {
                icon.data('icon', icon.attr('class')).attr('class', 'fa fa-fw fa-spinner fa-pulse');
            } else if (icon.data('icon')) {
                icon.attr('class', icon.data('icon'));
            }
        }

        function decide(domain, label, button) {
            if (busy) return;
            deciding(true, button);
            ajaxCall('/api/shopguard/service/feedback', {domain: domain, label: label}, function (data) {
                deciding(false, button);
                if (data.status !== 'ok') {
                    warn(data.message || tr('{{ sgLang._('The decision was not saved.') }}'));
                } else if (data.message) {
                    warn(data.message);
                } else {
                    var text = data.pending
                        ? tr('{{ sgLang._('Saved. Unbound applies it within 1 to 2 minutes.') }}')
                        : tr('{{ sgLang._('Saved.') }}');
                    $('#decide_info, #decide_info_grid').text(text).stop(true, true).show().delay(8000).fadeOut();
                }
                $('#grid-verdicts').bootgrid('reload');
                loadLabels();
                refreshStatus();
            });
        }

        function decisionBadge(feedback) {
            if (!feedback) return '';
            return feedback.label === 'fake'
                ? ' <span class="label label-danger">{{ sgLang._('marked fake') }}</span>'
                : ' <span class="label label-success">{{ sgLang._('marked legitimate') }}</span>';
        }

        var labels = [];

        function loadLabels() {
            ajaxGet('/api/shopguard/service/labels', {}, function (data) {
                labels = data.rows || [];
                $('#labels_message').text(data.status === 'ok' ? '' : (data.message || '')).toggle(data.status !== 'ok');
                var body = $('#labels tbody').empty();
                labels.forEach(function (r) {
                    $('<tr/>')
                        .append($('<td/>').text(r.domain))
                        .append($('<td/>').html(decisionBadge({label: r.label})))
                        .append($('<td/>').text(r.at ? new Date(r.at * 1000).toLocaleString() : ''))
                        .append($('<td/>').text(r.checked_at ? r.score : tr('{{ sgLang._('not analyzed yet') }}')))
                        .append($('<td/>').append(
                            $('<button type="button" class="btn btn-xs btn-default"/>')
                                .attr('title', tr('{{ sgLang._('Forget the decision') }}'))
                                .append('<span class="fa fa-fw fa-undo"></span>')
                                .addClass('decision-forget')
                                .on('click', function () { decide(r.domain, 'none', this); })
                        ))
                        .appendTo(body);
                });
                if (!labels.length) {
                    $('<tr/>').append($('<td colspan="5"/>').text(tr('{{ sgLang._('No decision yet.') }}'))).appendTo(body);
                }
                // hidden rather than disabled (a disabled button is a grey square in the dark theme)
                $('#export_fake').toggle(labels.some(function (r) { return r.label === 'fake'; }));
            });
        }

        $('#decide_fake, #decide_legit').click(function () {
            var domain = $.trim($('#decide_domain').val()).toLowerCase();
            if (!domain || busy) return;
            decide(domain, this.id === 'decide_fake' ? 'fake' : 'legit', this);
            $('#decide_domain').val('');
        });

        // confirmed fake shops, one domain per line: for HaGeZi or Signal Arnaques reports
        $('#export_fake').click(function () {
            var text = labels.filter(function (r) { return r.label === 'fake'; })
                .map(function (r) { return r.domain; }).join('\n') + '\n';
            var link = document.createElement('a');
            link.href = URL.createObjectURL(new Blob([text], {type: 'text/plain'}));
            link.download = 'shopguard-fake-shops.txt';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });

        loadLabels();

        function buttons(row) {
            var id = ' data-row-id="' + esc(row.domain) + '"';
            var out = '<button type="button" class="btn btn-xs btn-default bootgrid-tooltip verdict-details"' + id +
                ' title="{{ sgLang._('Signals') }}"><span class="fa fa-fw fa-info-circle"></span></button> ';
            if (row.feedback) {
                return out + '<button type="button" class="btn btn-xs btn-default bootgrid-tooltip verdict-decide"' + id +
                    ' data-label="none" title="{{ sgLang._('Forget the decision') }}"><span class="fa fa-fw fa-undo"></span></button>';
            }
            return out +
                '<button type="button" class="btn btn-xs btn-default bootgrid-tooltip verdict-decide"' + id +
                ' data-label="legit" title="{{ sgLang._('Legitimate: never block') }}"><span class="fa fa-fw fa-check"></span></button> ' +
                '<button type="button" class="btn btn-xs btn-default bootgrid-tooltip verdict-decide"' + id +
                ' data-label="fake" title="{{ sgLang._('Fake shop: always block') }}"><span class="fa fa-fw fa-ban"></span></button>';
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
                    domain: function (column, row) {
                        return esc(row.domain) + decisionBadge(row.feedback);
                    },
                    // OPNsense's grid treats the "commands" column like the Actions column
                    // of its own pages: frozen on the right, width locked
                    commands: function (column, row) {
                        return buttons(row);
                    },
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
                    }
                }
            }
        }).on('loaded.rs.jquery.bootgrid', function () {
            var rows = $(this).bootgrid('getCurrentRows');
            $(this).find('.verdict-decide').off('click').on('click', function () {
                decide($(this).data('row-id'), $(this).data('label'), this);
            });
            $(this).find('.verdict-details').off('click').on('click', function () {
                var domain = $(this).data('row-id');
                var row = rows.filter(function (r) { return r.domain === domain; })[0];
                if (!row) return;
                // thead/tbody: Bootstrap styles the cells only inside them
                var table = $('<table class="table table-condensed table-striped"/>');
                $('<thead/>').append($('<tr/>')
                    .append($('<th style="width: 5em; text-align: right;"/>').text(tr('{{ sgLang._('Weight') }}')))
                    .append($('<th style="width: 1%; white-space: nowrap;"/>').text(tr('{{ sgLang._('Signal') }}')))
                    .append($('<th/>').text(tr('{{ sgLang._('Detail') }}')))
                ).appendTo(table);
                var body = $('<tbody/>').appendTo(table);
                // what makes the score first, the record (weight 0) after, greyed
                var signals = (row.signals || []).slice().sort(function (a, b) {
                    return (b.weight !== 0) - (a.weight !== 0) || b.weight - a.weight;
                });
                signals.forEach(function (s) {
                    var weight = $('<td style="text-align: right; white-space: nowrap;"/>');
                    if (s.weight > 0) {
                        weight.append($('<span class="label label-danger"/>').text('+' + s.weight));
                    } else if (s.weight < 0) {
                        weight.append($('<span class="label label-success"/>').text(s.weight));
                    } else {
                        weight.text('0');
                    }
                    var tr = $('<tr/>')
                        .append(weight)
                        .append($('<td style="white-space: nowrap;"/>')
                            .append($('<div/>').text(s.name))
                            .append($('<small class="text-muted"/>').text(s.source)))
                        .append($('<td/>').text(s.detail))
                        .appendTo(body);
                    if (s.weight === 0) {
                        tr.addClass('text-muted');
                    }
                });
                BootstrapDialog.show({
                    title: $('<span/>').text(fmt('{{ sgLang._('%s — score %s') }}', row.domain, row.score)),
                    message: table,
                    size: BootstrapDialog.SIZE_WIDE,
                    buttons: [{label: tr('{{ sgLang._('Close') }}'), action: function (dlg) { dlg.close(); }}]
                });
            });
        });

        $('#min_score').on('change', function () {
            $('#grid-verdicts').bootgrid('reload');
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#verdicts">{{ sgLang._('Verdicts') }}</a></li>
    <li><a data-toggle="tab" href="#decisions">{{ sgLang._('Decisions') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ sgLang._('Settings') }}</a></li>
</ul>

<div class="tab-content content-box">
<div id="verdicts" class="tab-pane fade in active">
    <div class="form-inline" style="padding: 1em 1em 0;">
        <label for="min_score">{{ sgLang._('Minimum score') }}</label>
        <select id="min_score" class="form-control" style="width: auto; margin-left: .5em;">
            <option value="0" selected="selected">{{ sgLang._('0 (all)') }}</option>
            <option value="1">1</option>
            <option value="30">30</option>
            <option value="50">50</option>
            <option value="{{ threshold }}">{{ threshold }} ({{ sgLang._('blocking threshold') }})</option>
        </select>
        <span id="verdicts_message" class="text-danger" style="margin-left: 1em; display: none;"></span>
        <span id="decide_progress_grid" style="margin-left: 1em; display: none;"><i class="fa fa-spinner fa-pulse"></i> {{ sgLang._('Saving…') }}</span>
        <span id="decide_info_grid" class="text-success" style="margin-left: 1em; display: none;"></span>
    </div>
    <table id="grid-verdicts" class="table table-condensed table-hover table-striped">
        <thead>
            <tr>
                <th data-column-id="domain" data-type="string" data-identifier="true" data-formatter="domain">{{ sgLang._('Domain') }}</th>
                <th data-column-id="score" data-type="numeric" data-min-width="70" data-max-width="90" data-formatter="score">{{ sgLang._('Score') }}</th>
                <th data-column-id="signals" data-formatter="signals">{{ sgLang._('Signals') }}</th>
                <th data-column-id="checked_at" data-min-width="165" data-max-width="200" data-formatter="checked">{{ sgLang._('Last check') }}</th>
                <th data-column-id="commands" data-width="110" data-formatter="commands" data-sortable="false">{{ sgLang._('Actions') }}</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
</div>

<div id="decisions" class="tab-pane fade">
    <div style="padding: 1em 1em 0;">
        <p>{{ sgLang._('Your decisions override the score: a domain marked fake is always blocked (in Block mode), one marked legitimate never is. They are kept by the worker, which also uses them to improve its scoring.') }}</p>
        <div class="form-inline">
            <input type="text" id="decide_domain" class="form-control" placeholder="example-shop.com" style="width: 20em;"/>
            <button type="button" id="decide_fake" class="btn btn-danger"><span class="fa fa-fw fa-ban"></span> {{ sgLang._('Fake shop') }}</button>
            <button type="button" id="decide_legit" class="btn btn-success"><span class="fa fa-fw fa-check"></span> {{ sgLang._('Legitimate') }}</button>
            <span id="decide_progress" style="display: none;"><i class="fa fa-spinner fa-pulse"></i> {{ sgLang._('Saving…') }}</span>
            <span id="decide_info" class="text-success" style="display: none;"></span>
            <button type="button" id="export_fake" class="btn btn-default pull-right" style="display: none;"
                    title="{{ sgLang._('One domain per line, to report them (HaGeZi, Signal Arnaques)') }}">
                <span class="fa fa-fw fa-download"></span> {{ sgLang._('Export the fake shops') }}</button>
        </div>
        <span id="labels_message" class="text-danger" style="display: none;"></span>
    </div>
    <table id="labels" class="table table-condensed table-striped">
        <thead>
            <tr>
                <th>{{ sgLang._('Domain') }}</th>
                <th>{{ sgLang._('Decision') }}</th>
                <th>{{ sgLang._('Since') }}</th>
                <th>{{ sgLang._('Computed score') }}</th>
                <th style="width: 5em;"></th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
</div>

<div id="settings" class="tab-pane fade">
<div style="padding-bottom: 1.5em;">
    <table class="table table-condensed">
        <thead>
            <tr><th colspan="2">{{ sgLang._('Worker') }}</th></tr>
        </thead>
        <tbody>
            <tr><td style="width:22%">{{ sgLang._('Status') }}</td><td id="st_worker"></td></tr>
            <tr><td>{{ sgLang._('Domains waiting for analysis') }}</td><td id="st_pending"></td></tr>
            <tr><td>{{ sgLang._('Last collection') }}</td><td id="st_collect"></td></tr>
            <tr><td>{{ sgLang._('Blocking') }}</td><td id="st_blocked"></td></tr>
        </tbody>
    </table>
</div>

    {{ partial('layout_partials/base_form', ['fields': generalForm, 'id': 'frm_general', 'apply_btn_id': 'btn_save']) }}
    <div id="apply_result" class="alert" role="alert" style="display: none; margin: 0 1em 1em;"></div>
</div>
</div>
