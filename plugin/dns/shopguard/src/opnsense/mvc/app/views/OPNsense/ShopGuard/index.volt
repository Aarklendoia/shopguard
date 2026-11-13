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
    });
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
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

<div class="content-box">
    {{ partial('layout_partials/base_form', ['fields': generalForm, 'id': 'frm_general', 'apply_btn_id': 'btn_save']) }}
</div>
