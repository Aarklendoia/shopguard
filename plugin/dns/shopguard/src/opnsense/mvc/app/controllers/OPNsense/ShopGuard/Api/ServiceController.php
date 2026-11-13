<?php

/*
 * Copyright (C) 2026 Édouard Biton
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\ShopGuard\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    /**
     * worker reachability and version, as returned by shopguard.py status
     */
    public function statusAction()
    {
        $response = trim((new Backend())->configdRun('shopguard status'));
        $data = json_decode($response, true);
        return is_array($data) ? $data : ['status' => 'error', 'message' => $response];
    }

    /**
     * apply the settings: the collection cron job exists only while ShopGuard is enabled
     */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $out = trim((new Backend())->configdRun('cron restart'));
        return ['status' => stripos($out, 'error') === false ? 'ok' : 'failed'];
    }

    /**
     * one page of verdicts for the bootgrid, from the worker through configd (the token stays
     * on the router): current, rowCount, searchPhrase and min_score from the request
     */
    public function verdictsAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $rowCount = (int)$this->request->getPost('rowCount', 'int', 50);
        $rowCount = ($rowCount < 1 || $rowCount > 1000) ? 1000 : $rowCount;
        $current = max(1, (int)$this->request->getPost('current', 'int', 1));
        $minScore = min(100, max(0, (int)$this->request->getPost('min_score', 'int', 0)));
        $search = strtolower(trim((string)$this->request->getPost('searchPhrase', 'string', '')));
        if (!preg_match('/^[a-z0-9_.-]{0,253}$/', $search)) {
            $search = '';
        }
        $response = (new Backend())->configdpRun('shopguard verdicts', [
            (string)$minScore,
            (string)(($current - 1) * $rowCount),
            (string)$rowCount,
            $search,
        ]);
        $data = json_decode(trim($response), true);
        if (!is_array($data) || ($data['status'] ?? '') !== 'ok') {
            return [
                'rows' => [], 'rowCount' => 0, 'total' => 0, 'current' => 1,
                'message' => is_array($data) ? ($data['message'] ?? '') : trim($response),
            ];
        }
        return [
            'rows' => $data['rows'],
            'rowCount' => count($data['rows']),
            'total' => (int)$data['total'],
            'current' => $current,
        ];
    }
}
