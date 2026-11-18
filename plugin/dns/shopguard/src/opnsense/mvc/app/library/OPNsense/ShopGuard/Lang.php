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

namespace OPNsense\ShopGuard;

/**
 * Translations of the plugin: its own gettext catalogue (shopguard.mo, built from
 * plugin/dns/shopguard/lang/*.po), then the OPNsense one, then English.
 * OPNsense only translates the strings of its own plugins.
 */
class Lang
{
    const DOMAIN = 'shopguard';

    /* where the package installs shopguard.mo (another directory in the tests) */
    public static $directory = '/usr/local/share/locale';

    private static $bound = false;

    public static function bind()
    {
        if (!self::$bound) {
            bindtextdomain(self::DOMAIN, self::$directory);
            bind_textdomain_codeset(self::DOMAIN, 'UTF-8');
            self::$bound = true;
        }
    }

    public static function _($text)
    {
        if ($text === null || $text === '') {
            return '';
        }
        self::bind();
        $translated = dgettext(self::DOMAIN, $text);
        return $translated !== $text ? $translated : gettext($text);
    }

    /**
     * Run $build (a form, the settings model) with this catalogue as the default gettext
     * domain: OPNsense translates form labels, option values and validation messages with
     * gettext().
     */
    public static function within(callable $build)
    {
        self::bind();
        $previous = textdomain(null);
        textdomain(self::DOMAIN);
        try {
            return $build();
        } finally {
            textdomain($previous);
        }
    }

    /**
     * Translate the shopguard.py messages of an answer, at any depth: each "message" comes
     * with its English template and arguments in "message_t" (["Worker error: HTTP %d.",
     * [502]]). The template is used only when it still gives the message, otherwise the
     * message is kept as is.
     */
    public static function messages(array $data)
    {
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = self::messages($value);
            }
        }
        if (!array_key_exists('message_t', $data)) {
            return $data;
        }
        $template = $data['message_t'];
        unset($data['message_t']);
        if (!is_string($data['message'] ?? null) || !is_array($template) || count($template) != 2) {
            return $data;
        }
        list($text, $args) = array_values($template);
        if (!is_string($text) || !is_array($args)) {
            return $data;
        }
        $args = array_values($args);
        foreach ($args as $arg) {
            if (!is_scalar($arg)) {
                return $data;
            }
        }
        try {
            if (@vsprintf($text, $args) === $data['message']) {
                $data['message'] = vsprintf(self::_($text), $args);
            }
        } catch (\Throwable $e) {
            /* a translation with other placeholders: keep the English message */
        }
        return $data;
    }
}
