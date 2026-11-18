<?php

/*
 * Lang (plugin catalogue, fallback, backend message templates) with the compiled French
 * catalogue: php plugin/tests/test_lang.php <locale directory built by plugin/lang.py>
 * Needs the fr_FR.UTF-8 locale.
 */

require __DIR__ . '/../dns/shopguard/src/opnsense/mvc/app/library/OPNsense/ShopGuard/Lang.php';

use OPNsense\ShopGuard\Lang;

$fails = 0;
function check($name, $cond, $detail = '')
{
    global $fails;
    echo ($cond ? 'PASS ' : 'FAIL ') . $name . ($cond ? '' : '  -> ' . var_export($detail, true)) . "\n";
    $fails += $cond ? 0 : 1;
}

if (setlocale(LC_ALL, 'fr_FR.UTF-8') === false) {
    echo "fr_FR.UTF-8 locale missing\n";
    exit(2);
}
Lang::$directory = $argv[1];

check('plain string', Lang::_('Fake shop') === 'Fausse boutique', Lang::_('Fake shop'));
check('unknown string: English', Lang::_('Not in any catalogue') === 'Not in any catalogue');
check('empty string', Lang::_('') === '');

$st = Lang::messages([
    'status' => 'error',
    'message' => 'Worker error: HTTP 502.',
    'message_t' => ['Worker error: HTTP %d.', [502]],
    'collect' => [
        'message' => 'Worker unreachable: timed out',
        'message_t' => ['Worker unreachable: %s', ['timed out']],
        'time' => 1,
    ],
    'blocklist' => ['message' => 'Edited by hand', 'message_t' => ['The worker refused the token.', []]],
]);
check('message translated', $st['message'] === 'Erreur du worker : HTTP 502.', $st);
check('nested message translated', $st['collect']['message'] === 'Worker injoignable : timed out', $st);
check('template not matching: message kept', $st['blocklist']['message'] === 'Edited by hand', $st);
check('templates removed', !isset($st['message_t']) && !isset($st['collect']['message_t'])
    && !isset($st['blocklist']['message_t']), $st);
check('other fields untouched', $st['status'] === 'error' && $st['collect']['time'] === 1, $st);

$st = Lang::messages(['message' => 'Range 0x10', 'message_t' => ['Range 0x%x', [16]]]);
check('untranslated template: English message', $st['message'] === 'Range 0x10', $st);
$st = Lang::messages(['message' => 'x', 'message_t' => 'not a template']);
check('malformed template ignored', $st === ['message' => 'x'], $st);
$st = Lang::messages(['message' => 'x', 'message_t' => ['%s', [['nested']]]]);
check('non-scalar argument ignored', $st === ['message' => 'x'], $st);
$st = Lang::messages(['rows' => [], 'total' => 0]);
check('no message', $st === ['rows' => [], 'total' => 0], $st);

$form = Lang::within(function () {
    return [gettext('Score threshold'), gettext('Block in Unbound'), gettext('Choose a score from 1 to 100.')];
});
check(
    'within(): form and model strings from the plugin catalogue',
    $form === ['Seuil de score', 'Bloquer dans Unbound', 'Choisissez un score de 1 à 100.'],
    $form
);
check('within(): default domain restored', textdomain(null) === 'messages', textdomain(null));

echo "\n$fails failure(s)\n";
exit($fails ? 1 : 0);
