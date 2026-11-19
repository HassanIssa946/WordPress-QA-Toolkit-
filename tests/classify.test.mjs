// Severity classification of tool output (PHPCS, plugin checksums, PHPStan symbols).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { classifyPhpcs, notFoundSymbol, locateSymbols, projectConstants, isBlockRenderTemplate } from '../modules/code.mjs';
import { classifyChecksum } from '../modules/wpcli.mjs';
import { fixturePlugin, tempDir } from './helpers.mjs';

const GLOBAL_OVERRIDE = { source: 'WordPress.WP.GlobalVariablesOverride.Prohibited', type: 'ERROR', message: 'Overriding WordPress globals is prohibited. Found assignment to $post' };

describe('PHPCS: WordPress.WP.GlobalVariablesOverride', () => {
  test('block render template (render.php next to block.json) → info, aggregated (real-site false positive)', () => {
    const file = path.join(fixturePlugin('safe-plugin'), 'blocks', 'card', 'render.php');
    assert.ok(isBlockRenderTemplate(file));
    const c = classifyPhpcs(GLOBAL_OVERRIDE, file);
    assert.equal(c.severity, 'info');
    assert.equal(c.aggregate, true);
  });
  test('ordinary file → still medium', () => {
    const c = classifyPhpcs(GLOBAL_OVERRIDE, path.join(fixturePlugin('safe-plugin'), 'safe-plugin.php'));
    assert.equal(c.severity, 'medium');
  });
  test('render.php without block.json → still medium', () => {
    const d = tempDir();
    fs.writeFileSync(path.join(d, 'render.php'), '<?php $post = 1;');
    assert.equal(classifyPhpcs(GLOBAL_OVERRIDE, path.join(d, 'render.php')).severity, 'medium');
  });
  test('escaping and SQL sniffs keep their high severity', () => {
    assert.equal(classifyPhpcs({ source: 'WordPress.Security.EscapeOutput.OutputNotEscaped', type: 'ERROR' }, 'x.php').severity, 'high');
    assert.equal(classifyPhpcs({ source: 'WordPress.DB.PreparedSQL.InterpolatedNotPrepared', type: 'ERROR' }, 'x.php').severity, 'high');
  });
});

describe('plugin verify-checksums severity', () => {
  test('runtime-generated non-code files are low (All-in-One WP Migration storage/.htaccess)', () => {
    for (const file of ['storage/.htaccess', 'storage/index.html', 'storage/web.config']) assert.equal(classifyChecksum({ file, message: 'File was added' }), 'low', file);
  });
  test('added PHP is high (backdoor pattern)', () => {
    assert.equal(classifyChecksum({ file: 'storage/index.php', message: 'File was added' }), 'high');
    assert.equal(classifyChecksum({ file: 'lib/x.phtml', message: 'File was added' }), 'high');
    assert.equal(classifyChecksum({ file: 'storage/x.php', message: 'File was added', content: '<?php eval($_POST["c"]);' }), 'high');
    assert.equal(classifyChecksum({ file: 'storage/x.php', message: 'File was added', content: 'junk\n<?= `id` ?>' }), 'high');
  });
  test('added .php without a PHP open tag is inert text → low (AIOWPM storage/index.php)', () => {
    assert.equal(classifyChecksum({ file: 'storage/index.php', message: 'File was added', content: 'Kangaroos cannot jump here' }), 'low');
    assert.equal(classifyChecksum({ file: 'storage/index.php', message: "Checksum does not match", content: 'Kangaroos' }), 'high', 'modified files stay high');
  });
  test('modified PHP/JS is high, modified other files medium, missing files medium', () => {
    assert.equal(classifyChecksum({ file: 'a.php', message: "Checksum does not match" }), 'high');
    assert.equal(classifyChecksum({ file: 'a.js', message: "Checksum does not match" }), 'high');
    assert.equal(classifyChecksum({ file: 'readme.txt', message: "Checksum does not match" }), 'medium');
    assert.equal(classifyChecksum({ file: 'a.php', message: 'File is missing' }), 'medium');
  });
});

describe('PHPStan symbols', () => {
  test('notFoundSymbol parses the message forms seen on a real site', () => {
    assert.deepEqual(notFoundSymbol('Function pll_get_post not found.'), { kind: 'function', name: 'pll_get_post' });
    assert.deepEqual(notFoundSymbol('Constant ALH_DIR not found.'), { kind: 'constant', name: 'ALH_DIR' });
    assert.deepEqual(notFoundSymbol('Call to static method get() on an unknown class WPSEO_Options.'), { kind: 'class', name: 'WPSEO_Options' });
    assert.equal(notFoundSymbol('Parameter #1 $text of function esc_attr expects string, float given.'), null);
  });
  test('locateSymbols finds functions/classes in installed third-party plugins', () => {
    const d = tempDir();
    fs.mkdirSync(path.join(d, 'polylang', 'include'), { recursive: true });
    fs.writeFileSync(path.join(d, 'polylang', 'include', 'api.php'), '<?php\nfunction pll_get_post( $id ) {}\nfunction PLL() {}\n');
    fs.mkdirSync(path.join(d, 'wordpress-seo'));
    fs.writeFileSync(path.join(d, 'wordpress-seo', 'options.php'), '<?php\nclass WPSEO_Options {}\n');
    const found = locateSymbols(['pll_get_post', 'PLL', 'WPSEO_Options', 'missing_fn'], [{ slug: 'polylang', dir: path.join(d, 'polylang') }, { slug: 'wordpress-seo', dir: path.join(d, 'wordpress-seo') }]);
    assert.equal(found.get('pll_get_post')?.slug, 'polylang');
    assert.equal(found.get('pll')?.slug, 'polylang');
    assert.equal(found.get('wpseo_options')?.slug, 'wordpress-seo');
    assert.equal(found.has('missing_fn'), false);
  });
  test('projectConstants collects define() names for the PHPStan bootstrap', () => {
    assert.deepEqual(projectConstants([fixturePlugin('safe-plugin')], ['node_modules']), ['SF_DIR']);
  });
});

describe('wpcli.plugins on a site without plugins', () => {
  test('"Success: Plugin already verified." (exit 0) is verified, not an error', async () => {
    const { makeRun } = await import('./helpers.mjs');
    const wpcli = (await import('../modules/wpcli.mjs')).default;
    const run = makeRun({ config: { scan: { plugins: [] } }, mode: 'wordpress', flags: { only: ['wpcli.plugins'] } });
    run.wpCli = async () => ({ ok: true, db: true, siteurl: 'http://fixture.local' });
    run.wp = async (args) => {
      if (args[0] === 'plugin' && args[1] === 'verify-checksums') return { code: 0, stdout: 'Success: Plugin already verified.\n', stderr: '' };
      return { code: 0, stdout: '[]', stderr: '' };
    };
    await wpcli(run);
    assert.equal(run.checks.find((c) => c.id === 'wpcli.plugins').status, 'passed');
  });
});
