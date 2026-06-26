import { execFile } from 'child_process';
import { promisify } from 'util';
import { writeFile, unlink } from 'fs/promises';
import { existsSync } from 'fs';
import { join, resolve } from 'path';
import { tmpdir } from 'os';

const execFileAsync = promisify(execFile);

function findPluginRoot(): string {
  // Installed: plugins/sigmaUi/server/lib/ → two levels up
  const installed = resolve(__dirname, '../..');
  if (existsSync(join(installed, 'server', 'translation_script'))) return installed;
  // Dev build: target/server/lib/ → three levels up
  const dev = resolve(__dirname, '../../..');
  if (existsSync(join(dev, 'server', 'translation_script'))) return dev;
  throw new Error(`Cannot find plugin root from ${__dirname}`);
}

const PLUGIN_ROOT = findPluginRoot();
const VENV_PYTHON = join(PLUGIN_ROOT, 'server/translation_script/.venv/bin/python');
const CONVERTER_SCRIPT = join(PLUGIN_ROOT, 'server/translation_script/sigma/sigma_converter.py');

const VALID_FORMATS = new Set([
  'es-qs', 'default', 'dsl_lucene', 'kibana', 'kibana_ndjson',
  'siem_rule', 'siem_rule_ndjson', 'elasticsearch-rule',
  'xpack-watcher', 'xpack-watcher-sp', 'eql', 'esql', 'elastalert',
]);

export async function convertSigmaRule(
  sigmaYaml: string,
  format: string,
  pipeline = 'ecs_windows'
): Promise<string> {
  if (!VALID_FORMATS.has(format)) {
    throw new Error(`Unsupported format: ${format}`);
  }

  const tmpFile = join(tmpdir(), `sigma_${Date.now()}_${Math.random().toString(36).slice(2)}.yml`);

  try {
    await writeFile(tmpFile, sigmaYaml, 'utf8');
    const { stdout, stderr } = await execFileAsync(
      VENV_PYTHON,
      [CONVERTER_SCRIPT, tmpFile, format, '--pipeline', pipeline],
      { timeout: 30_000 }
    );

    if (stderr) {
      throw new Error(stderr.trim());
    }

    return stdout.trim();
  } finally {
    await unlink(tmpFile).catch(() => {});
  }
}