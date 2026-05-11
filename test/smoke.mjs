import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import YAML from 'yaml';
import { buildFromConfig } from '../src/build.mjs';

test('buildFromConfig merges fixture sources and writes clean output metadata', async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'filter-merger-test-'));
  const outputFile = path.join(tempDir, 'dist', 'adguardhome-merged.txt');
  const metadataFile = path.join(tempDir, 'dist', 'metadata.json');
  await mkdir(path.dirname(outputFile), { recursive: true });

  const config = YAML.parse(await readFile('config.yaml', 'utf8'));
  config.build.minimumRules = 3;
  config.build.allowEmpty = false;
  config.sources = [
    {
      name: 'Fixture A',
      url: path.resolve('test/fixtures/list-header.txt'),
      enabled: true,
      description: 'Local fixture source',
    },
    {
      name: 'Fixture B',
      url: path.resolve('test/fixtures/list-b.txt'),
      enabled: true,
    },
    {
      name: 'Disabled fixture',
      url: path.resolve('test/fixtures/list-b.txt'),
      enabled: false,
    },
  ];

  const result = await buildFromConfig(config, {
    configPath: path.resolve('config.yaml'),
    outputFile,
    metadataFile,
  });

  await writeFile(outputFile, result.outputText, 'utf8');
  await writeFile(metadataFile, `${JSON.stringify(result.metadata, null, 2)}\n`, 'utf8');

  const output = await readFile(outputFile, 'utf8');
  const metadata = JSON.parse(await readFile(metadataFile, 'utf8'));

  assert.ok(!output.startsWith('! Title:'));
  assert.ok(!output.includes('! Title: AdGuard DNS filter'));
  assert.ok(!output.includes('! Compiled by @adguard/hostlist-compiler'));
  assert.ok(output.endsWith('\n'));
  assert.ok(!output.includes('\n\n\n'));
  assert.ok(output.includes('||ads.example.com^'));
  assert.ok(output.includes('||tracking.example.com^'));
  assert.ok(output.includes('||analytics.example.com^'));
  assert.ok(!output.includes('filter-merger-'));
  assert.ok(!output.includes('merged-source.txt'));
  assert.equal((output.match(/\|\|tracking\.example\.com\^/g) ?? []).length, 1);
  assert.equal(metadata.counts.sources_enabled, 2);
  assert.equal(metadata.counts.sources_disabled, 1);
  assert.equal(metadata.counts.output_rules, 3);
  assert.equal(metadata.aggressive.compress, false);
});
