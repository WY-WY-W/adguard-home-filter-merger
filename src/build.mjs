import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import YAML from 'yaml';

const DEFAULT_CONFIG_PATH = path.resolve('config.yaml');
const DEFAULT_OUTPUT_PATH = 'dist/adguardhome-merged.txt';
const DEFAULT_METADATA_PATH = 'dist/metadata.json';

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function toPosixNewlines(text) {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

function isHttpUrl(value) {
  return /^https?:\/\//i.test(value);
}

function isFileUrl(value) {
  return /^file:\/\//i.test(value);
}

function stripBom(text) {
  return text.replace(/^\ufeff/, '');
}

function stripLeadingCompilerHeader(text) {
  const lines = text.split('\n');
  const headerLinePatterns = [
    /^!\s*Title:/i,
    /^!\s*Description:/i,
    /^!\s*Version:/i,
    /^!\s*Homepage:/i,
    /^!\s*License:/i,
    /^!\s*Last modified:/i,
    /^!\s*Compiled by @adguard\/hostlist-compiler/i,
  ];

  let sawHeader = false;
  let endIndex = 0;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();
    const isCommentLine = trimmed.startsWith('!');
    const isRecognizedHeader = headerLinePatterns.some((pattern) => pattern.test(trimmed));

    if (isRecognizedHeader) {
      sawHeader = true;
      endIndex = index + 1;
      continue;
    }

    if (sawHeader && (trimmed === '!' || trimmed === '')) {
      endIndex = index + 1;
      continue;
    }

    if (sawHeader && isCommentLine) {
      endIndex = index + 1;
      continue;
    }

    if (sawHeader) {
      return lines.slice(endIndex).join('\n');
    }

    if (!isCommentLine) {
      return text;
    }
  }

  return sawHeader ? lines.slice(endIndex).join('\n') : text;
}

function normalizeConfig(raw, configPath) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`Invalid config in ${configPath}: expected a YAML mapping.`);
  }

  const sources = Array.isArray(raw.sources) ? raw.sources : [];
  if (sources.length === 0) {
    throw new Error(`Invalid config in ${configPath}: sources must be a non-empty array.`);
  }

  const normalizedSources = sources.map((source, index) => {
    if (!source || typeof source !== 'object' || Array.isArray(source)) {
      throw new Error(`Invalid source at index ${index}: expected an object.`);
    }
    const name = typeof source.name === 'string' && source.name.trim() ? source.name.trim() : '';
    const url = typeof source.url === 'string' && source.url.trim() ? source.url.trim() : '';
    const enabled = source.enabled !== false;
    const description = typeof source.description === 'string' && source.description.trim()
      ? source.description.trim()
      : undefined;

    if (!name) {
      throw new Error(`Invalid source at index ${index}: missing name.`);
    }
    if (!url) {
      throw new Error(`Invalid source ${name}: missing url.`);
    }

    return { name, url, enabled, ...(description ? { description } : {}) };
  });

  const aggressive = raw.aggressive && typeof raw.aggressive === 'object' ? raw.aggressive : {};
  const build = raw.build && typeof raw.build === 'object' ? raw.build : {};
  const output = raw.output && typeof raw.output === 'object' ? raw.output : {};

  return {
    name: typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : 'Merged AdGuard Home Blocklist',
    homepage: typeof raw.homepage === 'string' && raw.homepage.trim() ? raw.homepage.trim() : '',
    license: typeof raw.license === 'string' && raw.license.trim() ? raw.license.trim() : '',
    output: {
      file: typeof output.file === 'string' && output.file.trim() ? output.file.trim() : DEFAULT_OUTPUT_PATH,
      metadata: typeof output.metadata === 'string' && output.metadata.trim() ? output.metadata.trim() : DEFAULT_METADATA_PATH,
    },
    build: {
      minimumRules: Number.isInteger(build.minimumRules) && build.minimumRules >= 0 ? build.minimumRules : 0,
      allowEmpty: Boolean(build.allowEmpty),
    },
    aggressive: {
      compress: Boolean(aggressive.compress),
      validate: Boolean(aggressive.validate),
      removeModifiers: Boolean(aggressive.removeModifiers),
      removeComments: Boolean(aggressive.removeComments),
    },
    sources: normalizedSources,
  };
}

async function readSourceText(sourceUrl, configDir) {
  if (isHttpUrl(sourceUrl)) {
    const response = await fetch(sourceUrl, {
      headers: {
        'user-agent': 'filter-merger/1.0.0',
        accept: 'text/plain, text/*;q=0.9, */*;q=0.1',
      },
    });
    if (!response.ok) {
      throw new Error(`Failed to fetch ${sourceUrl}: ${response.status} ${response.statusText}`);
    }
    return stripBom(toPosixNewlines(await response.text()));
  }

  const filePath = isFileUrl(sourceUrl) ? new URL(sourceUrl) : path.resolve(configDir, sourceUrl);
  const text = await readFile(filePath, 'utf8');
  return stripBom(toPosixNewlines(text));
}

function classifyRuleLine(line) {
  const trimmed = line.trim();
  if (!trimmed) return 'empty';
  if (trimmed.startsWith('!')) return 'comment';
  return 'rule';
}

function mergeSources(sourceTexts, aggressive) {
  const seen = new Set();
  const mergedLines = [];
  const sourceStats = [];
  let emptyLinesRemoved = 0;
  let duplicateLinesRemoved = 0;
  let commentLinesRemoved = 0;
  let inputLines = 0;

  for (const item of sourceTexts) {
    const strippedText = stripLeadingCompilerHeader(item.text);
    const originalLines = strippedText.split('\n');
    const sourceComments = aggressive.removeComments
      ? originalLines.filter((line) => classifyRuleLine(line) === 'comment').length
      : 0;
    const lines = aggressive.removeComments
      ? originalLines.filter((line) => classifyRuleLine(line) !== 'comment')
      : originalLines;

    inputLines += originalLines.length;
    commentLinesRemoved += sourceComments;
    let sourceEmpty = 0;
    let sourceDuplicates = 0;
    const kept = [];

    for (const line of lines) {
      if (classifyRuleLine(line) === 'empty') {
        emptyLinesRemoved += 1;
        sourceEmpty += 1;
        continue;
      }
      if (seen.has(line)) {
        duplicateLinesRemoved += 1;
        sourceDuplicates += 1;
        continue;
      }
      seen.add(line);
      kept.push(line);
      mergedLines.push(line);
    }

    sourceStats.push({
      name: item.name,
      url: item.url,
      enabled: item.enabled,
      ...(item.description ? { description: item.description } : {}),
      linesIn: originalLines.length,
      sourceHeaderRemoved: item.text.split('\n').length - originalLines.length,
      linesAfterCommentFiltering: lines.length,
      linesOut: kept.length,
      emptyLinesRemoved: sourceEmpty,
      duplicateLinesRemoved: sourceDuplicates,
      commentLinesRemoved: sourceComments,
      bytes: Buffer.byteLength(item.text, 'utf8'),
    });
  }

  return {
    mergedLines,
    sourceStats,
    emptyLinesRemoved,
    duplicateLinesRemoved,
    commentLinesRemoved,
    inputLines,
  };
}

function countOutputRules(lines) {
  return lines.filter((line) => classifyRuleLine(line) === 'rule').length;
}

export async function buildFromConfig(config, { configPath = DEFAULT_CONFIG_PATH, outputFile, metadataFile } = {}) {
  const normalized = normalizeConfig(config, configPath);
  const configDir = path.dirname(path.resolve(configPath));
  const enabledSources = normalized.sources.filter((source) => source.enabled);

  if (enabledSources.length === 0 && !normalized.build.allowEmpty) {
    throw new Error('No enabled sources are available and allowEmpty is false.');
  }

  const loadedSources = [];
  for (const source of enabledSources) {
    const text = await readSourceText(source.url, configDir);
    loadedSources.push({ ...source, text });
  }

  const merged = mergeSources(loadedSources, normalized.aggressive);
  const mergedRuleCount = countOutputRules(merged.mergedLines);

  if (!normalized.build.allowEmpty && mergedRuleCount === 0) {
    throw new Error('Merged output contains no rules and allowEmpty is false.');
  }
  if (mergedRuleCount < normalized.build.minimumRules) {
    throw new Error(`Merged output contains ${mergedRuleCount} rules, which is below the configured minimum of ${normalized.build.minimumRules}.`);
  }

  const finalOutput = `${merged.mergedLines.join('\n')}\n`;
  const finalRuleCount = countOutputRules(merged.mergedLines);

  const metadata = {
    name: normalized.name,
    homepage: normalized.homepage,
    license: normalized.license,
    generated_at: new Date().toISOString(),
    generator: {
      name: 'filter-merger',
      version: '1.0.0',
    },
    config_path: path.resolve(configPath),
    config_hash: sha256(JSON.stringify(normalized)),
    output_hash: sha256(finalOutput),
    output_files: {
      file: outputFile ?? normalized.output.file,
      metadata: metadataFile ?? normalized.output.metadata,
    },
    counts: {
      sources_total: normalized.sources.length,
      sources_enabled: enabledSources.length,
      sources_disabled: normalized.sources.length - enabledSources.length,
      input_lines: merged.inputLines,
      empty_lines_removed: merged.emptyLinesRemoved,
      duplicate_lines_removed: merged.duplicateLinesRemoved,
      comment_lines_removed: merged.commentLinesRemoved,
      output_rules: finalRuleCount,
    },
    aggressive: normalized.aggressive,
    sources: merged.sourceStats,
  };

  return { outputText: finalOutput, metadata };
}

export async function main(argv = process.argv.slice(2)) {
  const configIndex = argv.indexOf('--config');
  const configPath = configIndex >= 0 && argv[configIndex + 1] ? path.resolve(argv[configIndex + 1]) : DEFAULT_CONFIG_PATH;
  const raw = await readFile(configPath, 'utf8');
  const config = YAML.parse(raw);
  const result = await buildFromConfig(config, { configPath });

  const normalized = normalizeConfig(config, configPath);
  await mkdir(path.dirname(normalized.output.file), { recursive: true });
  await mkdir(path.dirname(normalized.output.metadata), { recursive: true });
  await writeFile(normalized.output.file, result.outputText, 'utf8');
  await writeFile(normalized.output.metadata, `${JSON.stringify(result.metadata, null, 2)}\n`, 'utf8');

  process.stdout.write(`Wrote ${normalized.output.file} and ${normalized.output.metadata}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
