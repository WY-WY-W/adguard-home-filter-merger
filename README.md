# AdGuard Home Filter Merger

This repository merges multiple already-processed AdGuard or adblock-style source lists into one AdGuard Home-compatible blocklist.

## What it does

- Reads `config.yaml` from the repo root
- Fetches or loads each enabled source URL
- Strips the leading AdGuard compiler header block from each source before merging
- Removes empty lines
- Removes exact duplicate lines
- Preserves comments unless `aggressive.removeComments` is enabled
- Writes a merged list to `dist/adguardhome-merged.txt`
- Writes build metadata to `dist/metadata.json`

## Configuration

Edit `config.yaml` to add, disable, or remove sources.

Each source needs:

- `name`
- `url`
- `enabled`
- optional `description`

Supported source URLs can be remote HTTP(S) URLs or local file paths for testing.

Aggressive mode is off by default:

- `compress`
- `validate`
- `removeModifiers`
- `removeComments`

Keep those `false` unless you want extra transformations applied to the merged output.

## Usage

Install dependencies:

```bash
npm ci
```

Build the merged list:

```bash
npm run build
```

Run the smoke test:

```bash
npm test
```

## GitHub Actions

The workflow in `.github/workflows/build-blocklist.yml` runs on a cron schedule and can also be started manually with `workflow_dispatch`.

It rebuilds the list and commits changed files in `dist/` back to the repository.
