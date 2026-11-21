import {cpSync, mkdirSync, rmSync} from 'node:fs';
import {spawnSync} from 'node:child_process';

const root = new URL('../', import.meta.url);
const distribution = new URL('dist/', root);
rmSync(distribution, {recursive: true, force: true});
const compiler = spawnSync(process.execPath, ['node_modules/typescript/bin/tsc'], {cwd: root, stdio: 'inherit'});
if (compiler.status !== 0) process.exit(compiler.status ?? 1);
mkdirSync(distribution, {recursive: true});
for (const file of ['metadata.json', 'README.md', 'icons'])
    cpSync(new URL(`extension/${file}`, root), new URL(file, distribution), {recursive: true});
