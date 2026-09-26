import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve('src', 'i18n');
const batchFiles = [
  'en_batch1.ts',
  'en_batch2.ts',
  'en_batch3.ts',
  'en_batch4a.ts',
  'en_batch4b.ts',
  'en_batch5.ts',
  'en_batch6.ts',
  'en_batch7.ts',
];

const pairRe = /^\s*\['((?:\\.|[^'\\])*)',\s*'((?:\\.|[^'\\])*)'\],?\s*$/gm;
const cjk = /[\u3400-\u9fff]/u;

function unescapeLiteral(value) {
  return value
    .replace(/\\'/g, "'")
    .replace(/\\\\/g, '\\')
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r');
}

function parsePairs(file) {
  const content = fs.readFileSync(file, 'utf8');
  const pairs = [];
  pairRe.lastIndex = 0;
  let match;
  while ((match = pairRe.exec(content))) {
    pairs.push([unescapeLiteral(match[1]), unescapeLiteral(match[2])]);
  }
  return pairs;
}

const russian = parsePairs(path.join(root, 'ru.ts'));
const english = batchFiles.flatMap(file => parsePairs(path.join(root, file)));
const errors = [];

if (russian.length === 0) errors.push('Russian source catalog could not be parsed');
if (english.length !== russian.length) {
  errors.push(\`English catalog count \${english.length} does not match Russian source count \${russian.length}\`);
}

const seen = new Set();
english.forEach(([source, target], index) => {
  if (seen.has(source)) errors.push(\`Duplicate English source at index \${index}: \${JSON.stringify(source)}\`);
  seen.add(source);

  const expected = russian[index]?.[0];
  if (expected !== source) {
    errors.push(
      \`Source sequence mismatch at index \${index}: expected \${JSON.stringify(expected)}, got \${JSON.stringify(source)}\`,
    );
  }

  if (!target.trim()) errors.push(\`Empty English target at index \${index}: \${JSON.stringify(source)}\`);
  if (cjk.test(target)) {
    errors.push(\`CJK remains in English target at index \${index}: \${JSON.stringify(target)}\`);
  }

  const sourcePlaceholders = source.match(/\{[^{}]*\}/g)?.length ?? 0;
  const targetPlaceholders = target.match(/\{[^{}]*\}/g)?.length ?? 0;
  if (sourcePlaceholders !== targetPlaceholders) {
    errors.push(
      \`Placeholder count mismatch at index \${index}: \${JSON.stringify(source)} -> \${JSON.stringify(target)}\`,
    );
  }
});

if (errors.length) {
  console.error(\`English localization parity check failed (\${errors.length}):\`);
  for (const error of errors.slice(0, 100)) console.error(\`- \${error}\`);
  if (errors.length > 100) console.error(\`... and \${errors.length - 100} more\`);
  process.exitCode = 1;
} else {
  console.log(\`English localization parity passed: \${english.length} strings match the current source catalog.\`);
}
