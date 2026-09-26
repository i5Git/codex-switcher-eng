import type { UiLocale } from './runtime';
import { enBatch1 } from './en_batch1';
import { enBatch2 } from './en_batch2';
import { enBatch3 } from './en_batch3';
import { enBatch4a } from './en_batch4a';
import { enBatch4b } from './en_batch4b';
import { enBatch5 } from './en_batch5';
import { enBatch6 } from './en_batch6';
import { enBatch7 } from './en_batch7';

type Replacement = readonly [source: string, target: string];

const replacements: Replacement[] = [
  ...enBatch1,
  ...enBatch2,
  ...enBatch3,
  ...enBatch4a,
  ...enBatch4b,
  ...enBatch5,
  ...enBatch6,
  ...enBatch7,
];

const sortedReplacements = [...replacements].sort((a, b) => b[0].length - a[0].length);
const exactReplacements = new Map(replacements);
const cjkRe = /[\u4e00-\u9fff]/;
const normalizeWhitespace = (value: string) => value.replace(/\s+/g, ' ').trim();
const normalizedExactReplacements = new Map(
  replacements.map(([source, target]) => [normalizeWhitespace(source), target]),
);
const placeholderRe = /\{[^{}]*\}/g;
const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\const escapeRegExp = (value: string) => value.replace(/[.*+?^$()|[\]\\{}]/g, '\\$&');');
const dynamicReplacements = replacements
  .filter(([source]) => /\{[^{}]*\}/.test(source))
  .sort((a, b) => b[0].length - a[0].length)
  .map(([source, target]) => {
    placeholderRe.lastIndex = 0;
    const parts = normalizeWhitespace(source).split(placeholderRe).map(escapeRegExp);
    placeholderRe.lastIndex = 0;
    return { pattern: new RegExp('^' + parts.join('(.*?)') + '$', 'u'), target };
  });
const partialReplacements = sortedReplacements.filter(([source]) => (
  cjkRe.test(source) || /[（）：「」【】、，。；]/.test(source)
));

export function translateEn(value: string): string {
  if (!value) return value;

  const leading = value.match(/^\s*/)?.[0] ?? '';
  const trailing = value.match(/\s*$/)?.[0] ?? '';
  const core = value.trim();

  const exact = exactReplacements.get(core);
  if (exact) return leading + exact + trailing;

  const normalizedExact = normalizedExactReplacements.get(normalizeWhitespace(core));
  if (normalizedExact) return leading + normalizedExact + trailing;

  const normalizedCore = normalizeWhitespace(core);
  for (const replacement of dynamicReplacements) {
    const match = replacement.pattern.exec(normalizedCore);
    if (!match) continue;
    let capture = 1;
    const translated = replacement.target.replace(placeholderRe, () => match[capture++] ?? '');
    return leading + translated + trailing;
  }

  if (!cjkRe.test(value)) return value;

  let out = value;
  for (const [source, target] of partialReplacements) {
    if (out.includes(source)) out = out.split(source).join(target);
  }

  out = out
    .replace(/(\d+)\s*天后重置/g, 'Resets in $1 days')
    .replace(/(\d+)\s*小时(\d+)\s*分钟后重置/g, 'Resets in $1h $2m')
    .replace(/(\d+)\s*分钟后重置/g, 'Resets in $1m')
    .replace(/(\d+)\s*天\s*(\d+)\s*小时\s*(\d+)\s*分钟\s*后重置/g, 'Resets in $1d $2h $3m')
    .replace(/(\d+)\s*小时\s*(\d+)\s*分钟\s*(\d+)\s*秒\s*后重置/g, 'Resets in $1h $2m $3s')
    .replace(/(\d+)\s*分钟\s*(\d+)\s*秒\s*后重置/g, 'Resets in $1m $2s')
    .replace(/(\d+)\s*秒\s*后重置/g, 'Resets in $1s')
    .replace(/(\d+)\s*天到期/g, '$1 days until expiration')
    .replace(/(\d+)\s*天前/g, '$1 days ago')
    .replace(/(\d+)\s*小时前/g, '$1 hours ago')
    .replace(/(\d+)\s*分钟前/g, '$1 minutes ago')
    .replace(/(\d+)\s*个使用额度/g, '$1 usage credits')
    .replace(/(\d+)\s*个工作区额度/g, '$1 workspace credits')
    .replace(/(\d+)\s*次限额重置/g, '$1 quota resets')
    .replace(/(\d+)\s*个账号/g, '$1 accounts')
    .replace(/(\d+)\s*人/g, '$1 people')
    .replace(/(\d+)\s*条/g, '$1 entries')
    .replace(/(\d+)\s*天/g, '$1d')
    .replace(/(\d+)\s*小时/g, '$1h')
    .replace(/(\d+)\s*分钟/g, '$1m')
    .replace(/(\d+)\s*秒/g, '$1s')
    .replace(/(\d+)\s*时/g, '$1h')
    .replace(/(\d+)\s*分/g, '$1m');

  return out;
}

export const englishLocale: UiLocale = {
  code: 'en',
  title: 'Codex Switcher',
  translate: translateEn,
};

export function countEnglishReplacements(): number {
  return replacements.length;
}
