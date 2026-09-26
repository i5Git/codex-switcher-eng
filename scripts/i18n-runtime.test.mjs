import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

const source = fs.readFileSync('src/i18n/ru.ts', 'utf8');
const code = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const module = { exports: {} };
vm.runInNewContext(code, { module, exports: module.exports });
const { translateRu } = module.exports;

function transpileModule(file, context = {}) {
  const source = fs.readFileSync(file, 'utf8');
  const code = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const loaded = { exports: {} };
  vm.runInNewContext(code, {
    module: loaded,
    exports: loaded.exports,
    require: name => context[name] ?? {},
  });
  return loaded.exports;
}

const englishBatches = {
  './en_batch1': transpileModule('src/i18n/en_batch1.ts'),
  './en_batch2': transpileModule('src/i18n/en_batch2.ts'),
  './en_batch3': transpileModule('src/i18n/en_batch3.ts'),
  './en_batch4a': transpileModule('src/i18n/en_batch4a.ts'),
  './en_batch4b': transpileModule('src/i18n/en_batch4b.ts'),
  './en_batch5': transpileModule('src/i18n/en_batch5.ts'),
  './en_batch6': transpileModule('src/i18n/en_batch6.ts'),
  './en_batch7': transpileModule('src/i18n/en_batch7.ts'),
};
const { translateEn, countEnglishReplacements } = transpileModule('src/i18n/en.ts', {
  ...englishBatches,
  './runtime': {},
});

const { resolveAppLocale } = transpileModule('src/i18n/index.ts', {
  './en': { englishLocale: {} },
  './ru': { russianLocale: {} },
  './runtime': { installUiLocale() {} },
});

test('system locale selects supported languages and unsupported locales fall back to English', () => {
  assert.equal(resolveAppLocale('ru'), 'ru');
  assert.equal(resolveAppLocale('ru-RU'), 'ru');
  assert.equal(resolveAppLocale('zh-CN'), 'zh-CN');
  assert.equal(resolveAppLocale('en-US'), 'en');
  assert.equal(resolveAppLocale('en-GB'), 'en');
  assert.equal(resolveAppLocale('fr-FR'), 'en');
  assert.equal(resolveAppLocale(''), 'en');
  assert.equal(resolveAppLocale('en-US', 'ru'), 'ru');
  assert.equal(resolveAppLocale('ru-RU', 'zh-CN'), 'zh-CN');
  assert.equal(resolveAppLocale('ru-RU', 'en'), 'en');
  assert.equal(resolveAppLocale('ru-RU', 'unsupported'), 'ru');
  assert.equal(resolveAppLocale('ru-RU', 'auto'), 'ru');
});

test('dynamic backend messages retain values and prefer the most specific template', () => {
  const cases = [
    ['模型列表请求失败: timeout', 'Не удалось запросить список моделей: timeout'],
    [
      'Server 不可达（primary=http://a, fallback=http://b）',
      'Server недоступен (основной адрес: http://a, резервный: http://b)',
    ],
    ['已重置 2 个限额窗口', 'Сброшено окон лимита: 2'],
  ];
  for (const [input, expected] of cases) assert.equal(translateRu(input), expected);
});

test('complete messages win over fragment replacements', () => {
  assert.equal(
    translateRu('Fast 模式已开启（2x 额度消耗，更快推理）。重启 Codex 生效。'),
    'Режим Fast включён: ответы быстрее, расход квоты удвоен. Перезапустите Codex для применения',
  );
});


test('English catalog translates current UI and dynamic backend messages', () => {
  assert.equal(countEnglishReplacements(), 1630);
  assert.equal(translateEn('账号管理'), 'Accounts');
  assert.equal(translateEn('Google 账号不存在'), 'Google account not found');
  assert.equal(
    translateEn('模型列表请求失败: timeout'),
    'Model list request failed: timeout',
  );
  assert.equal(
    translateEn('Server 不可达（primary=http://a, fallback=http://b）'),
    'Server unreachable (primary=http://a, fallback=http://b)',
  );
  assert.equal(translateEn('已重置 2 个限额窗口'), 'Reset 2 quota windows');
});

test('English complete messages take precedence over fragments', () => {
  assert.equal(
    translateEn('Fast 模式已开启（2x 额度消耗，更快推理）。重启 Codex 生效。'),
    'Fast mode enabled (2x quota consumption, faster reasoning). Restart Codex to apply.',
  );
});