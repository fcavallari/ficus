import { expect, test } from 'vitest';
import { guideSection } from '../src/ui/route';

test('guideSection reads the section a hash names', () => {
  expect(guideSection('')).toBeNull();
  expect(guideSection('#other')).toBeNull();
  expect(guideSection('#guide')).toBe('');
  expect(guideSection('#guide/capture')).toBe('capture');
  expect(guideSection('#guide/rule-a%20b')).toBe('rule-a b');
});

test('guideSection survives a hash with a bad escape, as the text written', () => {
  expect(() => guideSection('#guide/%E0%A4%A')).not.toThrow();
  expect(guideSection('#guide/%')).toBe('%');
});
