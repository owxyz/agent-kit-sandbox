const { add, absDiff } = require('./calc');

test('add', () => {
  expect(add(1, 2)).toBe(3);
});

test('absDiff is never negative', () => {
  expect(absDiff(1, 3)).toBe(2);
  expect(absDiff(3, 1)).toBe(2);
  expect(absDiff(-2, 2)).toBe(4);
});
