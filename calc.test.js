const { add } = require('./calc');

test('add', () => {
  expect(add(1, 2)).toBe(3);
});

test('add with negative numbers', () => {
  expect(add(-1, -2)).toBe(-3);
  expect(add(-5, 3)).toBe(-2);
  expect(add(5, -3)).toBe(2);
});
