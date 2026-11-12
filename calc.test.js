const { add } = require('./calc');

test('add', () => {
  expect(add(1, 2)).toBe(3);
});
