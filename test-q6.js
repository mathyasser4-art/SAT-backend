const fs = require('fs');

// Solve 1/(x-3) = (x-1)/x + 1.75
// (x-1)/x + 7/4 = 1 - 1/x + 7/4 = 11/4 - 1/x = (11x - 4)/(4x)
// 1/(x-3) = (11x - 4)/(4x)
// 4x = (x-3)(11x - 4) = 11x^2 - 4x - 33x + 12 = 11x^2 - 37x + 12
// 11x^2 - 41x + 12 = 0
// Discriminant: 41^2 - 4*11*12 = 1681 - 528 = 1153 (not a perfect square)

console.log('Roots of 11x^2 - 41x + 12 = 0:');
const r1 = (41 + Math.sqrt(1153)) / 22;
const r2 = (41 - Math.sqrt(1153)) / 22;
console.log('r1 =', r1, 'r2 =', r2);

// What if the equation was:
// 1/(x-3) = (x-1)/x + something?
// Or what if the equation was:
// 1/(x-3) = ...?
// What if x = 2.5?
// 1/(2.5 - 3) = -2
// What if the right side was (x-1)/x - ...?
// For x = 2.5: (2.5 - 1)/2.5 = 1.5/2.5 = 0.6.
// If 0.6 - 2.6 = -2?
// Or what if:
// 1/(x-something) = ...
