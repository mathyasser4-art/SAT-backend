// Search variations of Q6 equation
// Choices: 2.5, 0.75, 3, 4. (Key is 2.5)

// What if the equation was:
// 1/(x-3) = ... or (x-1)/... or something with 1.75?
console.log('Testing x = 2.5:');
// Suppose x = 2.5.
// (x - 1)/x = 1.5/2.5 = 3/5 = 0.6.
// What if 1/(...) = 0.6 + 1.75? 0.6 + 1.75 = 2.35.
// What if 1.75 was 1.4? 0.6 + 1.4 = 2. Then 1/(x - 2) or 1/(3 - x) = 2.
// What if the right side was (x - 1)/x + 0.75? 0.6 + 0.75 = 1.35.
// What if the left side was:
// (x-1)/(x-3) = ...?
// At x = 2.5: (2.5 - 1)/(2.5 - 3) = 1.5 / (-0.5) = -3.
// What if:
// 1/(x-something) = ...
// What if x = 4 was the answer?
// At x = 4:
// (4-1)/4 + 0.25 = 1. 1/(4-3) = 1.
// But the key in the database is 2.5!

// Let's check what x values make:
// 1/(x-3) = (x-1)/x + 1.75?
// We found earlier roots are:
// (41 +- sqrt(1153))/22:
// sqrt(1153) ~ 33.95585
// r1 = (41 + 33.95585)/22 = 74.95585/22 = 3.407
// r2 = (41 - 33.95585)/22 = 7.04415/22 = 0.320

// Wait! What if the equation in the test was:
// 1/(x - 2) = ...?
// 1/(x - 1) = ...?
// What if 1/(2x - 3) or 1/(2x - 4)?
