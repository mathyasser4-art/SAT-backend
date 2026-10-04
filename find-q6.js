const xs = [0.75, 2.5, 3, 4];
for (let x of xs) {
    let lhs = 1 / (x - 3);
    let rhs = (x - 1) / x + 1.75;
    if (Math.abs(lhs - rhs) < 0.001) {
        console.log(`x = ${x} works!`);
    }
}
