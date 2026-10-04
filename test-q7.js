for (let w of [-22, 14, 25, 314]) {
    console.log(`w = ${w}`);
    for (let c = -500; c <= 500; c++) {
        // equation: 4x^2 - px + w = c  => p^2 = 16(w - c)
        let val1 = w - c;
        // equation: 4x^2 - px + c = w  => p^2 = 16(c - w)
        let val2 = c - w;
        
        if (Math.sqrt(val1) % 1 === 0) {
            // w - c is perfect square
        }
    }
}
