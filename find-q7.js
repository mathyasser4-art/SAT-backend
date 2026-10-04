for (let a = -10; a <= 10; a++) {
    for (let c = -500; c <= 500; c++) {
        if (a === 0) continue;
        let p1 = -22, p2 = 25, p3 = 314, p4 = 14;
        let v1 = a * (p1 - c);
        let v2 = a * (p2 - c);
        let v3 = a * (p3 - c);
        let v4 = a * (p4 - c);
        
        let isSq = (n) => n >= 0 && Math.sqrt(n) % 1 === 0;
        
        if (isSq(v1) && isSq(v2) && isSq(v3) && !isSq(v4)) {
            console.log(`Found match: a = ${a}, c = ${c}`);
        }
    }
}
