const checkExpiration = (startingDate, expiryDate) => {
    const currentDate = new Date()
    const start = new Date(startingDate);
    start.setDate(start.getDate() - 1); // 24-hour timezone buffer
    start.setHours(0, 0, 0, 0);
    
    const end = new Date(expiryDate);
    end.setDate(end.getDate() + 1); // 24-hour timezone buffer
    end.setHours(23, 59, 59, 999);
    
    if (currentDate <= end && currentDate >= start) {
        return false // not expire
    } else {
        return true // it is expire
    }
}

module.exports = checkExpiration;