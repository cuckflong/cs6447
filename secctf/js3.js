function runIntel(o) {
    var size = 4096;
    var array = Array.from(Array(size)).map((OOO, ooooo) => 0);
    var i = 0;
    for (let j of o) {
        array[i] = j;
        i++
    }
    var i = 4001;
    for (let oOOooO of "flag{XXXXXXXXXXXXX}") {
        array[i] = oOOooO.charCodeAt(0);
        i++
    }
    var ram = [0, 0, 0, 0, 0, 0, 0, 0];
    var Instructions = [
    1. (a, b, c) => {}, (a, b, c) => {
        if (b < 4000) ram[a] = array[b]
    }, 
    2. (a, b, c) => console.log(String.fromCharCode(ram[a])), 
    3. (a, b, c) => ram[a] = ram[b] - ram[c], 
    4. (a, b, c) => ram[a] = ram[b] + ram[c], 
    5. (a, b, c) => {
        if (a < 4000) array[a] = ram[b]
    }, 
    6. (a, b, c) => console.log(ram), 
    7. (a, b, c) => ram[a] = b, 
    8. (a, b, c) => ram[a] = array[b] + array[c]];
    let oOOOo = 0;
    while (oOOOo + 3 <= 4000) {
        if (Instructions[array[oOOOo]] !== undefined)
            Instructions[array[oOOOo]](array[oOOOo + 1], array[oOOOo + 2], array[oOOOo + 3]);
        oOOOo += 4
    }
}
process.stdin.on('data', function(oo) {
    let o = String(oo).split(" ");
    o = o.map(ooo => parseInt(ooo));
    runIntel(o)
});
console.log("Welcome to intel_3.js! Good luck with this one smarty pants")