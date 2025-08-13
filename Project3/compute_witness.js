const fs = require("fs");
const witnessCalcFactory = require("./witness_calculator.js");
const [,, wasmPath, inputPath, outputPath] = process.argv;

if (!wasmPath || !inputPath || !outputPath) {
    console.error("用法: node compute_witness.js <circuit.wasm> <input.json> <output.wtns>");
    process.exit(1);
}

function loadJSON(file) {
    return JSON.parse(fs.readFileSync(file, "utf8"));
}

function loadWasm(file) {
    return fs.readFileSync(file);
}

(async () => {
    try {
        const inputData = loadJSON(inputPath);
        const wasmBuffer = loadWasm(wasmPath);

        const calc = await witnessCalcFactory(wasmBuffer);
        const wtnsBuffer = await calc.calculateWTNSBin(inputData, 0);

        fs.writeFileSync(outputPath, wtnsBuffer);
        console.log(`Witness 文件已生成: ${outputPath}`);
    } catch (err) {
        console.error("生成 witness 失败：", err);
        process.exit(1);
    }
})();
