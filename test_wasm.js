const Module = require('./decryptors.js');
const fs = require('fs');

async function test() {
    // Wait for module to initialize
    await new Promise(resolve => {
        if (Module.calledRun) resolve();
        else Module.onRuntimeInitialized = resolve;
    });

    console.log("[*] WASM Module initialized.");

    // Simple test for AndLua Stage 1 (partial logic)
    // Since we don't have a real encrypted file, let's just test if the functions are there.
    if (Module._decrypt_andlua && Module._decrypt_luaappx) {
        console.log("[+] Decrypt functions exported correctly.");
    } else {
        console.error("[!] Decrypt functions NOT found.");
    }
}

test();
