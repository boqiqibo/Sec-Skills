function hook_ssl_verify_result(address) {
    Interceptor.attach(address, {
        onEnter: function(args) {
            console.log("Disabling SSL validation")
        },
        onLeave: function(retval) {
            console.log("Retval: " + retval);
            retval.replace(0x1);
        }
    });
}

function hookFlutter_64() {
    var m = Process.findModuleByName("libflutter.so");
    // Replace this pattern with the actual bytecode from ssl_client function
    var pattern = "FF C3 01 D1 FD 7B 01 A9 FC 6F 02 A9 FA 67 03 A9 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 08 0A 80 52 48 00 00 39";
    var res = Memory.scan(m.base, m.size, pattern, {
        onMatch: function(address, size){
            console.log('[+] ssl_verify_result found at: ' + address.toString());
            hook_ssl_verify_result(address.add(0x01));
        },
        onError: function(reason){
            console.log('[!] There was an error scanning memory');
        },
        onComplete: function() {
            console.log("All done")
        }
    });
}

function hookFlutter_32() {
    var m = Process.findModuleByName("libflutter.so");
    // Replace this pattern with the actual bytecode from ssl_client function (32-bit)
    var pattern = "2D E9 F0 4F 85 B0 06 46 50 20 10 70";
    var res = Memory.scan(m.base, m.size, pattern, {
        onMatch: function(address, size){
            console.log('[+] ssl_verify_result found at: ' + address.toString());
            hook_ssl_verify_result(address.add(0x01));
        },
        onError: function(reason){
            console.log('[!] There was an error scanning memory');
        },
        onComplete: function() {
            console.log("All done")
        }
    });
}

// Usage: 
// For 64-bit libflutter.so
setTimeout(hookFlutter_64, 1000);

// For 32-bit libflutter.so, comment out above line and uncomment below:
// setTimeout(hookFlutter_32, 1000);

// Command line usage:
// frida -U -f appname -l hookFluttersslbypass.js --no-pause
