const module_name = "libkernel.so"

function hook(){
    function buf2hex(buffer) {
        const byteArray = new Uint8Array(buffer);
        const hexParts = [];
        for(let i = 0; i < byteArray.length; i++) {
            const hex = byteArray[i].toString(16);
            const paddedHex = ('00' + hex).slice(-2);
            hexParts.push(paddedHex);
        }
        return '0x' + hexParts.join(', 0x');
    }
    function buf2str(buffer, skip) {
        let result = "";
        const byteArray = new Uint8Array(buffer);
        for (let i = skip; i < byteArray.length; i++) {
            result += String.fromCharCode(byteArray[i]);
        }
        return result;
    }
    function hex2str(hex) {
        let str = '';
        for (let i = 0; i < hex.length; i += 2) {
            let charCode = parseInt(hex.substr(i, 2), 16);
            str += String.fromCharCode(charCode);
        }
        return str;
    }
    function hex2str_rev(hex) {
        let str = '';
        for (let i = hex.length-2; i >= 0; i -= 2) {
            let charCode = parseInt(hex.substr(i, 2), 16);
            str += String.fromCharCode(charCode);
        }
        return str;
    }
    var kernel_util = null;
    var process_Obj_Module_Arr = Process.enumerateModules();
    for(var i = 0; i < process_Obj_Module_Arr.length; i++) { 
    if(process_Obj_Module_Arr[i].path.indexOf(module_name)!=-1)   {
        console.log("模块名称:",process_Obj_Module_Arr[i].name);
        console.log("模块地址:",process_Obj_Module_Arr[i].base);
        console.log("大小:",process_Obj_Module_Arr[i].size);
        console.log("文件系统路径",process_Obj_Module_Arr[i].path);
        kernel_util = process_Obj_Module_Arr[i];
    }}
    if(kernel_util == null) {
        send(module_name + " not loaded. exit.")
    } else {
        function single_function(pattern) {
            pattern = pattern.replaceAll("##", "").replaceAll(" ", "").toLowerCase().replace(/\\s/g,'').replace(/(.{2})/g,"$1 ");
            send("Pattern: " + pattern)
            var akey_function_list = Memory.scanSync(kernel_util.base, kernel_util.size, pattern);
            if (akey_function_list.length == 0) {
                send("Pattern NOT FOUND!! EXIT!!")
                return null;
            }
            if (akey_function_list.length > 1) {
                send("Multi-pattern FOUND!! Take first item.")
            }
            send("Attach key_function addr: " + akey_function_list[0]['address'])
            return akey_function_list[0]['address'];
        }

        const key_function = single_function("__single_function__parameter__")

        if(key_function != null) Interceptor.attach(key_function, {
            onEnter: function(args) {
                console.log("¦-------------------");
                console.log("¦- arg0: " + "(" + args[0] + ")");
                console.log("¦- arg1: " + "(" + args[1] + ")");
                console.log("¦- arg2: " + "(" + args[2] + ")");
                console.log("¦- arg3: " + "(" + args[3] + ")");
                console.log("¦- arg4: " + "(" + args[4] + ")");
                console.log("¦- arg5: " + "(" + args[5] + ")");
                console.log("¦- arg6: " + "(" + args[6] + ")");
                console.log("¦- arg7: " + "(" + args[7] + ")");
                console.log("¦- arg8: " + "(" + args[8] + ")");
                console.log("¦- arg9: " + "(" + args[9] + ")");
                console.log("¦- arg10:" + "(" + args[10] + ")");
                console.log("¦- arg11:" + "(" + args[11] + ")");
                console.log("¦- arg12:" + "(" + args[12] + ")");
                console.log("¦- arg13:" + "(" + args[13] + ")");
                console.log("¦- arg14:" + "(" + args[14] + ")");
                console.log("¦- arg15:" + "(" + args[15] + ")");
                console.log("¦- arg16:" + "(" + args[16] + ")");
                console.log("¦- arg17:" + "(" + args[17] + ")");
                console.log("¦- arg18:" + "(" + args[18] + ")");
                console.log("¦- arg19:" + "(" + args[19] + ")");
                console.log("¦- arg20:" + "(" + args[20] + ")");
                console.log("¦- arg21:" + "(" + args[21] + ")");
                console.log("¦- arg22:" + "(" + args[22] + ")");
                console.log("¦- arg23:" + "(" + args[23] + ")");
                console.log("¦- arg24:" + "(" + args[24] + ")");
                console.log("¦- arg25:" + "(" + args[25] + ")");
                console.log("¦- arg26:" + "(" + args[26] + ")");
                console.log("¦- arg27:" + "(" + args[27] + ")");
                console.log("¦- arg28:" + "(" + args[28] + ")");
                console.log("¦- arg29:" + "(" + args[29] + ")");
                console.log("¦- arg30:" + "(" + args[30] + ")");
                console.log("¦- arg31:" + args[31] + "(" + args[31] + ")");
                console.log("¦- arg32:" + args[32] + "(" + args[32] + ")");
                console.log("¦- arg33:" + args[33] + "(" + args[33] + ")");
                console.log("¦- arg34:" + args[34] + "(" + args[34] + ")");
                console.log("¦- arg35:" + args[35] + "(" + args[35] + ")");
                console.log("¦- arg36:" + args[36] + "(" + args[36] + ")");
                console.log("¦- arg37:" + args[37] + "(" + args[37] + ")");
                console.log("¦- arg38:" + args[38] + "(" + args[38] + ")");
                console.log("¦- arg39:" + args[39] + "(" + args[39] + ")");
                console.log("¦- arg40:" + args[40] + "(" + args[40] + ")");
                console.log("¦- arg41:" + args[41] + "(" + args[41] + ")");
                console.log("¦- arg42:" + args[42] + "(" + args[42] + ")");
                console.log("¦- arg43:" + args[43] + "(" + args[43] + ")");
                console.log("¦- arg44:" + args[44] + "(" + args[44] + ")");
                console.log("¦- arg45:" + args[45] + "(" + args[45] + ")");
                console.log("¦- arg46:" + args[46] + "(" + args[46] + ")");
                console.log("¦- arg47:" + args[47] + "(" + args[47] + ")");
                console.log("¦- arg48:" + args[48] + "(" + args[48] + ")");
                console.log("¦- arg49:" + args[49] + "(" + args[49] + ")");
                console.log("¦- arg50:" + args[50] + "(" + args[50] + ")");
                console.log("¦- arg51:" + args[51] + "(" + args[51] + ")");
                console.log("¦- arg52:" + args[52] + "(" + args[52] + ")");
                console.log("¦- arg53:" + args[53] + "(" + args[53] + ")");
                console.log("¦- arg54:" + args[54] + "(" + args[54] + ")");
                console.log("¦- arg55:" + args[55] + "(" + args[55] + ")");
                console.log("¦- arg56:" + args[56] + "(" + args[56] + ")");
                console.log("¦- arg57:" + args[57] + "(" + args[57] + ")");
                console.log("¦- arg58:" + args[58] + "(" + args[58] + ")");
                console.log("¦- arg59:" + args[59] + "(" + args[59] + ")");
                console.log("¦- arg60:" + args[60] + "(" + args[60] + ")");
                console.log("¦-------------------");
            },
        });
    }
}

hook()
