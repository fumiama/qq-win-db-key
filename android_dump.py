import frida
import sys
import platform
import os
import sys
import subprocess

# OPTIONS

PACKAGE = "com.tencent.mobileqq"

# OPTIONS END

ON_TERMUX: bool = None
def isOnTermux() -> bool:
    global ON_TERMUX
    if ON_TERMUX is not None:
        return ON_TERMUX
    if platform.system() == "Linux"\
        and "ANDROID_ROOT" in os.environ.keys()\
        and (os.path.exists("/data/data/com.termux")
             or ("TERMUX_VERSION" in os.environ.keys())):
        ON_TERMUX = True
        return True
    ON_TERMUX = False
    return False

jscode1 = """
const DATABASE = "nt_msg.db";
const module_name = "libkernel.so";

// FOR LOG
let SQLITE3_EXEC_CALLBACK_LOG = true;
let index1 = 0;
let xCallback = new NativeCallback(
  (para, nColumn, colValue, colName) => {
    if (!SQLITE3_EXEC_CALLBACK_LOG) {
      return 0;
    }
    console.log();
    console.log(
      "------------------------" + index1++ + "------------------------"
    );
    for (let index = 0; index < nColumn; index++) {
      let c_name = colName
        .add(index * 8)
        .readPointer()
        .readUtf8String();
      let c_value = "";
      try {
        c_value =
          colValue
            .add(index * 8)
            .readPointer()
            .readUtf8String() ?? "";
      } catch {}
      console.log(c_name, "\t", c_value);
    }
    return 0;
  },
  "int",
  ["pointer", "int", "pointer", "pointer"]
);

// CODE BELOW
var kernel_so = null;
function single_function(pattern) {
  pattern = pattern
    .replaceAll("##", "")
    .replaceAll(" ", "")
    .toLowerCase()
    .replace(/\\s/g, "")
    .replace(/(.{2})/g, "$1 ");
  var akey_function_list = Memory.scanSync(
    kernel_so.base,
    kernel_so.size,
    pattern
  );
  if (akey_function_list.length > 1) {
    console.log("pattern FOUND MULTI!!");
    console.log(pattern);
    console.log(akey_function_list);
    throw Error("pattern FOUND MULTI!!");
  }
  if (akey_function_list.length == 0) {
    console.log("pattern NOT FOUND!!");
    console.log(pattern);
    throw Error("pattern NOT FOUND!!");
  }
  return akey_function_list[0]["address"];
}

let get_filename_from_sqlite3_handle = function (sqlite3_db) {
  // full of magic number
  let zFilename = "";
  try {
    let db_pointer = sqlite3_db.add(0x8 * 5).readPointer();
    let pBt = db_pointer.add(0x8).readPointer();
    let pBt2 = pBt.add(0x8).readPointer();
    let pPager = pBt2.add(0x0).readPointer();
    zFilename = pPager.add(208).readPointer().readCString();
  } catch (e) {}
  return zFilename;
};

let hook = function () {
  var process_Obj_Module_Arr = Process.enumerateModules();
  for (var i = 0; i < process_Obj_Module_Arr.length; i++) {
    if (process_Obj_Module_Arr[i].path.indexOf(module_name) !== -1) {
      kernel_so = process_Obj_Module_Arr[i];
    }
  }
  if (kernel_so === null) {
    console.log(module_name + " not loaded. exit.");
    throw Error(".so not loaded");
  }

  // sqlite3_exec -> sub_1CFB9C0
  // let sqlite3_exec_addr = base_addr.add(0x1cfb9c0);
  let sqlite3_exec_addr = single_function(
    "FF 43 02 D1  FD 7B 03 A9 FC 6F 04 A9  FA 67 05 A9 F8 5F 06 A9    F6 57 07 A9 F4 4F 08 A9  FD C3 00 91 54 D0 3B D5    88 16 40 F9 F8 03 04 AA  F5 03 03 AA F6 03 02 AA"
  ); // 貌似是稳定的，先这样写
  console.log("sqlite3_exec_addr: " + sqlite3_exec_addr);

  let sqlite3_exec = new NativeFunction(sqlite3_exec_addr, "int", [
    "pointer",
    "pointer",
    "pointer",
    "int",
    "int",
  ]);

  let target_db_handle = null;
  let js_sqlite3_exec = function (sql) {
    if (target_db_handle === null) {
      return -1;
    }
    let sql_pointer = Memory.allocUtf8String(sql);
    return sqlite3_exec(target_db_handle, sql_pointer, xCallback, 0, 0);
  };

  // ATTACH BELOW
  Interceptor.attach(sqlite3_exec_addr, {
    onEnter: function (args) {
      // sqlite3*,const char*,sqlite3_callback,void*,char**
      let sqlite3_db = ptr(args[0]);
      let sql = Memory.readCString(args[1]);
      let callback_addr = ptr(args[2]);
      let callback_arg = ptr(args[3]);
      let errmsg = ptr(args[4]);
      let database_name = get_filename_from_sqlite3_handle(sqlite3_db);
      if (
        database_name.slice(database_name.lastIndexOf("/") + 1) === DATABASE
      ) {
        console.log("sqlite3_db: " + sqlite3_db);
        console.log("sql: " + sql);
        target_db_handle = sqlite3_db;
      }
    },
  });
  setTimeout(function () {
    let EXPORT_FILE_PATH = "/storage/emulated/0/Download/plaintext.db";
    // 不建议更改导出路径
    console.log("Start exporting database to " + EXPORT_FILE_PATH);
    let ret = js_sqlite3_exec(
      `ATTACH DATABASE '` +
        EXPORT_FILE_PATH +
        `' AS plaintext KEY '';SELECT sqlcipher_export('plaintext');DETACH DATABASE plaintext;`
    );
    console.log("Export end.");
    console.log("js_sqlite3_exec ret: " + ret);
  }, 4000); // hook 后 导出前 等待4秒
};

var hasHooked = false;
console.log("Script loaded. Waiting for " + module_name + " to load...");
const dlopen_process = {
  onEnter: function (args) {
    this.path = Memory.readUtf8String(args[0]);
    if (0) send("Loading " + this.path);
  },
  onLeave: function (retval) {
    if (this.path.indexOf(module_name) !== -1 && !hasHooked) {
      hasHooked = true;
      if (1) send("Hooked!!");
      hook();
    }
  },
};

try {
  Interceptor.attach(Module.findExportByName(null, "dlopen"), dlopen_process);
} catch (err) {}
try {
  Interceptor.attach(
    Module.findExportByName(null, "android_dlopen_ext"),
    dlopen_process
  );
} catch (err) {}

"""

if __name__ == "__main__":
    print("仍在测试。")
    print("请先关闭 Magisk Hide 与 Shamiko")
    print("请先禁用 SELinux")
    print("请先打开 QQ 并登录，进入主界面，然后运行该脚本，等待数秒后退出登录并重新登录。")
    print("理论支持 Termux 与 桌面操作系统 运行")
    print("请勿使用 x86 或 x64 系统上的安卓模拟器。")
    print("适用版本：")
    print("https://downv6.qq.com/qqweb/QQ_1/android_apk/qq_8.9.58.11050_64.apk")
    print("https://github.com/Young-Lord/QQ-History-Backup/issues/9")
    print("""Termux 环境具体命令：
    sudo friendly # 重命名后的 frida-server
    python android_hook.py""")
    print("")
    print("可能需要彻底关闭 QQ 后运行，或者运行后重新登录")

    if isOnTermux():
        device = frida.get_remote_device()
    else:
        device = frida.get_usb_device()
    try:
        pid = int(subprocess.check_output(
            "su -c pidof "+PACKAGE, shell=True).decode().strip())
    except subprocess.CalledProcessError:
        running = False
    else:
        running = True
    if running:
        print(PACKAGE+" is already running", pid)
        session = device.attach(pid)
        script = session.create_script(jscode1)
    else:
        pid = device.spawn([PACKAGE])
        session = device.attach(pid)
        script = session.create_script(jscode1)
        device.resume(pid)
    print("QQ running!! pid = %d" % pid)
    
    def on_message(message, data):
        if message["type"] == "send":
            toprint=message["payload"]
        else:
            toprint=message
        toprint=str(toprint)
        #toprint=str(list(toprint))
        print(toprint)
    script.on("message", on_message)
    script.load()
    print("Frida script injected.")
    sys.stdin.read()
