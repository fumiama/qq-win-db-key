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

funcident = {
    '8.9.76': 'FD 7B BD A9 F6 57 01 A9 F4 4F 02 A9 FD 03 00 91 21 02 00 B4 08 30 40 B9 1F 01 00 71 15 C1',
}


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in funcident:
        print("usage: qq.version.number")
        print("supported version:", *funcident.keys())
        sys.exit(1)

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
                "su -c pidof "+PACKAGE, shell=True).decode().strip()
            ) if ON_TERMUX else device.get_frontmost_application().pid
    except subprocess.CalledProcessError:
        running = False
    else:
        running = True
    with open("android_get_key_new_method.js", "rb") as f:
        jscode1 = f.read().decode()
    jscode1 = jscode1.replace("__single_function__parameter__", funcident[sys.argv[1]])
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
