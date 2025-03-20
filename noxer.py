import os
import pathlib
import subprocess
import psutil
import re
import requests
from OpenSSL import crypto
from requests.exceptions import ConnectionError

adb_bin = ""
vm_installation_path = ""
adb_path = "adb"
adb_addr = "127.0.0.1"
adb_port_list = [5555]
adb_connected = False

banner = """\033[38;5;208m
__  _ _______ __  __ _______ ______
| | | ||    || |_| ||    ||  _ |
|  |_| ||  _  ||    ||  ___||  | ||
|    || | | ||    ||  |___ |  |_||_
| _  || |_| | |   | |  ___||  __ |
| | |  ||    ||  _  ||  |___ |  | | |
|_| |__||_______||__| |__||_______||___| |_|
____________Android Emulator Mod for GEEKZ______________
     Github: AggressiveUser
                  Ver-1.22_β
\033[0m"""
print(banner)

# Yaar Haryane Te - PANDAT JI :)


# run command in subprocess without any output
def run_in_bg(command):
    subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def is_tool_installed(tool):
    try:
        subprocess.run([tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False


def install_tool(tool):
    subprocess.run(["pip", "install", tool])


def find_vm_installation_path(emulator_name):
    for process in psutil.process_iter(["pid", "name", "exe"]):
        if emulator_name in process.info["name"]:
            return os.path.dirname(process.info["exe"])
    return None


# ADB Default Port of Nox Emulator : 62001,62025,62026, MuMu Player: 16384
def connect_to_vm_adb(ip, port_list):
    retry = 3
    while retry > 0:
        for port in port_list:
            port = port + (3 - retry)
            try:
                adb_command = f'"{adb_path}" connect {ip}:{port}'
                result = subprocess.run(
                    adb_command,
                    shell=True,
                    text=True,
                    capture_output=True,
                    encoding="utf-8",
                    errors="ignore",
                ).stdout.strip()
                if "connected to" in result:
                    return True
            except Exception as e:
                print(f"Error: {str(e)}")
            continue
        retry -= 1
    print("\033[91mAndroid Emulator is not running.\033[0m")


def check_url_accessibility(url):
    try:
        response = requests.get(url)
        status_code = response.status_code
        if status_code == 200:
            return True
        else:
            return False
    except requests.RequestException as e:
        print(
            f"Error: Unable to download the certificate from the specified URL: {url}."
        )
        print(e)
        input("Burp Suite open for cert install step? Press Enter to continue...")
        return True


def burpsuite_cacert():
    cert_url = "http://127.0.0.1:8080/cert"
    input_der_file = "cacert.der"
    output_pem_file = "9a5ba575.0"

    try:
        if not check_url_accessibility(cert_url):
            print(
                f"Error: Unable to download the certificate from the specified URL: {cert_url}."
            )
            print("")

        response = requests.get(cert_url)

        if response.status_code == 200:
            with open(input_der_file, "wb") as certificate_file:
                certificate_file.write(response.content)
            print("Burp Suite certificate downloaded successfully.")

            with open(input_der_file, "rb") as der_file:
                der_data = der_file.read()
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_data)

            with open(output_pem_file, "wb") as pem_file:
                pem_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
                pem_file.write(pem_data)

            os.system(f'"{adb_path}" root')
            os.system(f'"{adb_path}" remount')
            os.system(
                f'"{adb_path}" push {output_pem_file} /system/etc/security/cacerts/'
            )
            os.system(
                f'"{adb_path}" shell chmod 644 "/system/etc/security/cacerts/{output_pem_file}"'
            )
            print(
                "\x1b[1;32mBurpSuite Certificate Install Successfully in Android Emulator\x1b[0m"
            )
            for file_path in [input_der_file, output_pem_file]:
                file_to_rem = pathlib.Path(file_path)
                file_to_rem.unlink()
            print("")

        else:
            print(
                f"Error: Unable to download the certificate from the specified URL: {cert_url}."
            )

    except ConnectionError:
        print(
            "Error: Burp Suite is not running or the proxy server is not on 127.0.0.1:8080."
        )
        print("")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")


def open_adb_shell_from_vm():
    if vm_installation_path:
        # adb_shell_command = f'"{adb_path}" shell -t su'
        adb_shell_command = f'"{adb_path}" shell'
        print(
            "\x1b[1;32mOpening ADB Shell. Type 'exit' to return to the main menu.\x1b[0m"
        )
        subprocess.run(adb_shell_command, shell=True)
    else:
        print("\033[91mAndroid Emulator not installed.\033[0m")


def frida_server_install():
    print(
        "Checking Installed Frida-Tools Version, please ensure your network connection to download the frida-server from GitHub."
    )
    frida_version_output = subprocess.check_output(
        "frida --version 2>&1", shell=True, stderr=subprocess.STDOUT, text=True
    )
    if re.search(r"(\d+\.\d+\.\d+)", frida_version_output):
        frida_version = re.search(r"(\d+\.\d+\.\d+)", frida_version_output).group(1)
        print(f"Frida-Tools Version: {frida_version}")

        emulator_arch = f'"{adb_path}" shell getprop ro.product.cpu.abi'
        emulator_archre = subprocess.run(
            emulator_arch, shell=True, text=True, check=True, capture_output=True
        )
        emulator_arch_result = emulator_archre.stdout.strip()
        print(f"CPU Architecture of Android Emulator: {emulator_arch_result}")

        print("Downloading Frida-Server With Same Version")
        frida_server_url = f"https://github.com/frida/frida/releases/download/{frida_version}/frida-server-{frida_version}-android-{emulator_arch_result}.xz"

        downloadfridaserver = f'"{adb_path}" shell curl -s -L {frida_server_url} -o /data/local/tmp/FridaServer.xz'
        os.system(downloadfridaserver)
        print("Frida Server downloaded successfully.")

        z7zzsbinurl = (
            f"https://aggressiveuser.github.io/food/7zzs-{emulator_arch_result}"
        )
        download7zzsbinary = (
            f'"{adb_path}" shell curl -s -L {z7zzsbinurl} -o /data/local/tmp/7zzs'
        )
        os.system(download7zzsbinary)
        chmod7zzs = f'"{adb_path}" shell chmod +x /data/local/tmp/7zzs'
        os.system(chmod7zzs)

        unzipfridaserver = f'"{adb_path}" shell /data/local/tmp/7zzs x /data/local/tmp/FridaServer.xz -o/data/local/tmp/ -bsp1 -bso0'
        os.system(unzipfridaserver)
        print("Frida Server Unziped to Android Emulator successfully.")

        chmodfridaserver = f'"{adb_path}" shell chmod +x /data/local/tmp/FridaServer'
        os.system(chmodfridaserver)
        print("Provided executable permissions to Frida Server.")
        print("\x1b[1;32mFrida Server setup completely on Android Emulator.\x1b[0m")
        print()
    else:
        print("\033[91mFrida Tools is not installed on this system.\033[0m")


def run_frida_server_new_powershell():
    print(adb_connected)
    if adb_connected:
        runfridaserver = f'"{adb_path}" shell "/data/local/tmp/FridaServer" &'
        subprocess.Popen(runfridaserver)
        print("\x1b[1;32mFrida Server is running...\x1b[0m")
        print("Below Some Usefull command of Frida-Tools")
        print("List installed applications: \033[38;5;208mfrida-ps -Uai\033[0m")
        print(
            "Frida Script Injection: \033[38;5;208mfrida -U -l fridascript.js -f com.package.name\033[0m"
        )
    else:
        print("Frida server not started on the Android Emulator.")


def kill_frida_server():
    if adb_connected:
        kill_frida_server_cmd = f'"{adb_path}" shell pkill FridaServer'
        subprocess.run(
            kill_frida_server_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print("\x1b[1;32mFrida Server is killed.\x1b[0m")
        return True
    else:
        print("Frida server not started")
        return False


def remove_ads_and_bloatware():
    print("Removing Bloatware and Ads from Android Emulator...")
    debloatroot = f'"{adb_path}" root'
    os.system(debloatroot)
    debloatremount = f'"{adb_path}" remount'
    os.system(debloatremount)
    fuckads = "rm -rf /system/app/AmazeFileManager /system/app/AppStore /system/app/CtsShimPrebuilt /system/app/EasterEgg /system/app/Facebook /system/app/Helper /system/app/LiveWallpapersPicker /system/app/PrintRecommendationService /system/app/PrintSpooler /system/app/WallpaperBackup /system/app/newAppNameEn"
    debloatrun = f'"{adb_path}" shell {fuckads}'
    try:
        os.system(debloatrun)
    except Exception as e:
        print("Error: ", debloatrun, "\n", e)
    finally:
        pass

    print("Installing File Manager...")
    filemanagerget = f'"{adb_path}" shell curl -s -L https://aggressiveuser.github.io/food/fmanager.apk -o /data/local/tmp/fmanager.apk'
    InstallManager = f'"{adb_path}" shell pm install /data/local/tmp/fmanager.apk'
    try:
        os.system(filemanagerget)
        os.system(InstallManager)
    except Exception as e:
        print("Error: ", filemanagerget, "\n", e)
    finally:
        pass
    print("Installing Rootless Launcher...")
    launcherget = f'"{adb_path}" shell curl -s -L https://aggressiveuser.github.io/food/rootless.apk -o /data/local/tmp/rootless.apk'
    InstallLauncher = f'"{adb_path}" shell pm install /data/local/tmp/rootless.apk'
    try:
        os.system(launcherget)
        os.system(InstallLauncher)
    except Exception as e:
        print("Error: ", filemanagerget, "\n", e)
    finally:
        pass
    print("Rebooting the Android Emulator...")
    print(
        "\033[38;5;208mAfert Successfull Reboot, Select Rootless Launcher for Always.\033[0m"
    )
    emulator_reboot = f"\"{vm_installation_path}\\{adb_bin}\" shell su -c 'setprop ctl.restart zygote'"
    try:
        os.system(emulator_reboot)
    except Exception as e:
        print("Error: ", emulator_reboot, "\n", e)
    finally:
        pass
    print("")


def display_options():
    print("")
    print("\033[93mChoose an option:\033[0m")
    print("1. Windows Tools")
    print("2. Android Emulator Options")
    print("3. Fida-Tools Options")
    print("0. Exit")
    print(
        "\033[91mNote: Choose Frida-Tools Option, When Frida-Server is up in your Device/Emulator.\033[0m"
    )
    print("")


def display_windows_tools_options():
    print("")
    print("\033[93mChoose a window tool:\033[0m")
    print("1. Frida")
    print("2. Objection")
    print("3. reFlutter")
    print("4. Back")
    print("")


def display_vm_options():
    print("")
    print("\033[93mAndroid Emulator options:\033[0m")
    print("1. Remove Ads From Android emulator")
    print("2. Install Frida Server")
    print("3. Run Frida Server")
    print("4. Kill Frida Server")
    print("5. ADB Shell from Emulator")
    print("6. Install Burpsuite Certificate")
    print("0. Back")
    print(
        '\033[91mNote: Choose "Run Frida Server" option, When Frida-Server is installed by Android Emulator.\033[0m'
    )
    print("")


def emulator_init_options():
    print("")
    print("\033[93mChoose an emulator:\033[0m")
    print("1. Nox Player 夜神模擬器")
    print("2. MuMu Player MuMu 模拟器")
    print("3. LDPlayer 雷电模拟器(TODO)")
    print("4. Other 其他(TODO)")
    print("0. Exit")
    print(
        "\033[91mNote: Launch, Root, Enable Read&Write the emulator before next step.\033[0m"
    )
    print("")


def frida_tool_options():
    print("")
    print("\033[93mFrida-Tool Options:\033[0m")
    print("1. List installed applications")
    print("2. SSL Pinning Bypass")
    print("3. Root Check Bypass")
    print("4. SSL Pinning and Root Check Bypass")
    print("0. Back")
    print("\033[91mFrida Custom Script Injection:\033[0m")
    print("\x1b[1;32mfrida -U -l YourFridaScript.js -f com.package.name\033[0m")
    print("")


def run_frida_tool_option(Frida_Option):
    if Frida_Option == "1":
        print("Listing installed applications:")
        run_command = "frida-ps -Uai"
        os.system(run_command)
        print("")
    elif Frida_Option == "2":
        package_name = input(
            "\033[38;5;208mEnter the application package name: \033[0m"
        )
        run_command = f"frida -U -l ./Fripts/SSL-BYE.js -f {package_name}"
        os.system(run_command)
        print("")
    elif Frida_Option == "3":
        package_name = input(
            "\033[38;5;208mEnter the application package name: \033[0m"
        )
        run_command = f"frida -U -l ./Fripts/ROOTER.js -f {package_name}"
        os.system(run_command)
        print("")
    elif Frida_Option == "4":
        package_name = input(
            "\033[38;5;208mEnter the application package name: \033[0m"
        )
        run_command = f"frida -U -l ./Fripts/PintooR.js -f {package_name}"
        os.system(run_command)
        print("")
    else:
        print("\033[91mInvalid choice.\033[0m")


if __name__ == "__main__":
    emulator_init_options()
    vm_choice = input("\033[38;5;208mEnter your choice: \033[0m")
    if vm_choice == "1":
        # Nox Player 夜神模擬器
        adb_bin = "nox_adb.exe"
        emulator = "Nox.exe"
        adb_port_list = [62001, 62025, 62026]
        vm_installation_path = find_vm_installation_path(emulator)
        adb_path = pathlib.Path(vm_installation_path, adb_bin)
        print(adb_path, adb_port_list)
    elif vm_choice == "2":
        # MuMu Player MuMu 模拟器
        adb_bin = "adb.exe"
        emulator = "MuMuPlayer.exe"
        adb_port_list = [16384, 16416, 16448]
        vm_installation_path = find_vm_installation_path(emulator)
        adb_path = pathlib.Path(vm_installation_path, adb_bin)
        print(adb_path, adb_port_list)
    elif vm_choice == "3":
        # LDPlayer 雷电模拟器
        adb_bin = "adb.exe"
        emulator = "LDPlayer.exe"
        adb_port_list = []
        adb_path = pathlib.Path(vm_installation_path, adb_bin)
        print(adb_path, adb_port_list)
    elif vm_choice == "4":
        # Other 其他
        adb_bin = "adb.exe"
        emulator = "Other"
        adb_port_list = [5555]
        print(adb_path, adb_port_list)
    elif vm_choice == "0":
        print("\033[91mExiting...\033[0m")
        exit()
    else:
        print("\033[91mInvalid choice.\033[0m")
        exit()
    # exit()
    while True:
        display_options()
        choice = input("\033[38;5;208mEnter your choice: \033[0m")
        if choice == "1":
            # Windows Tools
            while True:
                display_windows_tools_options()
                tool_choice = input("\033[38;5;208mEnter your choice: \033[0m")
                if tool_choice == "1":
                    if is_tool_installed("frida"):
                        print("Frida is already installed.")
                    else:
                        install_tool("frida-tools==11.0.0")
                        print("Frida installed successfully.")
                elif tool_choice == "2":
                    if is_tool_installed("objection"):
                        print("Objection is already installed.")
                    else:
                        install_tool("objection")
                        print("Objection installed successfully.")
                elif tool_choice == "3":
                    if is_tool_installed("reFlutter"):
                        print("reFlutter is already installed.")
                    else:
                        install_tool("reFlutter")
                        print("reFlutter installed successfully.")
                elif tool_choice == "4":
                    break
                else:
                    print("\033[91mInvalid choice.\033[0m")

        elif choice == "2":
            if not adb_connected:
                adb_connected = connect_to_vm_adb(adb_addr, port_list=adb_port_list)
            while True:
                print("\x1b[1;32mADB Connected to Android.\x1b[0m")
                user_choice = ""
                display_vm_options()
                try:
                    user_choice = input("\033[38;5;208mEnter your choice: \033[0m")
                except Exception:
                    print("\033[91mNo input provided. Exiting...\033[0m")
                    exit()
                if user_choice == "0":
                    break
                elif user_choice == "6":
                    burpsuite_cacert()
                elif user_choice == "5":
                    open_adb_shell_from_vm()
                elif user_choice == "4":
                    kill_frida_server()
                elif user_choice == "3":
                    run_frida_server_new_powershell()
                elif user_choice == "2":
                    frida_server_install()
                elif user_choice == "1":
                    remove_ads_and_bloatware()
                else:
                    print("\033[91mInvalid choice.\033[0m")
            # else:
            #     print(
            #         "\033[91mAndroid Emulator is not running or not installed.\033[0m"
            #     )

        elif choice == "3":
            # Fida-Tools Options
            while True:
                frida_tool_options()
                frida_choice = input(
                    "\033[38;5;208mEnter your Frida tool choice: \033[0m"
                )
                if frida_choice == "0":
                    break
                run_frida_tool_option(frida_choice)

        elif choice == "0":
            print("\033[91mExiting...\033[0m")
            break

        else:
            print("\033[91mInvalid choice.\033[0m")
