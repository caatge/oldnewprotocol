import subprocess,sys,os

lib = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Preview\\VC\\Tools\\MSVC\\14.40.33521\\bin\\Hostx64\\x86\\lib.exe"

def main():
    
    for i in os.listdir("./_linker_defs"):
        if not i.endswith(".def"):
            continue
        nodef = i[:-4]
        print(subprocess.check_output([lib, "/machine:x86", f"/out:./lib/{nodef}.lib", f"/def:./_linker_defs/{i}", f"/name:{nodef}.dll"]).decode())
        
    input()
main()