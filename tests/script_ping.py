import subprocess
import time

INTERVALO = 60

if __name__ == "__main__":
  while True:
    
    command = f"ping6 -c 4 fe80::1%eth1"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output, _ = process.communicate()
    print("Primer Comando:")
    print (output)
    
    time.sleep(5)
    
    command = f"ping -c 4 192.168.0.4"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output, _ = process.communicate()
    print("Segundo comando:")
    print (output)

    time.sleep(INTERVALO)