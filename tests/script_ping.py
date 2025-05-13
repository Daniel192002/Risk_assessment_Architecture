import subprocess
import time

INTERVALO = 60

if __name__ == "__main__":
  while True:
    
    command = f"ping -6 -c 4 ff02::1%eth1"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output, _ = process.communicate()
    print("Primer Comando:")
    print (output)
    
    time.sleep(2)
    
    ips = ["192.168.1.4", "192.168.1.8"]
    
    for ip in ips:
      command = f"ping -c 4 {ip}"
      process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
      output, _ = process.communicate()
      print(f"Ping a {ip}:")
      print (output)
      time.sleep(2)


    time.sleep(INTERVALO)