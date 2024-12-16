import pexpect
import time

# Define variables
ssh_ip_address = '192.168.56.101'
ssh_username = 'prne'
ssh_password = 'cisco123!'  # Login password
ssh_password_enable = 'class123!'  # Enable password
ssh_new_hostname = 'R1'

# Configuration commands
loopback_ip = "10.10.10.23"
loopback_mask = "255.255.255.255"
ospf_area = "0"

def configure_router():
    try:
        # Start SSH session
        print("[*] Starting SSH session...")
        session = pexpect.spawn(
            f'ssh -o "StrictHostKeyChecking=no" {ssh_username}@{ssh_ip_address}',
            encoding='utf-8',
            timeout=20
        )
        session.logfile = open("ssh_debug.log", "w")  # Enable detailed logging for debugging

        # Login to the router
        result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('[!] FAILURE: Unable to create SSH session.')
            return
        session.sendline(ssh_password)
        result = session.expect(['>', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('[!] FAILURE: Invalid login credentials.')
            return
        print("[+] Successfully logged in.")

        # Enter enable mode
        print("[*] Entering enable mode...")
        session.sendline('enable')
        result = session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('[!] FAILURE: Failed to enter enable mode.')
            return

        # Provide enable password
        session.sendline(ssh_password_enable)
        result = session.expect([r'.*#', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('[!] FAILURE: Invalid enable password or unexpected router response.')
            print(f'[DEBUG] Router response: {session.before.strip()}')
            return
        print("[+] Successfully entered enable mode.")

        # Enter global configuration mode
        print("[*] Entering global configuration mode...")
        session.sendline('configure terminal')
        result = session.expect([r'\(config\)#', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('[!] FAILURE: Could not enter config mode.')
            return
        print("[+] Successfully entered global configuration mode.")

        # Change hostname
        print(f"[*] Changing hostname to {ssh_new_hostname}...")
        session.sendline(f'hostname {ssh_new_hostname}')
        result = session.expect([rf'{ssh_new_hostname}\(config\)#', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('[!] FAILURE: Could not set hostname.')
            return
        print("[+] Hostname changed successfully.")

        # Configure loopback interface
        print("[*] Configuring loopback interface...")
        session.sendline('interface loopback 0')
        result = session.expect([rf'{ssh_new_hostname}\(config-if\)#', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('[!] FAILURE: Could not enter interface config.')
            return

        session.sendline(f'ip address {loopback_ip} {loopback_mask}')
        result = session.expect([rf'{ssh_new_hostname}\(config-if\)#', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('[!] FAILURE: Could not configure IP address.')
            return

        session.sendline('no shutdown')
        result = session.expect([rf'{ssh_new_hostname}\(config-if\)#', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('[!] FAILURE: Could not enable interface.')
            return

        session.sendline('exit')  # Exit interface mode
        session.expect([rf'{ssh_new_hostname}\(config\)#'])
        print("[+] Loopback interface configured successfully.")

        # Configure OSPF
        print("[*] Configuring OSPF...")
        session.sendline('router ospf 1')
        result = session.expect([rf'{ssh_new_hostname}\(config-router\)#', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('[!] FAILURE: Could not enter OSPF config mode.')
            return

        session.sendline(f'network {loopback_ip} 0.0.0.0 area {ospf_area}')
        result = session.expect([rf'{ssh_new_hostname}\(config-router\)#', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('[!] FAILURE: Could not configure OSPF network.')
            return

        session.sendline('exit')  # Exit OSPF mode
        session.expect([rf'{ssh_new_hostname}\(config\)#'])
        print("[+] OSPF configured successfully.")

        # Save configuration
        print("[*] Saving configuration...")
        session.sendline('write memory')
        result = session.expect([rf'{ssh_new_hostname}\(config\)#', pexpect.TIMEOUT, pexpect.EOF])
        if result != 0:
            print('[!] FAILURE: Could not save configuration.')
            return
        print("[+] Configuration saved successfully.")

        # Exit configuration mode
        session.sendline('exit')
        session.expect([rf'{ssh_new_hostname}#', pexpect.TIMEOUT, pexpect.EOF])

        # Wait for OSPF to propagate
        time.sleep(5)
        print("[*] Displaying OSPF configuration...")
        session.sendline('show ip ospf')

        # Display OSPF configuration
        ospf_output = ""
        while True:
            try:
                result = session.expect([r'--More--', rf'{ssh_new_hostname}#', pexpect.TIMEOUT, pexpect.EOF], timeout=30)
                ospf_output += session.before.strip()

                if result == 0:  # Pagination detected
                    session.send(" ")  # Send space to continue
                elif result == 1:  # Command completed
                    break
            except pexpect.TIMEOUT:
                print("[!] TIMEOUT: The command took too long to respond.")
                break
            except Exception as e:
                print(f"[!] ERROR: {e}")
                break

        print("[+] OSPF Configuration:")
        print(ospf_output)

        # Close session
        session.sendline('exit')
        session.close()
        print('[+] Configuration completed successfully.')

    except pexpect.exceptions.TIMEOUT:
        print('[!] TIMEOUT: Operation took too long.')
    except pexpect.exceptions.EOF:
        print('[!] EOF: SSH session unexpectedly closed.')
    except Exception as e:
        print(f'[!] ERROR: {e}')

if __name__ == '__main__':
    configure_router()
