Linux Tools
========================
This repo contains Linux tools that are useful to conduct scanning and enumeration.

Tools in this repository:

#### 1. ARP Spoofer
      
    - Sends gratuitous ARP responses to two machines to act as a man in the middle which can intercept the flow of data between the two targets.
    - Use wireshark to view the packets being transferred between the two targets.
#### 2. Network Scanner

    - Retrieves the MAC address/addresses of an IP address or range of IP addresses that are up on a subnet.
    
## Requirements
Kali Linux,
Python3

## Usage

#### 1. [ARP Spoofer](https://github.com/aryanbhave/LinuxTools/blob/master/arpspoofer.py)
    
   Run the code with the terminal command:
    ```
    # python3 arpspoofer -t1 <target1> -t2 <target2>
    ```
#### 2. [Network Scanner](https://github.com/aryanbhave/LinuxTools/blob/master/networkscanner.py)

   Run the code with the terminal command:
    ```
    # python3 networkscanner.py -t1 <targetIP>
    ```
    
   You can also use CIDR notation and scan a range of IP addresses. Simply input the CIDR notation in the <targetIP> field.
## End Goal
The end goal of this project is to build a user-friendly Linux framework that can run all the individual tools in this repository.
