# Linux Tools
Linux tools that are useful to conduct scanning and enumeration.

Tools in this repository:

1. ARP Spoofer(#1.-ARP-spoofer) 
      
      (File Name: arpspoofer.py)
    - Sends gratuitous ARP responses to two machines to act as a man in the middle which can intercept the flow of data between the two targets.
    - Use wireshark to view the packets being transferred between the two targets.
    
## Requirements
Kali Linux,
Python3

## Usage

#### 1. ARP Spoofer
    (File Name: arpspoofer.py)
    
    Run the code with the terminal command:
    ```
    # python3 arpspoofer -t1 <target1> -t2 <target2>
## End Goal
The end goal of this project is to build a user-friendly Linux framework that can run all the individual tools in this repository.
