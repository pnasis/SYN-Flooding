# SYN Flooding
**Disclaimer!** \
This SYN Flooding program is shared for educational and research purposes only. The author Prodromos Nasis does not encourage or condone any unethical or illegal activities using this software. Any individual who chooses to use this program is solely responsible for their actions. The author shall not be held liable for any misuse of this software for unauthorized purposes, including but not limited to network intrusion, unauthorized access, or any other malicious activities.

By downloading, copying, or using this software, you agree that you will use it in compliance with all applicable laws, and you assume full responsibility for any consequences that may arise from its use.

This software is provided "as is," without any warranties or guarantees of any kind, either expressed or implied. The author makes no guarantees regarding the functionality, reliability, or suitability of this software for any purpose.

Users are advised to use this software in a lawful and ethical manner and to respect the privacy and rights of others.

**Please use this software responsibly and only in authorized and legal environments!**

## Description
A SYN flooding attack is a type of network-based attack that targets the TCP (Transmission Control Protocol) handshake process. In a typical TCP handshake, a client sends a SYN (synchronize) packet to initiate a connection, and the server responds with a SYN-ACK (synchronize-acknowledge) packet. The client then sends an ACK (acknowledge) packet to complete the handshake and establish a connection.

In a SYN flooding attack, the attacker sends a large number of SYN packets to a target server, but intentionally fails to complete the handshake by sending the final ACK. This causes the server to allocate resources and maintain half-open connections for each incoming SYN packet. Eventually, the server's resources are exhausted, leading to a Denial of Service (DoS) as legitimate connection requests cannot be accommodated.

***This program sends SYN packets to the specified destination (IP and port), with randomized source IP address and port!***

## Usage

```Bash
# To compile the program
gcc -Wall -o flood flood.c

# To run the program
sudo ./flood <interface> -d <destination_ip> -p <destination_port>
```

## Contributing

>Pull requests are welcome. **For major changes, please open an issue first
to discuss what you would like to change.**


## License

>This project is under [Apache 2.0](https://choosealicense.com/licenses/apache-2.0/) licence.
