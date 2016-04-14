# netMon

netMon is a tool developed in Python 2.7 that monitors the IPv4 addresses and ports that your Windows machine is connecting to.

####Demo
![netMon demo](https://github.com/CSSDePaul/NetMon/blob/master/img/demo.gif)

####Explanation

* **INBOUND Window:** Contains IPv4 addresses sending messages to your Windows machine and the port used on the receiving end (Local Port).
* **OUTBOUND Window:** Contains IPv4 addresses your Windows machine is sending messages to and the port used on the receiving end (Remote Port).
* **Format:** IP Address <Total Sent/Received Count>    Port <Sent/Received Count>    Port <Sent/Received Count>    Port <Sent/Received Count> . . .
* **Red Text:** Signifies a change.
* **Reset Button:** Clears both INBOUND/OUTBOUND windows.

####Quick Start

1. Execute netMon.exe as Administrator
2. Enter the IP address of your Windows machine
3. Click "Next"
4. Now start monitoring