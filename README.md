# How to run GREP
1. Compile the Key Manager (KM)
cd '/home/user/GREP Code'
g++ Shared.cpp KeyManager.cpp -o KeyManager-AES -lssl -lcrypto -fpermissive

Note: Check and modify the following variables if needed:
* CIPHMODE
* nodeIP which is determined in KM code in the following line:
char SnapRime[25 * 23] = "00:12:74:02:00:02:02:02" ...
* command for snapshot mode
char SnapCommand[25 * 2] = "JNJ0J0J0J0JNJ1J1J1J1JNJ2J2J2J2JNJ3J3J3J3JNJ4J4J4J4";

## For Cooja (Tmote Sky):
2. For Cooja, run Cooja from '/contiki/tools/cooja' directory
ant run
Note: In order to run KM, tunslip is required. So, at first run Basic.csc from Cooja. Basic.csc is Cooja simulation file that has only one node, a Border Router node that can be used to run tunslip connection.

3. Run tunslip from '/contiki/tools' directory. This step is required because tun0 connection is needed to run KM. Start simulation in Cooja by pressing Star button. Then run the following command:
tunslip6 -a 127.0.0.1 aaaa::1/64

4. Run the Key Manager (KM)
* Clean all previous node configuration files
rm -f *.ncfg
* Run KM
./KeyManager-AES
./KeyManager-SJ
* Press 's'

5. Compile and download GREP group member code from '/contiki/examples/grep' directory
* Download the code from github, or use GREP code in the image
* Check and modify all directories written in init.pl accordingly
* Clean all previously generated files
rm -f node-*
* Compile by executing the following command twice:
make TARGET=sky
Note: make sure conf directory is exist
* Load the GREP25Measurement.csc (may also create a new simulation)
Note: To verify and confirm the code used for the the nodes in the simulation, go to 'Motes -> Mote types...'.
* Press the Star button in Cooja

6. Run tunslip again
tunslip6 -a 127.0.0.1 aaaa::1/64

7. Start the measurement by starting simulation in Cooja. Save the log.

## For real node/device
2. Compile and download the Border Router code from '/contiki-master/examples/ipv6/rpl-border-router'
make TARGET=sky
make TARGET=cc2538dk
make TARGET=zoul BOARD=firefly
* Then execute the following command accordingly,
make border-router.upload TARGET=sky
make border-router.upload TARGET=cc2538dk
make border-router.upload TARGET=zoul BOARD=firefly
* Connect the Border Router to VM Image

3. Run tunslip from '/contiki-master/tools' directory. This step is required because tun0 connection is needed to run KM. Start the node by turning the power on. Then run the following command (assuming Border Router in is /dev/ttyUSB0):
tunslip6 -s /dev/ttyUSB0 aaaa::1/64

4. Run the Key Manager (KM)
* Clean all previous node configuration files
rm -f *.ncfg
* Run KM
./KeyManager-AES
./KeyManager-SJ
* Press 's'

5. Compile and download GREP group member code to Tmote Sky/SmartRF/Firefly board from '/contiki-master/examples/grep' directory
* Download the code from github, or use GREP code in the image
* Check and modify all directories written in init.pl accordingly
* Clean all previously generated files
rm -f node-*
* Compile by executing the following command twice:
make TARGET=sky
make TARGET=cc2538dk
make TARGET=zoul BOARD=firefly
Note: make sure conf directory is exist
* Download the binary file to the board 
make node-1.upload TARGET=sky
make node-1.upload TARGET=cc2538dk
make node-1.upload TARGET=zoul BOARD=firefly

6. Run tunslip again
tunslip6 -s /dev/ttyUSB0 aaaa::1/64

7. Start the measurement by dumping the real node output to the terminal (e.g. by using Screen or Picocom command)
picocom -b 115200 -r -l /dev/ttyUSB0 --imap lfcrlf | tee borderrouter.txt

# Configuration:
1. Config files:
* General: contiki-conf.h in /core
* For specific board, the config file can be found under /platform
E.g. contiki-default-conf.h in /platform/sky
2. CIPHMODE is the flag used to specify the cipher to be used (AES Software or SJ or AES Hardware). CIPHMODE can be found in contiki-default-conf.h and the code (GREP, Border Router)
/examples/grep/contiki-default-conf.h:#undef CIPHMODE
/examples/grep/contiki-default-conf.h:#define CIPHMODE		1 	//AES = 0, SkipJack = 1, Default HW Cipher = 2
3. In order to enable Energest, check ENERGEST_CONF_ON and ENERG_EN preprocessors in config files and code.
Example:
#define ENERGEST_CONF_ON 1
#define ENERG_EN		0 	// 0 or 1
