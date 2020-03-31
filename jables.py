#!/usr/bin/env python3
import glob
from cmd import Cmd
import os
from bluepy import btle
import shlex
import re
import sys
from configparser import ConfigParser
from tabulate import tabulate
from scapy.layers.bluetooth4LE import BTLE_ADV_IND, BTLE_DATA
from scapy.layers.bluetooth import *
from scapy.utils import PcapReader

__author__  = "ins1gn1a"
__tool__    =  "jaBLEs"
__version__ = "1.4.2"
__banner__  = rf"""
   _       ____  _     _____     
  (_) __ _| __ )| |   | ____|___ 
  | |/ _` |  _ \| |   |  _| / __|
  | | (_| | |_) | |___| |___\__ \
  | |\__,_|____/|_____|_____|___/
 _/ /
|__/  v{__version__}
"""



class ColPrint(object):

    PURPLE = '\x1b[95m'
    BLUE = '\x1b[1;94m'
    GREEN = '\x1b[92m'
    YELLOW = '\x1b[93m'
    RED = '\x1b[91m'
    RESET = '\x1b[32m'
    WHITE = ''
    NO_FORMAT = '\x1b[0m'


    def red(self,string):
        return self.RED + string + self.NO_FORMAT

    def yellow(self,string):
        return self.YELLOW + string + self.NO_FORMAT

    def green(self,string):
        return self.GREEN + string + self.NO_FORMAT

    def purple(self,string):
        return self.PURPLE + string + self.NO_FORMAT

    def blue(self,string):
        return self.BLUE + string + self.NO_FORMAT

    def info(self,string):
        print (self.BLUE + "[i] " + self.NO_FORMAT + string)

    def error(self,string):
        print (self.RED + "[!] " + self.NO_FORMAT + string)

    def warn(self,string):
        print (self.YELLOW + "[?] " + self.NO_FORMAT + string)

    def ok(self,string):
        print (self.GREEN + "[+] " + self.NO_FORMAT + string)


class JablesUI(Cmd):

    __hiden_methods = ('do_EOF', 'do_cls', 'do_exit', 'do_quit')

    pp = ColPrint()

    # Config file parser
    parser = ConfigParser()
    try:
        parser.read('jables.conf')
        _interface = parser.get('interface', 'int')
    except: # Create new config file if cannot be found
        parser.add_section('interface')
        parser['interface']['int'] = '0'
        parser['interface']['type'] = "public"
        parser.write(open('jables.conf', 'w'))
        _interface = parser.get('interface', 'int')

    # Placeholders
    _target = "" # Can be set to statically set target upon each run
    _devices = ""
    _disc_devices = []
    _targetcompletions = []
    _characteristics = []
    _block_data = []
    FIFO = '/tmp/pipe'
    _decode_pcap_fifo = False

    # Set interface type (Public / Random)
    _hci_type_conf = parser.get('interface', 'type')

    if _hci_type_conf.lower() == "public":
        _hci_type = btle.ADDR_TYPE_PUBLIC
    elif _hci_type_conf.lower() == "random":
        _hci_type = btle.ADDR_TYPE_RANDOM
    else:
        _hci_type = btle.ADDR_TYPE_PUBLIC
        parser.set('interface', "type", "public")
        parser.write(open('jables.conf', 'w'))


    # Basic Regex matcher for HEX format
    def match_hex(self,args):
        if re.match("^[0-9a-fA-F]+$", args):
            return True
        else:
            return False


    def complete_view(self, text, line, begidx, endidx):
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in self._targetcompletions if s.startswith(mline.lower())]


    def complete_enum(self, text, line, begidx, endidx):
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in self._targetcompletions if s.startswith(mline.lower())]


    def complete_target(self, text, line, begidx, endidx):
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in self._targetcompletions if s.startswith(mline.lower())]


    def complete_write(self, text, line, begidx, endidx):
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[2][offs:] for s in self._characteristics if s[0].lower() == self._target and s[2].lower().startswith(mline.lower())  and "write" in s[3].lower()]


    def complete_read(self, text, line, begidx, endidx):
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[2][offs:] for s in self._characteristics if s[0].lower() == self._target and s[2].lower().startswith(mline.lower()) and "read" in s[3].lower()]


    def handler(self,signum, frame):
        pass


    def do_options(self,args):
        """
Display the current option values.
"""
        print ("")
        table = [["Target", self._target],
                 ["Devices Discovered", len(self._disc_devices)],
                 ["Interface", "hci" + self._interface],
                 ["Interface Type",self._hci_type_conf]]
        headers = ["Option", "Value"]
        print(tabulate(table, headers, tablefmt="simple"))


    def do_scan(self,args):
        """
Perform a BLE scan for devices within range. Optional argument is a timeout for scan time:

    > scan
    > scan 3
    > scan 20
"""
        if not self._interface:
            return

        # Set scanner timeout - default 5 seconds
        if args:
            _timeout = int(args)
        else:
            _timeout = 2

        # Start scanner
        self.pp.info("Starting BLE scan...")
        scanner = btle.Scanner(self._interface)
        try:
            self._devices = scanner.scan(timeout=_timeout)
        except:
            self.pp.error(f"Error: Can't connect to Bluetooth interface hci{self._interface}")
            return

        self.pp.ok("Scan complete!")
        self.pp.info(f"Identifying device names for {str(len(self._devices))} devices..")

        _headerrow = ['Bluetooth Address', 'Device Name', 'RSSI', 'Connectable', 'Address Type']

        self._targetcompletions = []
        _rows = []
        self._disc_devices = []

        for x in self._devices:
            _address = x.addr
            _rssi = x.rssi
            if _rssi > -50:
                _rssi = self.pp.green(str(_rssi))
            elif _rssi <= -50 and _rssi > -65:
                _rssi = self.pp.yellow(str(_rssi))
            else:
                _rssi = self.pp.red(str(_rssi))

            _type = x.addrType

            if x.connectable == 1 or x.connectable == "1":
                _connect = True

                _connect_str = self.pp.green("True")
            else:
                _connect = False
                _connect_str = self.pp.red("False")

            # Attempt to read Device Name
            if _connect and _type.lower().strip() == "public":

                try:
                    _device = btle.Peripheral(_address,addrType=self._hci_type, iface=int(self._interface))
                    _device_name = _device.readCharacteristic(0x3).decode("utf-8")
                    _device.disconnect()
                except:
                    _device_name = ""
            else:
                _device_name = ""

            _row = [_address,_device_name,_rssi,_connect_str,_type]
            self._targetcompletions.append(_address)
            _rows.append(_row)
            self._disc_devices.append(_row)
        self.displayDevices("")


    def do_enum(self,args):
        """
Run a characteristic/handle enumeration scan against a specified device. If 'target' has been set this can be run without additional arguments.

    > enum
    > enum 00:11:22:33:44:55

Note: tab complete will show previously discovered bluetooth addresses if 'scan' has been run.
"""

        if not self._interface:
            return

        if args:
            self._target = args
            self.pp.info(f"Enumerating {self._target}...")
        elif self._target:
            self.pp.info(f"Enumerating {self._target}...")

        else:
            self.pp.warn("No target set!")
            return


        try:
            _device = btle.Peripheral(self._target, addrType=self._hci_type,iface=int(self._interface))
            _services = _device.getServices()
            handles = _device.getCharacteristics()
            _device.disconnect()
        except:
            self.pp.error("Error: Unable to connect")
            return

        self.pp.ok(f"Enumerated {self._target} with {str(len(handles))} characteristics")

        self._characteristics = []

        # try:
        #     _device.connect(self._target,iface=self._interface)
        # except:
        #     pass

        if handles:
            self._targetcompletions.append(self._target)
            for x in handles:
                _char_props = x.propertiesToString()
                self._characteristics.append(
                                            [self._target,
                                            str(x.uuid),
                                            str(hex(x.getHandle())),
                                            _char_props]
                                            )

            self.displayResults(args)


    def displayDevices(self,args):
        print("")

        # Format header row
        _headerrow = ['Bluetooth Address', 'Device Name', 'RSSI', 'Connectable', 'Address Type']

        _rows = []
        # Display characteristic data
        for row in self._disc_devices:
            if args:
                # Only display filtered results if bdaddr provided
                if args.lower() != row[0].lower():
                    continue
            _rows.append(row)
        print(tabulate(_rows, headers=_headerrow,tablefmt="simple"))

    def displayResults(self,args):
        print("")

        # Format header row
        _headerrow = ['Bluetooth Addr', 'UUID', 'Handle', 'Properties']

        _rows = []
        # Display characteristic data
        for row in self._characteristics:
            if args:
                # Only display filtered results if bdaddr provided
                if args.lower() != row[0].lower():
                    continue
            _rows.append(row)
        print(tabulate(_rows, headers=_headerrow,tablefmt="simple"))


    def do_view(self,args):
        """
Display previously discovered devices and services. Specify a BDAddr as an argument to filter on that device:

    > view
    > view 00:11:22:33:44:55

Note: tab complete will show previously discovered bluetooth addresses if 'scan' has been run.
"""
        if self._disc_devices:
            self.displayDevices(args)
        if self._characteristics:
            self.displayResults(args)


    def do_write(self,args):
        """
Interact with a target device and write to available service handles.

Write values must be written as a non-delimited hex format, or if the 'string' parameter is used as the third argument, this will be auto-converted:

    > write 0x3 5468697349736154657374
    > write 0x3 'ThisIsaTest' string

Note: tab complete will show available 'write' handles if 'enum' has been previous run.
"""
        if args:
            self.pp.info("Connecting...")
            try:
                _device = btle.Peripheral(self._target,
                                          addrType=self._hci_type,
                                          iface=int(self._interface))
            except:
                self.pp.error("Error: Unable to connect")
                return

            self.pp.ok(f"Connected to {self._target}")
            self.pp.info(f"Sending write cmd: {args}")
            self.write(args,_device)
            self.pp.ok("Commands sent")


    def write(self,args,_device):
        args = shlex.split(args)
        _writeValType = "hex"

        if len(args) > 2:
            if args[2] == "string" or args[2] == "s":
                _writeValType = "string"
            else:
                _writeValType = "hex"

        _handle = int(args[0], 16)
        if self.match_hex(args[1]) and _writeValType != "string":
            _val = bytearray.fromhex(args[1])
        else:
            _hex = "".join("{:02x}".format(ord(c)) for c in args[1])
            _val = bytearray.fromhex(_hex)

        try:
            _device.writeCharacteristic(_handle, _val, False)
        except:
            self.pp.error("Error: Unable to connect")


    def do_writeblk(self,args):
        """
Enter multiple 'write' commands as 'Handle Data':

    > write
    > 0x1e 5468697349736154657374
    > 0x09 5468697349736154657374
    > 0xa3 5468697349736154657374
    > end

Note: If you suffix the command with 'string' this will be converted to a hex string:

    > write
    > 0x1e 5468697349736154657374
    > 0x09 'ThisIsATest' string
    > 0xa3 5468697349736154657374
    > end

Alternatively, if you've already run a block previously, you can re-run this by sending the 'x' argument:

    > write x
"""
        if args == "x":
           self.pp.info("Sending previous block of write commands...")
        else:
            self._block_data = []
            _block_input = ""
            self.pp.info("Enter one command per line as 'handle data' and then 'end' to finish. E.g: 0x1e 305721e4a290 ")
            while True:
                _block_input = input()
                if _block_input.lower() != "end":
                    self._block_data.append(_block_input)
                else:
                    self.pp.info("Write command input finished!")
                    break

        if self._block_data:
            self.pp.info("Connecting...")

            try:
                _device = btle.Peripheral(self._target,
                                          addrType=self._hci_type,
                                          iface=int(self._interface))
            except:
                self.pp.error("Error: Unable to connect")
                return

            self.pp.ok(f"Connected to {self._target}")

            for x in self._block_data:
                self.pp.info(f"Sending write cmd: {x}")
                self.write(x,_device)
            self.pp.ok("Commands sent")

        else:
            self.pp.warn("No write commands specified")


    def do_read(self,args):
        """
Interact with a target device and read from the available service handles:

    > read 0x3
    > read 0x1a

Note: tab complete will show available 'read' handles if 'enum' has been previous run.
"""
        if args:
            args = shlex.split(args)

            try:
                _device = btle.Peripheral(self._target,
                                          addrType=self._hci_type,
                                          iface=int(self._interface))
            except:
                self.pp.error("Error: Unable to connect")
                return

            _handle = int(args[0], 16)

            _response = _device.readCharacteristic(_handle)
            try:
                print(_response.decode("utf-8"))
            except:
                print(_response)


    def do_target(self,args):
        """
Set a static Target for use with enum, write, and read commands:

    > target 00:11:22:33:44:55
"""
        if args:
            self._target = args

        elif self._target:
            self.pp.info ("Current Target: " + self._target)

        else:
            self.pp.warn("Please enter a target Bluetooth address")

    def is_ascii(self,s):
        return all(ord(c) < 128 for c in s)


    def decode_text(self,data,hex):

        if len(data) == 0:
            return
        else:
            pass


        for x in data:
            a = (x.strip().replace("LL Data: ", "").replace(" ", ""))
            try:
                ba = bytearray.fromhex(a)
            except:
                return

            if hex:
                self.pp.ok(self.pcap_match_colour(str(ba)[12:-2]))
                pass

            else:
                z = []
                if re.match('^[0-9a-fA-F]+$', a):

                    for b in ba:
                        _content = False
                        c = (chr(b))
                        if re.match('^[a-zA-Z0-9&£#$%^?!+\'\"\\\/| _=\-,.*\[\]{}()@]+$', c):
                            if self.is_ascii(c):
                                z.append(c)
                                _content = True
                            else:
                                z.append("_")

                    # if hex:
                    #     print("")
                    #     self.pp.info(f"Raw Hex: {a}")
                    self.pp.ok("".join(z))

    def make_pipe(self):
        os.mkfifo(self.FIFO,mode=0o666)
        os.chmod(self.FIFO,mode=0o666)

    def destroy_pipe(self):
        os.unlink(self.FIFO)

    def _append_slash_if_dir(p):
        if p and os.path.isdir(p) and p[-1] != os.sep:
            return p + os.sep
        else:
            return p

    def complete_decode_pcap(self, text, line, begidx, endidx):
        """ File path autocompletion, used with the cmd module complete_* series functions"""
        before_arg = line.rfind(" ", 0, begidx)

        if before_arg == -1:
            return  # arg not found

        fixed = line[before_arg + 1:begidx]  # fixed portion of the arg
        arg = line.split(" ", 1)[1]  # line[before_arg + 1:endidx]
        pattern = arg.strip() + '*'

        completions = []
        for path in glob.glob(pattern):
            if path[-5:].lower() == ".pcap" or os.path.isdir(path):
                completions.append(path.replace(fixed, "", 1))
        return completions


    def pcap_match_colour(self,txt):

        lastMatch = 0
        formattedText = ''
        txt = self.pp.green(txt)

        for match in re.finditer(r'\\x[0-9a-zA-Z]{2}|(\\r)|(\\n)|(\\t)', txt):
            start, end = match.span()
            formattedText += txt[lastMatch: start]
            formattedText += self.pp.PURPLE
            formattedText += txt[start: end]
            formattedText += self.pp.RESET
            lastMatch = end
        formattedText += txt[lastMatch:]
        return formattedText


    def parse_pcap(self,pkt):

        _only_data = True

        if pkt.haslayer(BTLE_ADV_IND):
            return

        if pkt.haslayer(ATT_Read_Request):
            gatt_r = pkt[ATT_Read_Request].gatt_handle
            gatt = self.pp.blue(f"0x{gatt_r:04x}")
            self.pp.info(f'Read-Req {gatt}')
            _only_data = False

        elif pkt.haslayer(ATT_Read_Response):
            value = self.pp.green(str(pkt[ATT_Read_Response].value)[2:-1])
            self.pp.ok(f'Read-Res {value}')
            _only_data = False

        elif pkt.haslayer(ATT_Write_Command):
            data = self.pcap_match_colour(str(pkt[ATT_Write_Command].data)[2:-1])
            # data = self.pcap_match_colour(str(pkt[ATT_Write_Command].value)[2:-1])
            gatt_r = pkt[ATT_Write_Command].gatt_handle
            gatt = self.pp.blue(f"0x{gatt_r:04x}")
            self.pp.ok(f'Write-Cmd {gatt}: {data}')
            _only_data = False

        elif pkt.haslayer(ATT_Write_Request):
            data = self.pp.green(str(pkt[ATT_Write_Request].data)[2:-1])
            # data = self.pp.green(str(pkt[ATT_Write_Request].value)[2:-1])
            gatt_r = pkt[ATT_Write_Request].gatt_handle
            gatt = self.pp.blue(f"0x{gatt_r:04x}")
            self.pp.ok(f'Write-Req {gatt}: {data}')
            _only_data = False

        # elif pkt.haslayer(ATT_Find_By_Type_Value_Response):
        #     print ()

        elif pkt.haslayer(BTLE_DATA) and self._decode_pcap_fifo:
            data = self.pcap_match_colour(str(pkt[BTLE_DATA])[2:-1])
            gatt_r = (pkt.gatt_handle)
            gatt = self.pp.blue(f"0x{gatt_r:04x}")
            self.pp.ok(f'          {gatt}: {data}')


        elif pkt.load:
            # print (pkt.show())
            data = self.pcap_match_colour(str(pkt.load)[2:-1])
            gatt_r = (pkt.gatt_handle)
            gatt = self.pp.blue(f"0x{gatt_r:04x}")
            self.pp.warn(f'          {gatt}: {data}')




    # ATT_Execute_Write_Request, ATT_Execute_Write_Response, ATT_Find_By_Type_Value_Request, ATT_Find_By_Type_Value_Response, ATT_Find_Information_Request, ATT_Find_Information_Response, ATT_Handle_Value_Indication, ATT_Handle_Value_Notification, ATT_Prepare_Write_Request, ATT_Prepare_Write_Response, ATT_Read_Blob_Request, ATT_Read_Blob_Response, ATT_Read_By_Group_Type_Request, ATT_Read_By_Group_Type_Response, ATT_Read_By_Type_Request_128bit, ATT_Read_By_Type_Request, ATT_Read_By_Type_Response, ATT_Read_Multiple_Request, ATT_Read_Multiple_Response, ATT_Read_Request, ATT_Read_Response, ATT_Write_Command, ATT_Write_Request, ATT_Write_Response


    def do_decode_pcap(self,args):
        """
Creates a FIFO pipe at /tmp/pipe by default. Stream an input PCAP format to parse the BTLE data:

    > decode_pcap

Specify a FIFO path:

    > decode_pcap /tmp/pipe1

Or use a static PCAP file as an input (this will also parse out the Write/Read commands and Handles:

    > decode_pcap /home/user/test.pcap

For PCAP format (especially when using FIFO with Btlejack) use the 'll_phdr' format within the tool itself. E.g.:

    > btlejack -c <BDADDRESS> -w /tmp/pipe -x ll_phdr
"""

        filename = self.FIFO
        fifo_scapy = False
        if args:
            filename = args
            if re.match('([/][\w\d]{1,})', args) and ".pcap" not in args:
                self.pp.info(f"Parsing PCAP via FIFO: {args}")
                filename = args
                self.FIFO = filename
                fifo_scapy = True

            elif ".pcap" in args:
                self.pp.info(f"Parsing PCAP as file: {args}")
                fifo_scapy = False
                filename = args

        if fifo_scapy or not args:

            self.pp.info(f"Creating FIFO Pipe: {self.FIFO}")
            try:
                self.make_pipe()
            except:
                try:
                    self.destroy_pipe()
                    self.make_pipe()
                except:
                    self.pp.error(f"Error: Unable to make pipe: {self.FIFO}")
                    return

            self.pp.info("FIFO opened")
            fifo = open(filename, "rb", buffering=0)
            self._decode_pcap_fifo = True
            while True:
                try:
                    for pkt in (PcapReader(fifo)):
                        try:
                            self.parse_pcap(pkt)
                        except:
                            continue
                except:
                    self.pp.info("Exited Decoder")
                    self.destroy_pipe()
                    return

        else:
            self._decode_pcap_fifo = False
            for pkt in PcapReader(filename):
                self.parse_pcap(pkt)



    def do_decode_text(self,args):
        """
Creates a FIFO pipe at /tmp/pipe by default. Stream an input of Hex content for auto-decoding such as an output of Btlejack:

    > decode_text

Specify a FIFO path:

    > decode_text /tmp/pipe1

Note: Add the -x (or --hex) arg to also print the raw Hex string alongside the decoded output.
"""

        _hex = False
        if args:

            args = shlex.split(args)
            for arg in args:
                if re.match('([/][\w\d]{1,})',arg):
                   self.FIFO = arg
                elif arg == "-x" or arg == "--hex":
                    _hex = True
                    self.pp.warn("Displaying raw byte output")

        # Create and open pipe

        self.pp.info(f"Creating FIFO Pipe: {self.FIFO}")
        try:
            self.make_pipe()
        except:
            try:
                self.destroy_pipe()
                self.make_pipe()
            except:
                self.pp.error(f"Error: Unable to make pipe: {self.FIFO}")
                return

        self.pp.info("FIFO opened")
        fifo = open(self.FIFO, 'r')
        while True:
            try:
                data = fifo.readline()[:-1]
                self.decode_text(data.splitlines(),_hex)
            except KeyboardInterrupt:
                self.pp.info("Exited Decoder")
                fifo.close()
                self.destroy_pipe()
                return


    def do_interface(self,args):
        """
Set the local Bluetooth interface (HCI) ID:

    > interface 1
    > interface 0
    > interface hci2
    > interface hci0
"""

        if args:
            self._interface = args.replace('hci', "")
            self.parser.set('interface', "int",args.replace('hci', ""))
            self.parser.write(open('jables.conf','w'))

        elif self._interface:

            self.pp.info (f"Current Interface: hci{self._interface}")

        else:

            self.pp.warn("Please enter an interface: hciX or X")


    def do_interface_type(self,args):
        """
Set the local Bluetooth interface type:

    > interface_type public
    > interface_type random
"""

        if args:
            self._hci_type = args.lower()
            if self._hci_type.lower() == "random":
                self._hci_type = btle.ADDR_TYPE_RANDOM
            else:
                 self._hci_type = btle.ADDR_TYPE_PUBLIC
            self.parser.set('interface', "type", self._hci_type)
            self.parser.write(open('jables.conf', 'w'))

        elif self._hci_type:
            self.pp.info (f"Current Interface Type: {self._hci_type}")

        else:
            self.pp.warn("Please enter an interface type: public or random")


    # Handle empty arugment when Enter is pressed (doesn't repeat previous cmd)
    def emptyline(self):
        pass


    # Clears screen
    def do_cls(self, args):
        """
Clears the screen content
"""
        os.system('cls' if os.name == 'nt' else 'clear')


    # Clears screen
    def do_clear(self, args):
        """
Clears the screen content
"""
        os.system('cls' if os.name == 'nt' else 'clear')


    def exit(self):
        try:
            os.unlink(self.FIFO)
        except:
            pass
        self.pp.info("Quitting")
        raise SystemExit

    # Handle Ctrl+C
    def do_EOF(self, args):
        """
Exits the program
"""
        print("exit")
        self.exit()


    # Exit program
    def do_exit(self, args):
        """
Exit the program
"""

        self.exit()


    # Hide unwanted arguments
    def get_names(self):
        return [n for n in dir(self.__class__) if n not in self.__hiden_methods]



if __name__ == '__main__':

    os.system('cls' if os.name == 'nt' else 'clear')
    print(__banner__)

    pp = ColPrint()

    if (os.geteuid() != 0):
        print ("")
        pp.error("Error: Re-run with Sudo\n")
        sys.exit(1)

    prompt = JablesUI()
    prompt.prompt = f"\n{pp.red(__tool__)} > "

    while True:
        try:
            prompt.cmdloop('')
        except KeyboardInterrupt:
            print("Use 'quit', 'exit', or Ctrl-D to exit")
            pass
