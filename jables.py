#!/usr/bin/env python3

from cmd import Cmd
import os
from bluepy import btle
import shlex
import re
import sys
from configparser import ConfigParser
from tabulate import tabulate

__version__ = "0.0.1"
__banner__ = rf"""
   _       ____  _     _____     
  (_) __ _| __ )| |   | ____|___ 
  | |/ _` |  _ \| |   |  _| / __|
  | | (_| | |_) | |___| |___\__ \
  | |\__,_|____/|_____|_____|___/
 _/ /
|__/  v{__version__}
"""
__author__ = "ins1gn1a"
__tool__ =  "\x1b[91mjaBLEs\x1b[0m"


class ColPrint(object):

    PURPLE = '\x1b[95m'
    BLUE = '\x1b[1;94m'
    GREEN = '\x1b[92m'
    YELLOW = '\x1b[93m'
    RED = '\x1b[91m'
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


class JablesUI(Cmd):

    __hiden_methods = ('do_EOF', 'do_cls', 'do_exit', 'do_quit')

    pp = ColPrint()

    # Config file parser
    parser = ConfigParser()
    try:
        parser.read('jables.conf')
        _interface = parser.get('interface', 'int')
    except:
        parser.add_section('interface')
        parser['interface']['int'] ='0'
        parser['interface']['type'] = "public"
        parser.write(open('jables.conf', 'w'))
        _interface = parser.get('interface', 'int')

    # Placeholders
    _target = "" # Can be set to statically set target upon each run
    _devices = ""
    _disc_devices = []
    _targetcompletions = []
    _characteristics = []

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
            _timeout = 5

        # Start scanner
        scanner = btle.Scanner(self._interface)
        try:
            self._devices = scanner.scan(timeout=_timeout)
        except:
            print(f"Error: Can't connect to Bluetooth interface hci{self._interface}")

        print("")

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
        # print (tabulate(_rows,headers=_headerrow,tablefmt="simple"))


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
        elif self._target:
            print (f"Enumerating {self._target}")

        else:
            print ("No target set")
            return


        try:
            _device = btle.Peripheral(self._target, addrType=self._hci_type,iface=int(self._interface))
            _services = _device.getServices()
            handles = _device.getCharacteristics()
            _device.disconnect()
        except:
            print("Unable to connect")
            return

        self._characteristics = []

        try:
            _device.connect(self._target,iface=self._interface)
        except:
            pass

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
    > write 0x3 ThisIsaTest string

Note: tab complete will show available 'write' handles if 'enum' has been previous run.
"""
        if args:

            args = shlex.split(args)
            _writeValType = "hex"

            if len(args) > 2:
                if args[2] == "string" or args[2] == "s":
                    _writeValType = "string"
                else:
                    _writeValType = "hex"

            try:
                _device = btle.Peripheral(self._target,
                                          addrType=self._hci_type,
                                          iface=int(self._interface))
            except:
                print("Unable to connect")
                return

            _handle = int(args[0], 16)
            if self.match_hex(args[1]) and _writeValType != "string":
                _val = bytearray.fromhex(args[1])
            else:
                _hex = "".join("{:02x}".format(ord(c)) for c in args[1])
                _val = bytearray.fromhex(_hex)

            _device.writeCharacteristic(_handle,_val,withResponse=True)


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
                print("Unable to connect")
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
            print("")
            print (self._target)

        else:
            print("")
            print("Please enter a target Bluetooth address")


    def do_interface(self,args):
        """
Set the local Bluetooth interface (HCI) ID:

    > interface 1
    > interface 0
"""

        if args:
            self._interface = args.replace('hci', "")
            self.parser.set('interface', "int",args.replace('hci', ""))
            self.parser.write(open('jables.conf','w'))

        elif self._interface:
            print("")
            print (f"hci{self._interface}")

        else:
            print("")
            print("Please enter an interface: hciX or X")


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
            print("")
            print (f"{self._hci_type}")

        else:
            print("")
            print("Please enter an interface type: public or random")


    # Handle empty arugment when Enter is pressed (doesn't repeat previous cmd)
    def emptyline(self):
        pass


    # Clears screen
    def do_cls(self, args):
        os.system('cls' if os.name == 'nt' else 'clear')


    # Clears screen
    def do_clear(self, args):
        """\n    Info\n    ----\n    Clears the screen content"""
        os.system('cls' if os.name == 'nt' else 'clear')


    # Handle Ctrl+C
    def do_EOF(self, args):
        # self.do_exit(None)
        self.context = {"exit": False}
        return True


    # Exit program
    def do_exit(self, args):
        """\n    Info\n    ----\n    Exit the program"""

        print("[!] Quitting.")
        raise SystemExit


    # Hide unwanted arguments
    def get_names(self):
        return [n for n in dir(self.__class__) if n not in self.__hiden_methods]



if __name__ == '__main__':

    os.system('cls' if os.name == 'nt' else 'clear')
    print(__banner__)

    if (os.geteuid() != 0):
        print("\nError: Re-run with Sudo\n")
        sys.exit(1)
    prompt = JablesUI()
    prompt.prompt = f"\n{__tool__} > "
    while True:
        try:
            prompt.cmdloop('')
        except KeyboardInterrupt:
            print("Use 'quit', 'exit', or Ctrl-D to exit")
            pass
