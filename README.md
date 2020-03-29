# jaBLEs
**J**ust **A**nother **B**luetooth **L**ow **E**nergy **S**canner

## Usage
Some examples of basic usage are below.

### View Help
```
jaBLEs > help

Documented commands (type help <topic>):
========================================
clear  help       interface_type  read  target  write
enum   interface  options         scan  view
```

### Set Bluetooth Interface
```
jaBLEs > interface 1

jaBLEs > interface

hci1
```

```
jaBLEs > interface hci0

jaBLEs > interface

hci0

```

### Set Bluetooth Interface Type
```
jaBLEs > interface_type

public

jaBLEs > interface_type random
```

### Scanning
```
jaBLEs > scan 3


Bluetooth Address    Device Name      RSSI  Connectable    Address Type
-------------------  -------------  ------  -------------  --------------
7f:72:d1:XX:XX:XX                      -32  True           random
55:32:e6:XX:XX:XX                      -61  True           random
b8:7c:6f:XX:XX:XX    XXXXXXXXX         -56  True           public
80:2b:f9:XX:XX:XX                      -47  False          public

```

### Enumeration
```
jaBLEs > enum b8:7c:6f:XX:XX:XX

Bluetooth Addr     UUID                                  Handle    Properties
-----------------  ------------------------------------  --------  ------------------------------
b8:7c:6f:XX:XX:XX  00002a00-0000-1000-8000-00805f9b34fb  0x3       READ WRITE
b8:7c:6f:XX:XX:XX  00002a01-0000-1000-8000-00805f9b34fb  0x5       READ
b8:7c:6f:XX:XX:XX  00002a02-0000-1000-8000-00805f9b34fb  0x7       READ WRITE
b8:7c:6f:XX:XX:XX  00002a04-0000-1000-8000-00805f9b34fb  0x9       READ
b8:7c:6f:XX:XX:XX  00002a03-0000-1000-8000-00805f9b34fb  0xb       READ WRITE NO RESPONSE WRITE
b8:7c:6f:XX:XX:XX  00002a05-0000-1000-8000-00805f9b34fb  0xe       READ INDICATE
b8:7c:6f:XX:XX:XX  003784cf-f7e3-55b4-XXXX-XXXXXXXXXXXX  0x12      NOTIFY
b8:7c:6f:XX:XX:XX  013784cf-f7e3-55b4-XXXX-XXXXXXXXXXXX  0x16      WRITE NO RESPONSE
b8:7c:6f:XX:XX:XX  00004459-0000-1000-XXXX-XXXXXXXXXXXX  0x19      WRITE NO RESPONSE WRITE NOTIFY
b8:7c:6f:XX:XX:XX  00004460-0000-1000-XXXX-XXXXXXXXXXXX  0x1c      WRITE NO RESPONSE WRITE NOTIFY
```

### View Options
```
jaBLEs > options

Option              Value
------------------  -----------------
Target              b8:7c:6f:XX:XX:XX
Devices Discovered  4
Interface           hci0
Interface Type      public
```

### Write
// To Do

### Read
// To Do
