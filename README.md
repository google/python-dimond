Python implementation of Telink Bluetooth mesh protocol
=======================================================

A simple Python API for controlling devices based on the Bluetooth LE mesh protocol from [Telink](http://www.telink-semi.com).

This is not an officially supported Google product.

Example use
-----------

All mesh networks have a name and a password, and devices have an associated vendor ID. To connect to the mesh:

```
import dimond

network = dimond.dimond(0x0211, "00:11:22:33:44:55", "Meshname", "Meshpass", callback=callback)
network.connect()
```

The target address should be any device making up the mesh. Callback is an optional argument for a callback that will be executed whenever the mesh delivers a notification. To send a packet, call:

```
network.send_packet(target, command, data)
```

where target is the target device (0 for the device that has been connected to, 0xffff for all devices on the mesh, anything in between for a specific device on the mesh), command is an integer describing the desired command and data is a list of integers providing data to the command.
