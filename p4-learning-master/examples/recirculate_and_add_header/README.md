# Recirculate and Add Headers


```
+--+      +--+     ++-+
|h1+------+s1+-----+h2+
+--+      +-++     +--+

```

## Introduction

In this example we show how to recirculate packets and add a headers at
each recirculation. At each recirculation it reads the content of a register
and adds it to the new header.

To test the program we provide a sending carrier application that sends
special packets that indicate how many times do they have to be recirculated.

We also provide a script to automatically fill a `register[i]=i values where
i in [0,127]`.


## How to run

Start topology:

```
sudo p4run
```

Fill register:

```
python fill_register.py
```

Send Magic packets:

```
mx h1
python send_carrier.py <num_recirculations>
```

You can monitor packets at the output port of the switch to see that
the number of bytes increases as we recirculate more. You can also inspect
the value of those packets and verify that they carry the register's content
using `wireshark` or any other tool.

