# L2 Basic Forwarding

## Introduction

In today's first exercise we will implement a very basic layer 2 forwarding switch. In order to
tell the switch how to forward frames, the switch needs to know in which port it can find a given MAC
address. Real life switches automatically learn this mapping by using the l2 learning algorithm (we will see
this later today). For this exercise we will provide the switch a fix mapping between addresses and ports.

<p align="center">
<img src="images/l2_topology.png" title="L2 Star Topology">
<p/>

## Before Starting

As we already did in the previous exercises we provide you some files that will
help you through the exercise.

  *  `p4app.json`: describes the topology we want to create with the help
     of mininet and p4-utils package.
  *  `p4src/l2_basic_forwarding.p4`: p4 program skeleton to use as a starting point.


**Note**: This time you will not be able to run `p4run` until you finish some of the `TODOs`.

#### Notes about p4app.json

Remember that if the `l2` assignment strategy is enabled all devices will be automatically placed in the same
subnet and ARP tables get automatically populated. This was already explained in the previous exercise session, for
more information check [here](../02-Repeater/README.md#note-about-p4appjson).

In this exercise you will need to fill some table entries as we did last week.
If you used the control plane documentation page to fill tables, you probably used
the `simple_switch_CLI` and filled the table manually. Since this can get a bit repetitive, p4-utils allows
you to define a `CLI-like` input file for each switch. If you open the `p4app.json` example file provided with
this exercise, you will see that now, the `s1` switch has an extra option, `cli_input = ''s1-commands.txt''`.
Every time you start the topology, or reboot the switch using the `cli`, p4-utils will automatically call
the `simple_switch_CLI` using that file.

You can find all the documentation about `p4app.json` in the `p4-utils` [documentation](https://github.com/nsg-ethz/p4-utils#topology-description).

## Implementing the L2 Basic Forwarding

To solve this exercise you only need to fill the gaps you will find in the
`l2_basic_forwarding.p4` skeleton. The places where you are supposed to write your own code
are market with a `TODO`. Furthermore, you will need to create a file called `s1-commands.txt`
with commands to fill your tables.

In summary, your tasks are:

1. Define the ethernet header type and an empty metadata `struct` called meta. Then define
the headers `struct` with an ethernet header.

2. Parse the ethernet header.

3. Define a match-action table to make switch behave as a l2 packet forwarder. The destination
Mac address of each packet should tell the switch witch output port use. You can use your last exercise
as a reminder, or check the [documentation](../../documentation/control-plane.md).

4. Define the action the table will call for matching entries. The action should get
the output port index as a parameter and set it to the `egress_spec` switch's metadata field.

5. Apply the table you defined.

6. Deparse the ethernet header to add it back to the wire.

7. Write the `s1-commands.txt` file. This file should contain all the `cli` commands needed to fill
the forwarding table you defined in 3. For more information about adding entries to the table check the
[control plane documentation](../../documentation/control-plane.md).

   **Important Note**: In order to fill the table you will need two things:

     1. Host's MAC addresses: by default hosts get assigned MAC addresses using the following pattern: `00:00:<IP address to hex>`. For example
     if `h1` IP's address were `10.0.1.5` the Mac address would be: `00:00:0a:00:01:05`. Alternatively, you can use `iconfig`/`ip` directly in a
     host's terminal.

     2. Switch port index each host is connected to. There are several ways to figure out the `port_index` to interface mapping. By default
     p4-utils add ports in the same order they are found in the `links` list in the `p4app.json` conf file. Thus, with the current configuration
     the port assignment would be: {h1->1, h2->2, h3->3, h4->4}. However, this basic port assignment might not hold for more complex topologies. Another
     way of finding out port mappings is checking the messages printed by when running the `p4run` command:

         ```bash
         Switch port mapping:
         s1:  1:h1       2:h2    3:h3    4:h4
         ```

        In future exercises we will see an extra way to get topology information.

## Testing your solution

Once you have the `l2_basic_forwarding.p4` program finished you can test its behaviour:

1. Start the topology (this will also compile and load the program).

   ```bash
   sudo p4run
   ```

2. Ping between all hosts using the cli:

   ```bash
   *** Starting CLI:
   mininet> pingall
   *** Ping: testing ping reachability
   h1 -> h2 h3 h4
   h2 -> h1 h3 h4
   h3 -> h1 h2 h4
   h4 -> h1 h2 h3
   *** Results: 0% dropped (12/12 received)
   mininet>
   ```

#### Some notes on debugging and troubleshooting

We have added a [small guideline](../../documentation/debugging-and-troubleshooting.md) in the documentation section. Use it as a reference when things do not work as
expected.