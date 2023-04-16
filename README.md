# cdn-controller-floodlight
SDN controller implementation for SDN usecase based on Floodlight and OpenFlow protocol


# PacketForwarder.java
Main class to read the `packet_in` message and process it

Then it creates the `Match` and `Action` from the content of `Packet_IN` message
and prepares a `FLOW_MOD` which can be pushed to the switch.

# Important- this code is not 100% working as I was able to push the mod-flow onto the vSwitch and that can be seen by retreiving all the existing flows using Floodlight REST interface. However, for some reason that flow was not getting in effect, means later packets were not getting transfer to different nodes as expected. 

This issue needs to be investigated further. I'll come back on this and update my findings here.

Thanks,
