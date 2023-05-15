gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0


Sites that helped for this project:
https://www.tcpdump.org/pcap.html
https://linux.die.net/man/3/pcap
https://en.wikipedia.org/wiki/Ethernet_frame#Structure
https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header
https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure


Total network flows are the TCP and UDP network flows only, since for other
protocols the port numbers for source and destination are in not known places in
the packet.

UDP does not retransmit if a packet does not arrive successfully, it just drops
it.

For TCP, retransmitted packets are not implemented due to time restrictions, but
the way to find them is to check the sequence numbers. If we find something out
of order then it is going to be retransmitted or it is a retransmition.

The port filter mush match either the source of destination port. The total
number of packet counter is not affected by the filter.

When it runs live on a given device, it sniffs 400 packets (which can be changed 
in code).

IPv6 is not implemented.

