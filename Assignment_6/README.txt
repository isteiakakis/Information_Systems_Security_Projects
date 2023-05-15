Ubuntu 20.04.5 LTS
GNU bash, version 5.0.17(1)-release (x86_64-pc-linux-gnu)


Everything is done as the assignment instructions describe. 

Only IPv4 addresses were blocked since only the iptables command has been used
(not ip6tables) because it was not mentioned in the assignment instructions to
block both IPv4 and IPv6 and it would be a little hard to save both IPv4 and
IPv6 addresses with the given file structure. Hence, only DNS queries of type A
were made.

A new function named domain_to_IP was created to find the IPv4 addresses of the
given domains. The domains are in each line of a file given as the first
argument of the function and the IPv4 addresses are written in the file given as
the second argument.

Everything else in the code is explained in comments.

Everything works fine. The domain names that should be blocked are blocked, with
a few exceptions... if a domain name has IPv6 address, then it may not be
blocked, due to the reason explained above. But if ip6tables is used to block
all the IPv6 addresses then the firewall blocks those domains also successfully
(e.g. xxxmatch.com).

During visiting one of my favorite websites, without using the adblocker of the
browser, some of the ads persist because their IP address is not one of the IP
addresses that the script blocked.

