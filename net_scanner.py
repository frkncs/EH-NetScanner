import scapy.all as scapy
import optparse

# 1. Arp request
# 2. Broadcast
# 3. Response

def get_parse() -> tuple[any, any]:
    parse_object = optparse.OptionParser()
    parse_object.add_option("-r", "--range", dest="ip_range", help="IP Range that you wanna scan.")

    if not parse_object.parse_args()[0].ip_range:
        print("Enter IP Range. Run \"--help\" to see options")
        raise SystemExit

    return parse_object.parse_args()


# returns: Answereds and Unanswereds broadcasts returns (answereds, unanswereds)
def get_broadcast_result(ip_range: str) -> tuple[list, list]:
    arp_request_packet = scapy.ARP(pdst=ip_range)
    # scapy.ls(scapy.ARP())

    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # scapy.ls(scapy.Ether())

    combined_packet = broadcast_packet / arp_request_packet
    return scapy.srp(combined_packet,
                     timeout=1)  # We can use "sr" function to only send package to a specific target, "srp" is for broadcasts

ip_range = get_parse()[0].ip_range
get_broadcast_result(ip_range)[0].summary()
