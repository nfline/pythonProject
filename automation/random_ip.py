import random
import ipaddress

def generate_random_ip(network=None):
    """
    Generate a random IP address
    If network is specified, generate IP within that network
    network format: '192.168.1.0/24'
    """
    if network:
        try:
            net = ipaddress.ip_network(network)
            # Generate random IP in network
            random_ip = str(net[random.randint(0, net.num_addresses - 1)])
            return random_ip
        except ValueError as e:
            print(f"Invalid network format: {e}")
            return None
    else:
        # Generate completely random IP
        return ".".join(str(random.randint(0, 255)) for _ in range(4))

def main():
    # Example usage
    print("Random IP:", generate_random_ip())
    print("Random IP in network 192.168.1.0/24:", 
          generate_random_ip('192.168.1.0/24'))

if __name__ == "__main__":
    main()