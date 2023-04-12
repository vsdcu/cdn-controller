from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import CPULimitedHost, RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.util import dumpNodeConnections

class MyTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        # Add hosts
        h1 = self.addHost('h1', cpu=.5)
        h2 = self.addHost('h2', cpu=.5)
        h3 = self.addHost('h3', cpu=.5)

        # Add switch
        s1 = self.addSwitch('s1')

        # Add links
        self.addLink(h1, s1, bw=12)
        self.addLink(h2, s1, bw=12)
        self.addLink(h3, s1, bw=12)

if __name__ == '__main__':
    setLogLevel('info')

    topo = MyTopo()

    # Create Mininet instance with remote controller
    # net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=RemoteController('192.168.1.3','6653'))
    net = Mininet(topo=topo, switch=OVSSwitch, host=CPULimitedHost, controller=RemoteController('mycontroller',ip='192.168.1.3',port=6653), link=TCLink)

    net.start()

    # Install SimpleHTTPServer on host 2
    h2 = net.get('h2')
    h2.cmd('apt-get update')
    h2.cmd('apt-get install -y python')
    h2.cmd('echo "Hello, from H2!" > index.html')
    h2.cmd('nohup python -m SimpleHTTPServer 80 &')


    # Install SimpleHTTPServer on host 3
    h3 = net.get('h3')
    h3.cmd('apt-get update')
    h3.cmd('apt-get install -y python')
    h3.cmd('echo "Hello, from H3!" > index.html')
    h3.cmd('nohup python -m SimpleHTTPServer 80 &')

    # Test connectivity
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)

    # Start CLI
    net.interact()

    # Stop Mininet
    net.stop()
