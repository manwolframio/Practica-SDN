#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller
from time import sleep



class SingleSwitchTopo(Topo):

    def build(self):
        s1 = self.addSwitch(name = 's1')
        h1 = self.addHost(name = 'h1', ip = "10.0.0.2",mac="00:00:00:01")
        h2 = self.addHost(name = 'h2', ip = "10.0.0.3",mac="00:00:00:02")

        self.addLink(h1, s1)
        self.addLink(h2, s1)


if __name__ == '__main__':
    setLogLevel('info')
    topo = SingleSwitchTopo()
    c1 = RemoteController('c1', ip='172.0.0.1') # Se va a conectar a la IP del host con ryu
    net = Mininet(topo=topo, controller=c1)
    net.start()
    sleep(5)
    CLI(net)
    net.stop()
