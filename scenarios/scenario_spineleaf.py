#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController
from time import sleep

class SpineLeafTopo(Topo):

    def build(self):

        spines = []
        leaves = []
        hosts = []


        for i in range(0,5):
            spine = self.addSwitch('s{}'.format(i))
            host = self.addHost('h{}'.format(i), ip="10.0.0.{}".format(i+1), mac="00:00:00:00:00:{}".format(i+1))
						self.addLink(spine, host)
						spines.append(spine)

        for i in range(5,10):
            leaf = self.addSwitch('l{}'.format(i+1))
            
            host = self.addHost('h{}'.format(i), ip="10.0.0.{}".format(i + 1), mac="00:00:00:00:00:{}".format(i + 1))
            self.addLink(leaf, host)
            for spine in spines:
                self.addLink(leaf, spine)
            leaves.append(leaf)
            hosts.append(host)

if __name__ == '__main__':
    setLogLevel('info')
    topo = SpineLeafTopo()
    c1 = RemoteController('c1', ip='172.0.0.1')
    net = Mininet(topo=topo, controller=c1)
    net.start()
    sleep(5)
    CLI(net)
    net.stop()

