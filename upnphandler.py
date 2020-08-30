import miniupnpc
upnp = miniupnpc.UPnP()

def open_port(port):

    upnp.discoverdelay = 10
    upnp.discover()

    upnp.selectigd()

    # add port mapping(external-port, protocol, internal-host, internal-port, description, remote-host)
    result = upnp.addportmapping(port, 'TCP', upnp.lanaddr, port, 'PLOP_TRANSFER', '')
    return result


def close_port(port):
    b = upnp.deleteportmapping(port, 'TCP')
    return b