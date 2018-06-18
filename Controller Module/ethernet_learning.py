from pox.core import core
import pox.openflow.libopenflow_01 as of

# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()

# Empty dictionary to save event information
topology = {}


# Handle messages the switch has sent us because it has no
# matching rule.
def _handle_PacketIn(event):
    packet = event.parsed

    topology[event.connection.eth_addr, packet.src] = event.port  # learn from this event

    dest_port = topology.get((event.connection.eth_addr, packet.dst))  # get instruction for switch

    msg = of.ofp_packet_out()
    msg.data = event.ofp  # original OpenFlow packet

    if dest_port is not None:  # filters ARP as well since packet source will never be FF:FF:FF:FF:FF:FF
        mod = of.ofp_flow_mod()
        mod.match.dl_dst = packet.dst
        mod.match.in_port = event.port
        mod.actions.append(of.ofp_action_output(port=dest_port))

        log.info("INSTALL FLOW")
        event.connection.send(mod)

        log.info("RESEND PACKET")
        msg.actions.append(of.ofp_action_output(port=dest_port))
    else:
        log.info("FLOOD PACKET")
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

    event.connection.send(msg)


def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("Pair-Learning switch running.")
