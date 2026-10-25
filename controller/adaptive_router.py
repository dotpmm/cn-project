
"""
Adaptive SDN Router
Project: Adaptive Communication Network with Failure Recovery
Controller: Ryu
Protocol: OpenFlow 1.3

Features:
- LLDP-based topology discovery
- Dynamic shortest-path routing
- Link failure and restoration handling
- IPv4 forwarding based on destination IP
- Basic ARP proxying
- Controller event logging
"""

import os
import csv
import time
import threading
from collections import deque, defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types
from ryu.topology import event
from ryu.topology.api import get_switch, get_link


class AdaptiveRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AdaptiveRouter, self).__init__(*args, **kwargs)

        self.switches = {}
        self.graph = defaultdict(dict)
        self.links = {}
        self.hosts = {}
        self.mac_to_ip = {}

        self.event_log = "controller_events.csv"
        self.stats_log = "port_stats.csv"

        self.lock = threading.RLock()
        self.datapaths = {}

        self._initialize_logs()

        self.logger.info("AdaptiveRouter initialized")

    # ---------------------------------------------------------
    # Logging
    # ---------------------------------------------------------

    def _initialize_logs(self):
        for filename, header in [
            (
                self.event_log,
                ["timestamp", "event", "details"],
            ),
            (
                self.stats_log,
                [
                    "timestamp",
                    "switch",
                    "port",
                    "rx_packets",
                    "tx_packets",
                    "rx_bytes",
                    "tx_bytes",
                ],
            ),
        ]:
            try:
                directory = os.path.dirname(os.path.abspath(filename))
                os.makedirs(directory, exist_ok=True)

                if not os.path.exists(filename):
                    with open(filename, "w", newline="") as file:
                        csv.writer(file).writerow(header)
            except OSError as exc:
                self.logger.error("Cannot initialize %s: %s", filename, exc)

    def log_event(self, event_name, details=""):
        timestamp = time.time()
        self.logger.info("%s: %s", event_name, details)

        try:
            with open(self.event_log, "a", newline="") as file:
                csv.writer(file).writerow(
                    [timestamp, event_name, details]
                )
        except OSError as exc:
            self.logger.error("Cannot write event log: %s", exc)

    # ---------------------------------------------------------
    # Switch connection and initial configuration
    # ---------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        # Table-miss: send unmatched packets to the controller.
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]

        self.add_flow(
            datapath,
            priority=0,
            match=match,
            actions=actions,
        )

        self.logger.info("Switch s%d connected", datapath.id)
        self.log_event("switch_connected", f"s{datapath.id}")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self.log_event("switch_disconnected", f"s{datapath.id}")

            with self.lock:
                self._rebuild_graph()
                self._recompute_all_routes()

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        idle_timeout=0,
        hard_timeout=0,
    ):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions,
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )

        datapath.send_msg(mod)

    def delete_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch(),
        )
        datapath.send_msg(mod)

        # Restore the table-miss rule.
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]
        self.add_flow(
            datapath,
            0,
            parser.OFPMatch(),
            actions,
        )

    # ---------------------------------------------------------
    # Topology discovery
    # ---------------------------------------------------------

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        self.refresh_topology()

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        self.refresh_topology()

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst

        with self.lock:
            self.graph[src.dpid][dst.dpid] = src.port_no
            self.links[(src.dpid, dst.dpid)] = (
                src.port_no,
                dst.port_no,
            )
            self._recompute_all_routes()

        self.log_event(
            "link_up",
            f"s{src.dpid}:port{src.port_no} "
            f"<-> s{dst.dpid}:port{dst.port_no}",
        )

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst

        with self.lock:
            self.graph.get(src.dpid, {}).pop(dst.dpid, None)
            self.graph.get(dst.dpid, {}).pop(src.dpid, None)

            self.links.pop((src.dpid, dst.dpid), None)
            self.links.pop((dst.dpid, src.dpid), None)

            self._recompute_all_routes()

        self.log_event(
            "link_down_detected",
            f"s{src.dpid} <-> s{dst.dpid}",
        )

    def refresh_topology(self):
        try:
            switches = get_switch(self, None)
            links = get_link(self, None)
        except Exception as exc:
            self.logger.warning("Topology refresh failed: %s", exc)
            return

        with self.lock:
            self.switches = {
                switch.dp.id: switch.dp for switch in switches
            }

            self.graph = defaultdict(dict)
            self.links = {}

            for link in links:
                src = link.src
                dst = link.dst

                self.graph[src.dpid][dst.dpid] = src.port_no
                self.links[(src.dpid, dst.dpid)] = (
                    src.port_no,
                    dst.port_no,
                )

            self._recompute_all_routes()

        self.log_event(
            "topology_updated",
            f"{len(self.switches)} switches, {len(links)} directed links",
        )

    def _rebuild_graph(self):
        self.graph = defaultdict(dict)

        for (src, dst), ports in self.links.items():
            self.graph[src][dst] = ports[0]

    # ---------------------------------------------------------
    # Shortest path routing
    # ---------------------------------------------------------

    def shortest_path(self, source, destination):
        if source == destination:
            return [source]

        queue = deque([[source]])
        visited = {source}

        while queue:
            path = queue.popleft()
            current = path[-1]

            for neighbor in sorted(self.graph.get(current, {})):
                if neighbor in visited:
                    continue

                new_path = path + [neighbor]

                if neighbor == destination:
                    return new_path

                visited.add(neighbor)
                queue.append(new_path)

        return None

    def _recompute_all_routes(self):
        """
        Remove old forwarding rules and reinstall routes for
        every learned host on the current topology.
        """
        for datapath in list(self.datapaths.values()):
            self.delete_flows(datapath)

        for ip_address in list(self.hosts.keys()):
            self.install_route_to_host(ip_address)

        self.log_event(
            "routes_updated",
            f"Recomputed routes for {len(self.hosts)} learned hosts",
        )

    def install_route_to_host(self, destination_ip):
        destination = self.hosts.get(destination_ip)
        if destination is None:
            return

        destination_switch, destination_port, _ = destination

        for source_switch in list(self.datapaths.keys()):
            path = self.shortest_path(
                source_switch,
                destination_switch,
            )

            if not path:
                continue

            datapath = self.datapaths.get(source_switch)
            if datapath is None:
                continue

            if source_switch == destination_switch:
                output_port = destination_port
            else:
                next_switch = path[1]
                output_port = self.graph.get(
                    source_switch, {}
                ).get(next_switch)

                if output_port is None:
                    continue

            parser = datapath.ofproto_parser
            actions = [
                parser.OFPActionOutput(output_port)
            ]

            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=destination_ip,
            )

            self.add_flow(
                datapath,
                priority=10,
                match=match,
                actions=actions,
            )

            self.logger.info(
                "Route to %s on s%d via port %d; path=%s",
                destination_ip,
                source_switch,
                output_port,
                path,
            )

    # ---------------------------------------------------------
    # Link status messages
    # ---------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        desc = msg.desc
        ofproto = datapath.ofproto

        reason = msg.reason

        if reason == ofproto.OFPPR_DELETE:
            status = "PORT_DELETED"
        elif desc.state & ofproto.OFPPS_LINK_DOWN:
            status = "LINK_DOWN"
        else:
            status = "PORT_STATUS_CHANGED"

        self.log_event(
            "port_status",
            f"s{datapath.id} port={desc.port_no} status={status}",
        )

        # LLDP topology events update the graph. Refreshing the
        # topology here is a fallback; port events alone do not
        # always identify the remote switch.
        if status == "LINK_DOWN":
            self.refresh_topology()

    # ---------------------------------------------------------
    # Packet processing
    # ---------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_packet = pkt.get_protocol(arp.arp)
            if arp_packet:
                self.handle_arp(
                    datapath,
                    in_port,
                    eth.src,
                    arp_packet,
                    msg.data,
                )
            return

        ip_packet = pkt.get_protocol(ipv4.ipv4)
        if ip_packet:
            self.learn_host(
                ip_packet.src,
                eth.src,
                datapath.id,
                in_port,
            )

            self.forward_ipv4(
                datapath,
                in_port,
                ip_packet.dst,
                msg.data,
            )

    def learn_host(self, ip_address, mac_address, dpid, port):
        if ip_address in ("0.0.0.0", None):
            return

        old = self.hosts.get(ip_address)
        self.hosts[ip_address] = (dpid, port, mac_address)
        self.mac_to_ip[mac_address] = ip_address

        if old != self.hosts[ip_address]:
            self.log_event(
                "host_learned",
                f"{ip_address} {mac_address} on s{dpid}:port{port}",
            )

            self.install_route_to_host(ip_address)

    def forward_ipv4(self, datapath, in_port, destination_ip, data):
        destination = self.hosts.get(destination_ip)

        if destination is None:
            # Unknown destination: drop rather than flood a looped
            # topology with arbitrary IPv4 broadcasts.
            return

        self.install_route_to_host(destination_ip)

        dpid = datapath.id
        destination_switch, destination_port, _ = destination

        if dpid == destination_switch:
            output_port = destination_port
        else:
            path = self.shortest_path(dpid, destination_switch)
            if not path or len(path) < 2:
                return

            output_port = self.graph.get(dpid, {}).get(path[1])
            if output_port is None:
                return

        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(output_port)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    # ---------------------------------------------------------
    # ARP proxy
    # ---------------------------------------------------------

    def handle_arp(
        self,
        datapath,
        in_port,
        source_mac,
        arp_packet,
        original_data,
    ):
        if arp_packet.opcode != arp.ARP_REQUEST:
            return

        source_ip = arp_packet.src_ip
        target_ip = arp_packet.dst_ip

        self.learn_host(
            source_ip,
            source_mac,
            datapath.id,
            in_port,
        )

        target = self.hosts.get(target_ip)
        if target is None:
            # Unknown ARP destination: flood only to host-facing ports.
            self.flood_arp_to_hosts(
                datapath,
                in_port,
                original_data,
            )
            return

        _, _, target_mac = target

        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                dst=source_mac,
                src=target_mac,
                ethertype=ether_types.ETH_TYPE_ARP,
            )
        )
        pkt.add_protocol(
            arp.arp(
                hwtype=arp.ARP_HW_TYPE_ETHERNET,
                proto=arp.ARP_PROTO_TYPE_IP,
                hlen=6,
                plen=4,
                opcode=arp.ARP_REPLY,
                src_mac=target_mac,
                src_ip=target_ip,
                dst_mac=source_mac,
                dst_ip=source_ip,
            )
        )
        pkt.serialize()

        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(in_port)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data,
        )
        datapath.send_msg(out)

    def flood_arp_to_hosts(self, datapath, in_port, data):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        inter_switch_ports = set(
            self.graph.get(datapath.id, {}).values()
        )

        actions = []

        # Only flood to ports not currently known to connect switches.
        for port in datapath.ports:
            if port == in_port:
                continue

            if port in inter_switch_ports:
                continue

            if port >= ofproto.OFPP_MAX:
                continue

            actions.append(parser.OFPActionOutput(port))

        if not actions:
            return

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)