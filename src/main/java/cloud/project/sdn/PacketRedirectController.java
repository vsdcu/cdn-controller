package cloud.project.sdn;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.staticentry.IStaticEntryPusherService;
import net.floodlightcontroller.statistics.IStatisticsService;
import net.floodlightcontroller.topology.ITopologyService;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;

public class PacketRedirectController implements IFloodlightModule, IOFMessageListener {

    protected static Logger logger = LoggerFactory.getLogger(PacketRedirectController.class);
    protected static OFFactory factory = OFFactories.getFactory(OFVersion.OF_13);
    protected IFloodlightProviderService floodlightProvider;
    protected IDeviceService deviceService;
    protected ITopologyService topologyService;
    protected IOFSwitchService switchService;
    protected ILinkDiscoveryService linkService;
    IStaticEntryPusherService staticFlowEntryPusher;

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        l.add(ITopologyService.class);
        l.add(IDeviceService.class);
        l.add(IOFSwitchService.class);
        l.add(ILinkDiscoveryService.class);
        l.add(IStatisticsService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        topologyService = context.getServiceImpl(ITopologyService.class);
        deviceService = context.getServiceImpl(IDeviceService.class);
        switchService = context.getServiceImpl(IOFSwitchService.class);
        linkService = context.getServiceImpl(ILinkDiscoveryService.class);
        staticFlowEntryPusher = context.getServiceImpl(IStaticEntryPusherService.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        logger.info("******* Vinit ******************* PacketRedirectController module started.");
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }

    @Override
    public String getName() {
        return NetworkBandwidthManager.class.getSimpleName();
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

        if (msg.getType() != OFType.PACKET_IN) {
            return Command.CONTINUE;
        }

        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        if (eth.getEtherType() != EthType.IPv4) {
            return Command.CONTINUE;
        }

        // process the ETH packet now
        return processPacketInMsg(sw, msg, eth);
    }

    private Command processPacketInMsg(IOFSwitch sw, OFMessage msg, Ethernet eth) {

        // fetch the pkt-in details

        OFPacketIn pktIn = null;
        if (msg instanceof OFPacketIn) {
            pktIn = (OFPacketIn) msg;
        }

        if (pktIn == null) {
            return Command.CONTINUE; // won't do anything if the message is not correct or not available.
        }

        IPv4 ipv4 = (IPv4) eth.getPayload();
        TransportPort srcPort = null;
        TransportPort dstPort = null;

        IpProtocol protocol = ipv4.getProtocol();
        if (protocol.equals(IpProtocol.TCP)) {
            TCP tcp = (TCP) ipv4.getPayload();
            srcPort = tcp.getSourcePort();
            dstPort = tcp.getDestinationPort();
        } else if (protocol.equals(IpProtocol.UDP)) {
            UDP udp = (UDP) ipv4.getPayload();
            srcPort = udp.getSourcePort();
            dstPort = udp.getDestinationPort();
        } else {
            return Command.CONTINUE;
        }

        if (srcPort == null || dstPort == null) {
            return Command.CONTINUE;  // won't do anything if any of the port is null
        }

        IPv4Address srcAddress = ipv4.getSourceAddress();
        IPv4Address dstAddress = ipv4.getDestinationAddress();

        // Check if the source or destination IP is one of our hosts
        boolean isSrcHost = isHost(srcAddress);
        boolean isDstHost = isHost(dstAddress);

        if (!isSrcHost && !isDstHost) {
            return Command.CONTINUE;  // won't do anything if not from our mininet topology
        }

        boolean isValid = checkRedirectionCriteria(srcAddress, dstAddress, protocol, dstPort, sw);


        return Command.CONTINUE;
    }


    private boolean checkRedirectionCriteria(IPv4Address srcIP, IPv4Address dstIP, IpProtocol protocol, TransportPort dstPort, IOFSwitch sw) {


        IPv4Address HOST1_IP = IPv4Address.of("10.0.0.1");
        IPv4Address HOST2_IP = IPv4Address.of("10.0.0.2");
        IPv4Address HOST3_IP = IPv4Address.of("10.0.0.3");
        IPv4Address HOST4_IP = IPv4Address.of("10.0.0.4");

        TransportPort VIDEO_FILE_PORT = TransportPort.of(80);

        // Check if the traffic matches the criteria for redirection
        if (srcIP.equals(HOST1_IP) && dstIP.equals(HOST2_IP) && isValidProtocol(protocol) && dstPort.equals(VIDEO_FILE_PORT)) {

            logger.info("---check passed--");
            IDevice host1 = getHostByIPv4Address(HOST1_IP); // new host
            IDevice host2 = getHostByIPv4Address(HOST2_IP);
            IDevice host3 = getHostByIPv4Address(HOST3_IP); // new host
            IDevice host4 = getHostByIPv4Address(HOST4_IP); // new host

            if (null != host1 && null != host2 && null != host3 && null != host4) {

                logger.info("---devices found--{}, {}, {}, {}", host1.getMACAddressString(), host2.getMACAddressString(), host3.getMACAddressString(), host4.getMACAddressString());
                logger.info("--- h1-{} ", host1);logger.info("--- h2-{} ", host2);logger.info("--- h3-{} ", host3);logger.info("--- h4-{} ", host4);

                // Get the switch port objects representing the ports on the switches that the hosts are attached to
                SwitchPort swPort2 = host2.getAttachmentPoints()[0]; // fetching switchPort where host2 is linked

                SwitchPort swPort3 = host3.getAttachmentPoints()[0]; // fetching switchPort where host3 is linked

                // Install the flow rule to redirect the traffic through host 2 instead of host 4
                String flowName = "redirect-video-flow";
                String flowMatch = "ip src " + HOST1_IP + "/32";
                String flowAction = "set-src-ip=" + HOST3_IP + ",output=" + swPort3.getPortId();
                int flowPriority = 100;

                // Set actions
                List<OFAction> actions = new ArrayList<OFAction>();
                actions.add(factory.actions().buildOutput().setPort(swPort3.getPortId()).build());

                logger.info("---action created---{}", actions.get(0));

                //set match
                //IPv4AddressWithMask srcIpWithMask = IPv4AddressWithMask.of(HOST1_IP, IPv4Address.of(32));
                Match match = factory.buildMatchV3().setExact(MatchField.IPV4_SRC, HOST1_IP).build();

                logger.info("---match created---{}", match);

                OFFlowMod flowMod = factory.buildFlowAdd()
                        .setMatch(match)
                        .setActions(actions)
                        .setPriority(flowPriority)
                        .setHardTimeout(0)
                        .setIdleTimeout(0)
                        .setBufferId(OFBufferId.NO_BUFFER)
                        .setCookie(U64.of(0)).build();

                logger.info("---flowMod created---{}", flowMod);

                try {
                    // Push the flow rule to the switch
                    staticFlowEntryPusher.addFlow(flowName, flowMod, sw.getId());
                } catch (Exception e) {
                    e.printStackTrace();
                }

                logger.info("---completed --");
            } else {
                logger.info("---devices not found-- h1-{}, h2-{}, h3-{}, h4-{}", host1, host2, host3, host4);
                logger.error("Error finding hosts:: ------------ ");
            }
        }

        return true;
    }

    public IDevice getHostByIPv4Address(IPv4Address ipv4Address) {
        for (IDevice device : deviceService.getAllDevices()) {
            if (Arrays.asList(device.getIPv4Addresses()).contains(ipv4Address)) {
                return device;
            }
        }
        return null;
    }

    public IDevice getHostByIPv4Address2(IPv4Address ipv4Address) {
        for (IDevice device : deviceService.getAllDevices()) {
            if (Arrays.asList(device.getIPv4Addresses()).contains(ipv4Address)) {
                return device;
            }
        }
        return null;
    }

    private boolean isHost(IPv4Address ip) {
        if (ip.equals(IPv4Address.of("10.0.0.1")) || ip.equals(IPv4Address.of("10.0.0.2")) || ip.equals(IPv4Address.of("10.0.0.3"))) {
            return true;
        } else {
            return false;
        }
    }

    private boolean isValidProtocol(IpProtocol protocol) {
        return protocol.equals(IpProtocol.TCP) || protocol.equals(IpProtocol.UDP);
    }

    public static class FlowModExample {
        private static OFFactory factory =
                OFFactories.getFactory(OFVersion.OF_13);

        public static OFFlowMod createFlowMod() {
            OFFlowMod flowMod = factory.buildFlowAdd()
                    .build();
            return flowMod;
        }
    }

}
