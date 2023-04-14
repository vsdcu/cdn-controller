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
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.staticentry.IStaticEntryPusherService;
import net.floodlightcontroller.statistics.IStatisticsService;
import net.floodlightcontroller.topology.ITopologyService;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.projectfloodlight.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ExecutionException;

public class PacketForwarder implements IFloodlightModule, IOFMessageListener {

    protected static Logger logger = LoggerFactory.getLogger(PacketForwarder.class);
    protected static OFFactory factory;
    protected IFloodlightProviderService floodlightProvider;
    protected IDeviceService deviceService;
    protected ITopologyService topologyService;
    protected IOFSwitchService switchService;
    protected ILinkDiscoveryService linkService;
    protected IStaticEntryPusherService staticFlowEntryPusher;
    protected TopologyData topologyData;
    FlowListener flowListener;

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
        flowListener = new FlowListener();

    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        logger.info("******* Vinit ******************* PacketForwarder module started.");
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, flowListener);
        floodlightProvider.addOFMessageListener(OFType.FLOW_MOD, flowListener);
    }


    @Override
    public String getName() {
        return PacketForwarder.class.getSimpleName();
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

    static FloodlightContext context;

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        logger.info("\n\n----New OF-Packet received----");

        factory = sw.getOFFactory();
        context = cntx;

        if (msg.getType() != OFType.PACKET_IN) {
            return Command.CONTINUE;
        }

        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        if (eth.getEtherType() != EthType.IPv4) {
            return Command.CONTINUE;
        }

        topologyData = new TopologyData(sw, cntx);
        //logger.info("---TopologyData created---{}", ToStringBuilder.reflectionToString(topologyData));


        return processPacketInMsg(sw, msg, eth);

    }

    private Command processPacketInMsg(IOFSwitch sw, OFMessage msg, Ethernet eth) {

        OFPacketIn pktIn = null;
        if (msg instanceof OFPacketIn) {
            pktIn = (OFPacketIn) msg;
        }

        if (pktIn == null) {
            return Command.CONTINUE; // won't do anything if the message is not correct or not available.
        }

        IPv4 ipv4 = (IPv4) eth.getPayload();
        TransportPort srcPort;
        TransportPort dstPort;

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
            return Command.CONTINUE; // won't do anything if not TCP or UDP pkt
        }

        if (srcPort == null || dstPort == null) {
            return Command.CONTINUE;  // won't do anything if any of the port is null
        }

        topologyData.setSrcPort(srcPort);
        topologyData.setDstPort(dstPort);

        topologyData.setSourceIP(ipv4.getSourceAddress());
        topologyData.setDestIP(ipv4.getDestinationAddress());


        logger.info("------- srcPort: {}  ----------- dstPort: {}", topologyData.getSrcPort().getPort(),
                topologyData.getDstPort().getPort());

        // Check if the source or destination IP is one of our hosts
        if (!isHost(topologyData.getSourceIP()) && !isHost(topologyData.getDestIP())) {
            return Command.CONTINUE;  // won't do anything if not from our mininet topology
        }

        if (topologyData.getSourceIP().toString().equals("10.0.0.1") && topologyData.getDestIP().toString().equals("10.0.0.2")) {

            // feeding the flow first
            writeFlowToSwitch();

            // pushing down the pkt-out msg
            pushPacketOutMessage(pktIn);

        }
        return Command.CONTINUE;
    }

    private void writeFlowToSwitch() {

        String flowName = "static-redirect-flow";
        int flowPriority = 100;

        // Set actions
        List<OFAction> actions = new ArrayList<>();
        OFActionOutput output = factory.actions().buildOutput().setPort(topologyData.host3.getAttachmentPoints()[0].getPortId()).build();
        actions.add(output); //port where host3 is attached to the switch

        OFInstructions instructions = factory.instructions();
        OFInstructionApplyActions applyActions = instructions.buildApplyActions()
                .setActions(Collections.singletonList(output))
                .build();

        logger.info("---Action created---{}", ToStringBuilder.reflectionToString(applyActions));

        //set match
        Match match = factory.buildMatchV3()
                .setExact(MatchField.IPV4_SRC, topologyData.getSourceIP())
                .setExact(MatchField.IN_PORT, topologyData.host1.getAttachmentPoints()[0].getPortId()) //port where host1 is attached to the switch
                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                .setExact(MatchField.ETH_SRC, topologyData.host1.getMACAddress())
                .setExact(MatchField.ETH_DST, topologyData.host2.getMACAddress())
                .setExact(MatchField.IP_PROTO, IpProtocol.TCP)
                .setExact(MatchField.IPV4_DST, topologyData.getDestIP())
                .setExact(MatchField.TCP_SRC, topologyData.getSrcPort())
                .setExact(MatchField.TCP_DST, topologyData.getDstPort())
                .build();

        logger.info("---Match created---{}", ToStringBuilder.reflectionToString(match));

        // flow mod
        OFFlowMod flowMod = factory.buildFlowModify()
                .setMatch(match)
                //.setActions(actions)
                .setPriority(flowPriority)
                .setHardTimeout(300)
                .setIdleTimeout(300)
                .setBufferId(OFBufferId.NO_BUFFER)
                .setCookie(U64.of(225566))
                .setInstructions(Collections.singletonList(applyActions))
                .build();

        // write flow-mod to switch
        //boolean write = topologyData.sw.write(flowMod);

        //logger.info("---FlowMod written: {} ---{}",write, ToStringBuilder.reflectionToString(flowMod));

        //printExistingFlows();

//        try {
        // Push the flow rule to the switch
        staticFlowEntryPusher.addFlow(flowName, flowMod, topologyData.sw.getId());
        //Thread.sleep(5000);

//            Collection<TableId> swTables = topologyData.sw.getTables();
//            logger.info("\n---swTables---{}", ToStringBuilder.reflectionToString(swTables));

//        } catch (Exception e) {
//            e.printStackTrace();
//        }

        //printExistingFlows();

    }


    private void pushPacketOutMessage(OFPacketIn pktIn) {

        List<OFAction> actions = new ArrayList<>();
        actions.add(factory.actions().buildOutput().setPort(topologyData.host3.getAttachmentPoints()[0].getPortId()).build()); //port where host3 is attached to the switch

        OFPacketOut.Builder packetOutBuilder = topologyData.sw.getOFFactory().buildPacketOut();
        OFPacketOut packetOut = packetOutBuilder.setBufferId(pktIn.getBufferId()).setInPort(OFPort.of(topologyData.getDstPort().getPort()))
                .setActions(actions)
                .setData(pktIn.getData())
                .build();

        logger.info("---packetOut -- {}", ToStringBuilder.reflectionToString(packetOut));

        // Send message
        try {
            boolean write = topologyData.sw.write(packetOut);
            logger.info("---write -- {}", write);
        } catch (Exception e) {
            e.printStackTrace();
        }

        logger.info("---completed --");




    }




    private void printExistingFlows() {
        OFFlowStatsRequest flowStatsRequest = factory.buildFlowStatsRequest()
                .setTableId(TableId.ALL)
                .setOutPort(OFPort.ANY)
                .setOutGroup(OFGroup.ANY)
                .setCookie(U64.ZERO)
                .setCookieMask(U64.ZERO)
                .build();

        // Retrieve the FlowStatsReply message from the switch
        try {
            List<OFFlowStatsReply> flowStatsReplies = topologyData.sw.writeStatsRequest(flowStatsRequest).get();

            // Iterate through the list of FlowStatsReply messages to read flow details
            for (OFFlowStatsReply flowStatsReply : flowStatsReplies) {
                // Extract the list of FlowStatsEntry objects from the FlowStatsReply message
                List<OFFlowStatsEntry> flowStatsEntries = flowStatsReply.getEntries();
                logger.info("\n---flowStatsEntries size: ---{}", flowStatsEntries.size());

                // Iterate through the list of FlowStatsEntry objects to read flow details
                for (OFFlowStatsEntry flowStatsEntry : flowStatsEntries) {
                    // Extract flow details from the FlowStatsEntry object
                    Match match = flowStatsEntry.getMatch();
                    List<OFAction> actions = flowStatsEntry.getActions();

                    logger.info("\n---match---{}", ToStringBuilder.reflectionToString(match));
                    logger.info("n---action---{}", ToStringBuilder.reflectionToString(actions));

                }
            }

        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean isHost(IPv4Address ip) {
        if (ip.equals(IPv4Address.of("10.0.0.1")) || ip.equals(IPv4Address.of("10.0.0.2")) || ip.equals(IPv4Address.of("10.0.0.3"))) {
            return true;
        } else {
            return false;
        }
    }

    public class FlowListener implements IOFMessageListener {

        @Override
        public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
            if (msg.getType() == OFType.FLOW_REMOVED) {
                OFFlowRemoved flowRemovedMsg = (OFFlowRemoved) msg;
                DatapathId switchId = sw.getId();

                // Extract flow removal details from the OFFlowRemoved message
                OFFlowRemovedReason reason = flowRemovedMsg.getReason();

                logger.info("------------->> Flow REMOVED message received : reason {}", ToStringBuilder.reflectionToString(reason));

            }

            if (msg.getType() == OFType.FLOW_MOD) {
                OFFlowMod flowModMsg = (OFFlowMod) msg;
                DatapathId switchId = sw.getId();

                // Extract flow removal details from the OFFlowRemoved message
                //OFFlowRemovedReason reason = flowModMsg.getActions()

                //logger.info("------------>> Flow MOD message received : reason {}", ToStringBuilder.reflectionToString(flowModMsg));

            }

            return Command.CONTINUE;
        }

        @Override
        public String getName() {
            return FlowListener.class.getSimpleName();
        }

        @Override
        public boolean isCallbackOrderingPrereq(OFType type, String name) {
            return false;
        }

        @Override
        public boolean isCallbackOrderingPostreq(OFType type, String name) {
            return false;
        }
    }

    protected class TopologyData {

        IDevice host1;
        IDevice host2;
        IDevice host3;
        IOFSwitch sw;
        IDevice device_sw;
        FloodlightContext context;
        TransportPort srcPort;
        TransportPort dstPort;
        IPv4Address sourceIP;
        IPv4Address destIP;

        public TopologyData(IOFSwitch sw, FloodlightContext cntx) {
            this.sw = sw;
            this.context = cntx;
            this.host1 = getHostByIPv4Address_2(IPv4Address.of("10.0.0.1"));
            this.host2 = getHostByIPv4Address_2(IPv4Address.of("10.0.0.2"));
            this.host3 = getHostByIPv4Address_2(IPv4Address.of("10.0.0.3"));
            this.device_sw = deviceService.getDevice(HexString.toLong("00:00:00:00:00:00:00:01"));
        }

        public IDevice getHostByIPv4Address_2(IPv4Address ipv4Address) {
            for (IDevice device : deviceService.getAllDevices()) {
                if (Arrays.asList(device.getIPv4Addresses()).contains(ipv4Address)) {
                    return device;
                }
            }
            return null;
        }

        public TransportPort getSrcPort() {
            return srcPort;
        }

        public void setSrcPort(TransportPort srcPort) {
            this.srcPort = srcPort;
        }

        public TransportPort getDstPort() {
            return dstPort;
        }

        public void setDstPort(TransportPort dstPort) {
            this.dstPort = dstPort;
        }

        public IPv4Address getSourceIP() {
            return sourceIP;
        }

        public void setSourceIP(IPv4Address sourceIP) {
            this.sourceIP = sourceIP;
        }

        public IPv4Address getDestIP() {
            return destIP;
        }

        public void setDestIP(IPv4Address destIP) {
            this.destIP = destIP;
        }
    }


}
