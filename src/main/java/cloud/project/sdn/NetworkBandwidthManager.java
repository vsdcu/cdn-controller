package cloud.project.sdn;


import com.google.common.collect.ImmutableSet;
import com.google.common.util.concurrent.ListenableFuture;
import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.types.NodePortTuple;
import net.floodlightcontroller.core.web.StatsReply;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.Link;
import net.floodlightcontroller.linkdiscovery.internal.LinkInfo;
import net.floodlightcontroller.statistics.IStatisticsService;
import net.floodlightcontroller.statistics.SwitchPortBandwidth;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.topology.ITopologyService;

import java.util.*;
import java.util.concurrent.TimeUnit;

public class NetworkBandwidthManager implements IFloodlightModule, IOFMessageListener {

    protected static Logger logger = LoggerFactory.getLogger(NetworkBandwidthManager.class);

    /**
     * Required Module: Floodlight Provider Service.
     */
    protected IFloodlightProviderService floodlightProvider;

    /**
     * Required Module: Floodlight Device Manager Service.
     */
    protected IDeviceService deviceService;

    /**
     * Required Module: Topology Manager module. We listen to the topologyManager for changes of the topology.
     */
    protected ITopologyService topologyService;

    protected IOFSwitchService switchService;

    protected ILinkDiscoveryService linkService;

    protected IStatisticsService statisticsService;

    protected Map<DatapathId, IOFSwitch> switches = new HashMap<>();

    protected Map<DatapathId, OFFlowStatsReply> switchStats = new HashMap<>();

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        return getServices();
    }

    private Collection<Class<? extends IFloodlightService>> getServices() {
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
        logger = LoggerFactory.getLogger(NetworkBandwidthManager.class);
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        topologyService = context.getServiceImpl(ITopologyService.class);
        deviceService = context.getServiceImpl(IDeviceService.class);
        switchService = context.getServiceImpl(IOFSwitchService.class);
        linkService = context.getServiceImpl(ILinkDiscoveryService.class);
        statisticsService = context.getServiceImpl(IStatisticsService.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        logger.info("******* Vinit ******************* NetworkBandwidthManager module started.");
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        statisticsService.collectStatistics(true);
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

    /**
     * This method gets the packet received in controller (typically PACKET_IN)
     * @param sw the OpenFlow switch that sent this message
     * @param msg the message
     * @param cntx a Floodlight message context object you can use to pass
     * information between listeners
     * @return
     */
    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (msg.getType() != OFType.PACKET_IN) {
            return Command.CONTINUE;
        }

        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        if (eth.getEtherType() != EthType.IPv4) {
            return Command.CONTINUE;
        }

        if (msg.getType() == OFType.STATS_REPLY && msg instanceof OFStatsReply) {
            processStatsMessages(msg);
        }


        // process the ETH packet now
        return processEthIPv4Packet(sw, msg, eth);
    }

    /**
     * Method to be used to process the PACKET-IN msg.
     * @param sw
     * @param msg
     * @param eth
     * @return
     */
    private Command processEthIPv4Packet(IOFSwitch sw, OFMessage msg, Ethernet eth) {
        // request bandwidth stats from all switches
        // requestBandwidthStats(sw)
        // printBandwidthConsumption();

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

        if (ipv4.getProtocol().equals(IpProtocol.TCP)) {
            TCP tcp = (TCP) ipv4.getPayload();
            srcPort = tcp.getSourcePort();
            dstPort = tcp.getDestinationPort();
        } else if (ipv4.getProtocol().equals(IpProtocol.UDP)) {
            UDP udp = (UDP) ipv4.getPayload();
            srcPort = udp.getSourcePort();
            dstPort = udp.getDestinationPort();
        } else {
            return Command.CONTINUE;
        }

        logger.info("-----{}------- srcPort {} and dstPort {} ------------",pktIn.getType(), srcPort, dstPort);
        if (srcPort == null || dstPort == null) {
            return Command.CONTINUE;  // won't do anything if any of the port is null
        }

        // Check if the source or destination IP is one of our hosts
        boolean isSrcHost = isHost(ipv4.getSourceAddress());
        boolean isDstHost = isHost(ipv4.getDestinationAddress());

        if (!isSrcHost && !isDstHost) {
            return Command.CONTINUE;  // won't do anything if not from our mininet topology
        }

        // Check if the traffic is media streaming
        boolean isMediaStreaming = false;
        if (dstPort.getPort() == 5004 || dstPort.getPort() == 5005) {
            isMediaStreaming = true;
        }


        // Get the current bandwidth of the link
        long bandwidth = getCurrentBandwidth(sw, pktIn);

        // Apply the bandwidth policy
        if (isMediaStreaming) {
            // If the traffic is media streaming, allow higher bandwidth
            if (bandwidth < 100) {
                setBandwidth(sw.getId(), 10000000);
            }

            // route traffic to different port if media streaming
            //logger.info(">>>>>>>>>> Transferring traffic to different port");
            routeTrafficToOtherPort(sw);

        } else {
            // If the traffic is not media streaming, limit the bandwidth to 1000000 bits per second
            //logger.info("<<<<<<<<<< Not transferring traffic to different port");
            if (bandwidth > 100) {
                setBandwidth(sw.getId(), 50);
            }
        }

        // Forward the packet to the destination host
        if (isDstHost) {

            IOFSwitch dstSw = switchService.getSwitch(sw.getId());
            OFPort inPort = (pktIn.getVersion().compareTo(OFVersion.OF_12) < 0 ? pktIn.getInPort() : pktIn.getMatch().get(MatchField.IN_PORT));
            OFPacketOut packetOut = dstSw.getOFFactory().buildPacketOut()
                    .setData(eth.serialize())
                    .setActions(Arrays.asList(dstSw.getOFFactory().actions().output(inPort, Integer.MAX_VALUE)))
                    .setInPort(inPort)
                    .build();
            dstSw.write(packetOut);
        }
        //printLinkInfo();
        return Command.CONTINUE;
    }


    /**
     * This method is responsible for dispatching the packet, typically PACKET-OUT
     * @param sw
     */
    private void routeTrafficToOtherPort(IOFSwitch sw) {

        // create a flow rule to match on TCP traffic with source port 80
        Match match = sw.getOFFactory().buildMatch()
                .setExact(MatchField.ETH_TYPE, EthType.IPv4)
                .setExact(MatchField.IP_PROTO, IpProtocol.TCP)
                .setExact(MatchField.TCP_SRC, TransportPort.of(80))
                .build();

        // create an action to set the output port to a specific value
        OFActionOutput outputAction = sw.getOFFactory().actions().buildOutput()
                .setPort(OFPort.of(2))
                .build();

        // create a flow rule to forward matching traffic to the specified output port
        OFFlowAdd flowAdd = sw.getOFFactory().buildFlowAdd()
                .setPriority(100)
                .setMatch(match)
                .setActions(Collections.singletonList(outputAction))
                .build();

        // send the flow rule to the switch
        sw.write(flowAdd);
        logger.info(">>>>>>>>>>>> Routing traffic successfully to port 2 ------->");
    }


    /**
     * Just a utility method to print the link info, used for debugging
     */
    private void printLinkInfo() {
        Map<Link, LinkInfo> links = linkService.getLinks();
        logger.info("Printing Links information -------> No-Of-links = {}", links);
        links.forEach((link, linkInfo) -> {
            logger.info("Link -> {}", link);
            logger.info("LinkInfo -> {}", linkInfo);
        });
    }


/*    private OFPortStatisticsReply getPortStats(IOFSwitch sw, OFPort port) {
        OFStatsRequest req = new OFStatsRequest();
        req.setStatisticType(OFStatisticsType.PORT);
        req.setFlags(OFStatisticsRequestFlags.SEND_REQUEST_REPLY);
        OFPortStatisticsRequest psr = new OFPortStatisticsRequest();
        psr.setPortNumber(port);
        req.setStatistics(Collections.singletonList(psr));
        try {
            Future<List<OFStatistics>> future = sw.writeRequest(req);
            List<OFStatistics> stats = future.get(10, TimeUnit.SECONDS);
            if (stats != null && !stats.isEmpty()) {
                OFPortStatisticsReply reply = (OFPortStatisticsReply) stats.get(0);
                return reply;
            }
        } catch (Exception e) {
            logger.error("Failed to get port statistics from switch {}", sw.getId(), e);
        }
        return null;
    }*/


    private void processStatsMessages(OFMessage msg) {
        logger.info("----- >>>>>>>>>. processing stats msgs ------> " + msg.toString());
        StatsReply reply = (StatsReply) msg;
        if (reply.getStatType() == OFStatsType.FLOW) {
            // Handle flow stats reply
            //for (OFStatistics stat : reply.getStatistics()) {
            List<?> statsList = (List<?>) reply.getValues();
            logger.info("----- statsList ------> " + statsList);
/*                for (Object obj : statsList) {
                    if(obj instanceof StatsReply) {
                        OFStatsReply flowStat = (OFStatsReply) obj;
                        OFStatsType statsType = flowStat.getStatsType();

                        logger.info(flowStat.);
                        //long byteCount = flowStat.getByteCount().getValue();
                        //long packetCount = flowStat.getPacketCount().getValue();
                        //System.out.println(String.format("Switch %s flow stats: byteCount=%d, packetCount=%d", sw.getId().toString(), byteCount, packetCount));
                    }
                }*/
        }
    }

    private boolean isHost(IPv4Address ip) {
        if (ip.equals(IPv4Address.of("10.0.0.1")) || ip.equals(IPv4Address.of("10.0.0.2"))) {
            return true;
        } else {
            return false;
        }
    }

    private long getCurrentBandwidth(IOFSwitch sw, OFPacketIn pktIn) {
        OFPort inPort = (pktIn.getVersion().compareTo(OFVersion.OF_12) < 0 ? pktIn.getInPort() : pktIn.getMatch().get(MatchField.IN_PORT));
        SwitchPortBandwidth swpBandwidth = statisticsService.getBandwidthConsumption(sw.getId(), inPort);

        if (null == swpBandwidth) {
            logger.info("***ERROR**** failed to get the port bandwidth for switch - {}, port - {} ", sw.getId(), inPort);
            return 0L;
        }
        U64 pBandwidth = swpBandwidth.getBitsPerSecondRx().add(swpBandwidth.getBitsPerSecondTx());
        logger.info("----------- port bandwidth for switch - {}, port - {} : {} bytes/sec", sw.getId(), inPort, pBandwidth.getValue());
        return pBandwidth.getValue();
    }

    private void setBandwidth(DatapathId switchId, int bandwidth) {
        // This method should set the new bandwidth of the link
        logger.info("******* setting bandwidth : {}, {}", switchId, bandwidth);
    }



    /**
     * Following method is used to fetch the stats for all switches present in the topology
     */
    private void requestBandwidthStats() {
        // Request flow stats from all switches
        switchService.getAllSwitchDpids().forEach(id->{
            IOFSwitch sw = switchService.getSwitch(id);
            OFFlowStatsRequest req = sw.getOFFactory().buildFlowStatsRequest()
                    .setMatch(sw.getOFFactory().buildMatch().build())
                    .setOutPort(OFPort.ANY)
                    .setTableId(TableId.ALL)
                    .setFlags(ImmutableSet.of())
                    .build();

            try {
                ListenableFuture<OFFlowStatsReply> statsReplyFuture = sw.writeRequest(req);
                OFFlowStatsReply statsReply = statsReplyFuture.get(1, TimeUnit.MINUTES);
                if (Objects.nonNull(statsReply)) {
                    logger.info("£££££ port statistics from switch {} >> {}", sw.getId(), statsReply);
                    switchStats.put(sw.getId(), statsReply);
                } else {
                    logger.info("?????? NO statistics from switch {}", sw.getId());
                }
            } catch (Exception e) {
                logger.error("Failed to get port statistics from switch {}", sw.getId(), e);
            }

        });
    }

    /**
     * Just a logging method used for debug purposes
     */
    private void printBandwidthConsumption() {
        Map<NodePortTuple, SwitchPortBandwidth> bandwidthConsumption = statisticsService.getBandwidthConsumption();
        bandwidthConsumption.forEach((tuple, band) -> {
            U64 switchPortBandwidth = band.getBitsPerSecondRx().add(band.getBitsPerSecondTx());
            logger.info(":: Stats **** tuple = {}, bandwidth = {} bits/sec", tuple.toString(), switchPortBandwidth.getValue());
        });
    }

}
