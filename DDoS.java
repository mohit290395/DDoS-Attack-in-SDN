package net.floodlightcontroller.ddos;
import net.floodlightcontroller.core.IFloodlightProviderService;
import java.lang.Math;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;

import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.VlanVid;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

public class DDOS implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	static int pcktinc=0;
	HashMap<String,Integer> pktcnt = new HashMap<String,Integer>();
	
	@Override
	public String getName() {
	    return DDOS.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
	    Collection<Class<? extends IFloodlightService>> l =
	        new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
	    floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    macAddresses = new ConcurrentSkipListSet<Long>();
	    logger = LoggerFactory.getLogger(DDOS.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
	    floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		
		switch (msg.getType()) {
	    case PACKET_IN:
	     
	    	Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
	        		    	
	    	if (eth.getEtherType() == EthType.IPv4) {
	            IPv4 ipv4 = (IPv4) eth.getPayload();          
	            IPv4Address dstIp = ipv4.getDestinationAddress();
	            IPv4Address srcIp = ipv4.getSourceAddress();
	            System.out.println("SD"+srcIp+" "+dstIp);
	            addentry(srcIp);
	            display(pktcnt);
	            disp();
	            System.out.println("here 5");
	          System.out.println(calculateEntropy(pktcnt)+"BYEBYE_IMDONE");
	        }
	        
	        
	        
	        break;
	    default:
	        break;
	    }
	    return Command.CONTINUE;
	}
	void addentry(IPv4Address Ip) 
	{	
		pcktinc++;
		System.out.println("Inside "+Ip.toString());
		if(pktcnt.containsKey(Ip.toString()))
		{
			System.out.println("Inside if");
		    int tmp = pktcnt.get(Ip.toString())+1;
	
		    pktcnt.put(Ip.toString(),tmp);
			System.out.println("New Value is:"+pktcnt.get(Ip.toString()).toString()+"  "+tmp);

		}
		else
		{
			System.out.println("Inside else"+Ip.toString());
			pktcnt.put(Ip.toString(),1);
		}		
		
	}
public void disp()
{
	System.out.println("INSIDE DISP");
	 for(String key : pktcnt.keySet())
	  {
		  System.out.println("@@@@@@@Key is "+key+" Value is "+pktcnt.get(key));
	  }
}
	
    void display(HashMap<String,Integer> pkt)
    {
    	
    	System.out.println("PRINT TOTAL NUMBER OF PACKETS ");
    	 if(pcktinc==50)
	       {
		      System.out.println("total no. of packets are:"+pcktinc);
		      double entropy = calculateEntropy(pktcnt);
		      System.out.println("final entropy is :"+entropy);
		    }	
    	 System.out.println("PacketIN count is"+pcktinc);
    
    }
	
	
	public static Double calculateEntropy(HashMap<String,Integer> pkt) {
		  HashMap<String, Double> entropy = new HashMap<String, Double>();
		 
		  double p=0,tmp=0.0,t2,sum=0;
		  int n=0;
		  double ent=0;
		  for(String key : pkt.keySet())
		  {
	          tmp=pkt.get(key);
	          System.out.println("**************************************");
	          System.out.println(tmp);
			  tmp=tmp/pcktinc;
			  System.out.println(tmp);
			  
			  t2=(-1)*tmp*(Math.log10(tmp));
			 // sum=sum+t2;
			  System.out.println("Each host entropy "+" "+t2);
			  entropy.put(key, t2);
			  sum=(sum+t2)/pkt.size();
			  System.out.println("**************************************");  
			  
			  
			  
		  }
		  System.out.println(entropy);
		//  System.out.println(sum);
		  System.out.println("Final Entropy = "+ " "+sum);
		  DDOS obj=new DDOS();
		  System.out.println("@@@@@@@Final Entropy after approximation@@@@@@@@");
		  obj.roundFourDecimals(sum);
		  return null;
		  }
	
	       void roundFourDecimals(double d) {
	       DecimalFormat FourDForm = new DecimalFormat("#.####");
	       System.out.println( Double.valueOf(FourDForm.format(d)));

	}
}
