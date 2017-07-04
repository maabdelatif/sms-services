package com.abdelama.sms;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;
import java.util.StringTokenizer;
import java.text.SimpleDateFormat;

import org.smpp.Data;
import org.smpp.pdu.*;
import org.smpp.ServerPDUEvent;
import org.smpp.ServerPDUEventListener;
import org.smpp.Session;
import org.smpp.SmppObject;
import org.smpp.TCPIPConnection;
import org.smpp.TimeoutException;
import org.smpp.WrongSessionStateException;
import org.smpp.pdu.Address;
import org.smpp.pdu.AddressRange;
import org.smpp.pdu.BindRequest;
import org.smpp.pdu.BindResponse;
import org.smpp.pdu.EnquireLink;
import org.smpp.pdu.EnquireLinkResp;
import org.smpp.pdu.PDU;
import org.smpp.pdu.PDUException;
import org.smpp.pdu.SubmitSM;
import org.smpp.pdu.SubmitSMResp;
import org.smpp.pdu.UnbindResp;
import org.smpp.pdu.ValueNotSetException;
import org.smpp.pdu.WrongLengthOfStringException;
import org.smpp.util.Queue;

import org.smpp.util.ByteBuffer;

/**
 * Some of the code was copied from under the following copyright *
 * "Copyright (c) 1996-2001 Logica Mobile Networks Limited;
 this product includes software developed by Logica by whom copyright
 and know-how are retained, all rights reserved."  
 */

/**
 * Class <code>ExtendedChars</code> sends a single silent SMS by manipulating the
 * data coding to specify a message wait indicator with discard flag
 * 
 * @author Logica Mobile Networks SMPP Open Source Team, since adapted slightly
 *         by Mohamed Abdelatif
 */
public class ExtendedChars {

	/**
	 * * File with default settings for the application.
	 */
	static String propsFilePath = "./smppsender.cfg";

	/**
	 * This is the SMPP session used for communication with SMSC.
	 */
	static Session session = null;

	/**
	 * Contains the parameters and default values for this test application such
	 * as system id, password, default npi and ton of sender etc.
	 */
	Properties properties = new Properties();

	/**
	 * If the application is bound to the SMSC.
	 */
	boolean bound = false;

	/**
	 * Address of the SMSC.
	 */
	String ipAddress = null;

	/**
	 * The port number to bind to on the SMSC server.
	 */
	int port = 0;

	/**
	 * The name which identifies you to SMSC.
	 */
	String systemId = null;

	/**
	 * The password for authentication to SMSC.
	 */
	String password = null;

	/**
	 * How you want to bind to the SMSC: transmitter (t), receiver (r) or
	 * transciever (tr). Transciever can both send messages and receive
	 * messages. Note, that if you bind as receiver you can still receive
	 * responses to you requests (submissions).
	 */
	String bindOption = "tr";

	/**
	 * Indicates that the Session has to be asynchronous. Asynchronous Session
	 * means that when submitting a Request to the SMSC the Session does not
	 * wait for a response. Instead the Session is provided with an instance of
	 * implementation of ServerPDUListener from the smpp library which receives
	 * all PDUs received from the SMSC. It's application responsibility to match
	 * the received Response with sended Requests.
	 */
	boolean asynchronous = true;

	/**
	 * This is an instance of listener which obtains all PDUs received from the
	 * SMSC. Application doesn't have explicitly call Session's receive()
	 * function, all PDUs are passed to this application callback object. See
	 * documentation in Session, Receiver and ServerPDUEventListener classes
	 * form the SMPP library.
	 */
	static SMPPTestPDUEventListener pduListener = null;

	/**
	 * The range of addresses the smpp session will serve.
	 */
	AddressRange addressRange = new AddressRange();

	/*
	 * for information about these variables have a look in SMPP 3.4
	 * specification
	 */
	String systemType = "";
	String serviceType = "";
	static Address sourceAddress = new Address();
	static Address destAddress = new Address();
	String scheduleDeliveryTime = "";
	String validityPeriod = "000000001000000R"; // 10 minutes from now (relative)
	String shortMessage = "";
	int numberOfDestination = 1;
	static String messageId = "";
	byte esmClass = 0; // WAP push 64 // Default 0
	byte protocolId = 0;
	byte priorityFlag = 0;
	byte registeredDelivery = 1; // We want a delivery report
	byte replaceIfPresentFlag = 0;
	byte dataCoding = (byte) 0; // Silent SMS 192 // Flash SMS 240 // WAP Push 245 // Default 0
	byte smDefaultMsgId = 0;

	/**
	 * If you attempt to receive message, how long will the application wait for
	 * data.
	 */
	long receiveTimeout = Data.RECEIVE_BLOCKING;

	/**
	 * The command ID for the SMPP 3.4 protocols
	 */
	// final int ENQUIRE_LINK_RESP_COMMAND_ID = 2147483669;
	static final int ENQUIRE_LINK_COMMAND_ID = 21;
	static final int DELIVER_SM_COMMAND_ID = 5;
	static final int QUERY_SM_RESP_COMMAND_ID = -2147483645;
	static final int SUBMIT_SM_RESP_COMMAND_ID = -2147483644;

	/**
	 * Runnable class that processes received PDUs
	 */
	static ReceivedPDUsProcessor pduProcessor = null;

	/**
	 * Initialises the application, loads default values for connection to SMSC
	 * and for various PDU fields.
	 */
	public ExtendedChars() throws IOException {
		loadProperties(propsFilePath);
		pduProcessor = new ReceivedPDUsProcessor();
	}

	/**
	 * Processes the enquire_link PDU by sending back a enquire_link_resp PDU.
	 */
	public static void processEnquireLinkPDU(PDU pdu) {
		// Generating enquire_link_resp
		Response response = ((Request) pdu).getResponse();
		System.out.println(getCurrentTime() + " Sending enquire_link_resp " + response.debugString());
		if (session != null) {
			try {
				session.respond(response);
			} catch (ValueNotSetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (WrongSessionStateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	/**
	 * Processes the enquire_link PDU by sending back a enquire_link_resp PDU.
	 */
	public static void processDeliverSMPDU(PDU pdu) {
		// Cast to deliverSM
		DeliverSM deliverSM = (DeliverSM) pdu;
		// Check to see whether this is a subscriber SM or delivery report
		System.out.println(getCurrentTime() + " Examining recieved deliverSM " + deliverSM.debugString());
		
		/**
		 * Format of the delivery report:
		 * id:0669703056 sub:001 dlvrd:001 submit date:1405061655 done date:1405061705 stat:EXPIRED err:254 text:foshfoshfosh@@@@@@@@
		 */

		// Check the message format
		String message = deliverSM.getShortMessage();
		if (message.contains("id:") && message.contains("sub:") && message.contains("dlvrd:") && message.contains("date:") &&
				message.contains("stat:") && message.contains("err") && message.contains("text:")){
			String[] splited = message.split("\\s+");
			String id = splited[0].substring(splited[0].indexOf(":")+1);
			String convertedMessageId = Long.toString(Long.parseLong(messageId, 16));
			/**
			 * Convert both message IDs to Long because there could be leading zeroes.
			 * If this if statement is not executed is is probably because we have not received a submit_sm_resp
			 */
			if (convertedMessageId != "") {
				if (Long.parseLong(convertedMessageId) == Long.parseLong(id)){
					String stat = splited[7].substring(splited[7].indexOf(":")+1);
					String err = splited[8].substring(splited[8].indexOf(":")+1);
					System.out.println("Received deliver report for the message: " + stat + ", with error code: " + err);
				}
			}
		}

		// Generating deliver_sm_resp
		Response response = ((Request) pdu).getResponse();
		System.out.println(getCurrentTime() + " Sending deliver_sm_resp " + response.debugString());
		if (session != null) {
			try {
				session.respond(response);
			} catch (ValueNotSetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (WrongSessionStateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	/**
	 * Processes the query_sm_resp PDU by confirming the delivery status
	 */
	public static void processQuerySMRespPDU(PDU pdu) {
		QuerySMResp queryResp = (QuerySMResp) pdu;
		String messageState = "";
		switch ((int)queryResp.getMessageState()) {
		case Data.SM_STATE_EN_ROUTE:
			messageState = "ENROUTE";
			break;
		case Data.SM_STATE_DELIVERED:
			messageState = "DELIVERED";
			break;
		case Data.SM_STATE_EXPIRED:
			messageState = "EXPIRED";
			break;
		case Data.SM_STATE_DELETED:
			messageState = "DELETED";
			break;
		case Data.SM_STATE_UNDELIVERABLE:
			messageState = "UNDELIVERABLE";
			break;
		case Data.SM_STATE_ACCEPTED:
			messageState = "ACCEPTED";
			break;
		case Data.SM_STATE_INVALID:
			messageState = "UNKNOWN";
			break;
		case Data.SM_STATE_REJECTED:
			messageState = "REJECTED";
			break;
		default:
			messageState = "Undefined message state";
			break;
		}

		System.out.println(getCurrentTime() + " Received the message status as " + messageState + " " + queryResp.getMessageState() + " " + queryResp.getErrorCode());
	}

	/**
	 * Processes the submit_sm_resp PDU by saving the message ID
	 */
	public static void processSubmitSMRespPDU(PDU pdu) {
		SubmitSMResp submitResp = (SubmitSMResp) pdu;
		messageId = submitResp.getMessageId();
		System.out.println(getCurrentTime() + " Received Submit SM Resp with message ID as " + messageId);
	}

	/**
	 * Sets global SMPP library debug and event objects. Runs the application.
	 * 
	 * @see SmppObject#setDebug(Debug)
	 * @see SmppObject#setEvent(Event)
	 */
	public static void main(String args[]) {
		// Parse the command line
		String sender = null;
		byte senderTon = (byte) 0;
		byte senderNpi = (byte) 0;
		String dest = null;
		String message = null;

		for (int i = 0; i < args.length; i++) {
			if (args[i].startsWith("-")) {
				String opt = args[i].substring(1);
				if (opt.compareToIgnoreCase("sender") == 0) {
					sender = args[++i];
				} else if (opt.compareToIgnoreCase("senderTon") == 0) {
					senderTon = Byte.parseByte(args[++i]);
				} else if (opt.compareToIgnoreCase("senderNpi") == 0) {
					senderNpi = Byte.parseByte(args[++i]);
				} else if (opt.compareToIgnoreCase("dest") == 0) {
					dest = args[++i];
				} else if (opt.compareToIgnoreCase("destination") == 0) {
					dest = args[++i];
				} else if (opt.compareToIgnoreCase("message") == 0) {
					message = args[++i];
				} else if (opt.compareToIgnoreCase("file") == 0) {
					propsFilePath = args[++i];
				}
			}
		}

		if ((dest == null)) {
			System.out
					.println("Usage: SMPPSender -dest <dest number on international format> ");
			System.exit(0);
		}

		// Dest may contain comma-separated numbers
		Collection<String> destinations = new ArrayList<String>();
		StringTokenizer st = new StringTokenizer(dest, ",");
		while (st.hasMoreTokens()) {
			String d = st.nextToken();
			destinations.add(d);
		}

		System.out.println("Initialising...");
		ExtendedChars smppSender = null;
		try {
			smppSender = new ExtendedChars();
		} catch (IOException e) {
			System.out.println("Exception initialising SMPPSender " + e);
		}
		
		message = "@£$¥èéùìòÇ Øø ÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà^{}\\[~]|€";
		//message = "£$¥èéùìòÇØøÅåÆæßÉ !\"¤$%&'()*+,-./01239:;?ABCYZÄÖÑÜ§abcxyzäöñüà{}\\[~]@€";
		//ByteBuffer messagePayload = new ByteBuffer();
		//messagePayload.appendBytes(message.getBytes());
		//message  = "a324a5e8e9f9ecf2c7d8f8c5e5c6e6dfc9202122a42425262728292a2b2c2d2e2f30313233393a3b3f414243595ac4d6d1dca761626378797ae4f6f1fce07b7d5c5b7e5d4080";

		System.out.println("Sending: \"" + message + "\" to " + dest);
		if (smppSender != null) {
			smppSender.bind();

			if (smppSender.bound) {
				Iterator<String> it = destinations.iterator();
				while (it.hasNext()) {
					String d = it.next();
					smppSender.submit(d, message, sender, senderTon, senderNpi);
				}

				// Start the thread that will process received PDUs from the
				// Queue
				Thread runner = new Thread(pduProcessor);
				runner.start();

				// Wait for the validity period to expire, 11 minutes just to be safe 
				try {
					Thread.sleep(1000*60*11);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				// If a delivery receipt is not received after this then send query_sm

				// Send query_sm to find status of message
				QuerySM querySM = new QuerySM();
				if (messageId != ""){
					try {
						// Convert from hexadecimal to integer
						String convertedMessageId = Long.toString(Long.parseLong(messageId, 16));
						querySM.setMessageId(convertedMessageId);
					} catch (WrongLengthOfStringException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				querySM.setSourceAddr(sourceAddress);
				
				// Receive response for the query_sm asynchronously
				try {
					System.out.println(getCurrentTime() + " Sending query SM request " + querySM.debugString());
					session.query(querySM);
				} catch (TimeoutException | PDUException | WrongSessionStateException | IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				try {
					// Sleep for 10 seconds
					Thread.sleep(10000);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				runner.interrupt();
				smppSender.unbind();
			}
		}
	}

	/**
	 * The first method called to start communication betwen an ESME and a SMSC.
	 * A new instance of <code>TCPIPConnection</code> is created and the IP
	 * address and port obtained from user are passed to this instance. New
	 * <code>Session</code> is created which uses the created
	 * <code>TCPIPConnection</code>. All the parameters required for a bind are
	 * set to the <code>BindRequest</code> and this request is passed to the
	 * <code>Session</code>'s <code>bind</code> method. If the call is
	 * successful, the application should be bound to the SMSC.
	 * 
	 * See "SMPP Protocol Specification 3.4, 4.1 BIND Operation."
	 * 
	 * @see BindRequest
	 * @see BindResponse
	 * @see TCPIPConnection
	 * @see Session#bind(BindRequest)
	 * @see Session#bind(BindRequest,ServerPDUEventListener)
	 */
	private void bind() {
		try {
			if (bound) {
				System.out.println("Already bound, unbind first.");
				return;
			}

			BindRequest request = null;
			BindResponse response = null;

			// Set the bind to transciever mode
			request = new BindTransciever();

			TCPIPConnection connection = new TCPIPConnection(ipAddress, port);
			connection.setReceiveTimeout(20 * 1000);
			session = new Session(connection);

			// set values
			request.setSystemId(systemId);
			request.setPassword(password);
			request.setSystemType(systemType);
			request.setInterfaceVersion((byte) 0x34);
			request.setAddressRange(addressRange);

			// send the request
			System.out.println("Bind request " + request.debugString());
			if (asynchronous) {
				pduListener = new SMPPTestPDUEventListener(session);
				response = session.bind(request, pduListener);
			} else {
				response = session.bind(request);
			}
			System.out.println("Bind response " + response.debugString());
			if (response.getCommandStatus() == Data.ESME_ROK) {
				bound = true;
			} else {
				System.out.println("Bind failed, code " + response.getCommandStatus());
			}
		} catch (Exception e) {
			System.out.println("Bind operation failed. " + e);
		}
	}

	/**
	 * Ubinds (logs out) from the SMSC and closes the connection.
	 * 
	 * See "SMPP Protocol Specification 3.4, 4.2 UNBIND Operation."
	 * 
	 * @see Session#unbind()
	 * @see Unbind
	 * @see UnbindResp
	 */
	private void unbind() {
		try {

			if (!bound) {
				System.out.println("Not bound, cannot unbind.");
				return;
			}

			// send the request
			System.out.println("Going to unbind.");
			if (session.getReceiver().isReceiver()) {
				System.out.println("It can take a while to stop the receiver.");
			}
			UnbindResp response = session.unbind();
			System.out.println("Unbind response " + response.debugString());
			bound = false;
		} catch (Exception e) {
			System.out.println("Unbind operation failed. " + e);
		}
	}

	/**
	 * Creates a new instance of <code>SubmitSM</code> class, lets you set
	 * subset of fields of it. This PDU is used to send SMS message to a device.
	 * 
	 * See "SMPP Protocol Specification 3.4, 4.4 SUBMIT_SM Operation."
	 * 
	 * @see Session#submit(SubmitSM)
	 * @see SubmitSM
	 * @see SubmitSMResp
	 */
	private void submit(String destAddress, String shortMessage, String sender, byte senderTon, byte senderNpi) {
		try {
			SubmitSM request = new SubmitSM();
			SubmitSMResp response;

			// set values
			request.setServiceType(serviceType);

			if (sender != null) {
				if (sender.startsWith("+")) {
					sender = sender.substring(1);
					senderTon = 1;
					senderNpi = 1;
				}
				if (!sender.matches("\\d+")) {
					senderTon = 5;
					senderNpi = 0;
				}

				if (senderTon == 5) {
					request.setSourceAddr(new Address(senderTon, senderNpi, sender, 11));
				} else {
					request.setSourceAddr(new Address(senderTon, senderNpi, sender));
				}
			} else {
				request.setSourceAddr(sourceAddress);
			}

			if (destAddress.startsWith("+")) {
				destAddress = destAddress.substring(1);
			}
			request.setDestAddr(new Address((byte) 1, (byte) 1, destAddress));
			request.setReplaceIfPresentFlag(replaceIfPresentFlag);
			//request.setShortMessage(shortMessage, Data.ENC_ISO8859_1);
			//String message = "£$¥èéùìòÇØøÅåÆæßÉ !\"¤$%&'()*+,-./01239:;?ABCYZÄÖÑÜ§abcxyzäöñüà{}\\[~]@€";
			String message = "@£$¥èéùìòÇ Øø ÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà^{}\\[~]|€";
			ByteBuffer messagePayload = new ByteBuffer();
			messagePayload.appendBytes(message.getBytes());
			request.setMessagePayload(messagePayload);
			
			request.setScheduleDeliveryTime(scheduleDeliveryTime);
			request.setValidityPeriod(validityPeriod);
			request.setEsmClass(esmClass);
			request.setProtocolId(protocolId);
			request.setPriorityFlag(priorityFlag);
			request.setRegisteredDelivery(registeredDelivery);
			request.setDataCoding(dataCoding);
			request.setSmDefaultMsgId(smDefaultMsgId);
			request.assignSequenceNumber(true);
			// request.getAlertOnMsgDelivery(); // Does not seem to be supported

			if (asynchronous) {
				System.out.println(getCurrentTime() + " Submit request " + request.debugString());
				session.submit(request);
			} else {
				response = session.submit(request);
				messageId = response.getMessageId();
				System.out.println(getCurrentTime() + " Submit response " + response.debugString());
			}

		} catch (Exception e) {
			System.out.println("Submit operation failed. " + e);
		}
	}

	/**
	 * Creates a new instance of <code>EnquireSM</code> class. This PDU is used
	 * to check that application level of the other party is alive. It can be
	 * sent both by SMSC and ESME.
	 * 
	 * See "SMPP Protocol Specification 3.4, 4.11 ENQUIRE_LINK Operation."
	 * 
	 * @see Session#enquireLink(EnquireLink)
	 * @see EnquireLink
	 * @see EnquireLinkResp
	 */
	private void enquireLink() {
		try {
			EnquireLink request = new EnquireLink();
			EnquireLinkResp response;
			System.out.println(getCurrentTime() + " Enquire Link request " + request.debugString());
			if (asynchronous) {
				session.enquireLink(request);
			} else {
				response = session.enquireLink(request);
				System.out.println(getCurrentTime() + " Enquire Link response " + response.debugString());
			}
		} catch (Exception e) {
			System.out.println("Enquire Link operation failed. " + e);
		}
	}

	/**
	 * Receives one PDU of any type from SMSC and prints it on the screen.
	 * 
	 * @see Session#receive()
	 * @see Response
	 * @see ServerPDUEvent
	 */
	private void receive() {
		try {

			PDU pdu = null;
			System.out.print("Going to receive a PDU. ");
			if (receiveTimeout == Data.RECEIVE_BLOCKING) {
				System.out.print("The receive is blocking, i.e. the application " + "will stop until a PDU will be received.");
			} else {
				System.out.print("The receive timeout is " + receiveTimeout / 1000 + " sec.");
			}
			System.out.println();
			if (asynchronous) {
				ServerPDUEvent pduEvent = pduListener.getRequestEvent(receiveTimeout);
				if (pduEvent != null) {
					pdu = pduEvent.getPDU();
				}
			} else {
				pdu = session.receive(receiveTimeout);
			}
			if (pdu != null) {
				System.out.println(getCurrentTime() + " Received PDU " + pdu.debugString());
				if (pdu.isRequest()) {
					Response response = ((Request) pdu).getResponse();
					// respond with default response
					System.out.println("Going to send default response to request " + response.debugString());
					session.respond(response);
				}
			} else {
				System.out.println("No PDU received this time.");
			}

		} catch (Exception e) {
			System.out.println("Receiving failed. " + e);
		}
	}

	private class SMPPTestPDUEventListener extends SmppObject implements ServerPDUEventListener {
		@SuppressWarnings("unused")
		Session session;
		Queue requestEvents = new Queue();

		public SMPPTestPDUEventListener(Session session) {
			this.session = session;
		}

		public void handleEvent(ServerPDUEvent event) {
			PDU pdu = event.getPDU();
			if (pdu.isRequest() || pdu.isResponse()) {
				System.out.println("async request received, enqueuing " + pdu.debugString());
				synchronized (requestEvents) {
					requestEvents.enqueue(event);
					requestEvents.notify();
				}
			} else {
				System.out.println("pdu of unknown class (not request nor " + "response) received, discarding " + pdu.debugString());
			}
		}

		/**
		 * Returns received pdu from the queue. If the queue is empty, the
		 * method blocks for the specified timeout.
		 */
		public ServerPDUEvent getRequestEvent(long timeout) {
			ServerPDUEvent pduEvent = null;
			synchronized (requestEvents) {
				if (requestEvents.isEmpty()) {
					try {
						requestEvents.wait(timeout);
					} catch (InterruptedException e) {
						// ignoring, actually this is what we're waiting for
					}
				}
				if (!requestEvents.isEmpty()) {
					pduEvent = (ServerPDUEvent) requestEvents.dequeue();
				}
			}
			return pduEvent;
		}
	}

	/**
	 * Loads configuration parameters from the file with the given name. Sets
	 * private variable to the loaded values.
	 */
	private void loadProperties(String fileName) throws IOException {
		System.out.println("Reading configuration file " + fileName + "...");
		FileInputStream propsFile = new FileInputStream(fileName);
		properties.load(propsFile);
		propsFile.close();
		System.out.println("Setting default parameters...");
		byte ton;
		byte npi;
		String addr;
		String bindMode;
		int rcvTimeout;
		String syncMode;

		ipAddress = properties.getProperty("ip-address");
		port = getIntProperty("port", port);
		systemId = properties.getProperty("system-id");
		password = properties.getProperty("password");

		ton = getByteProperty("addr-ton", addressRange.getTon());
		npi = getByteProperty("addr-npi", addressRange.getNpi());
		addr = properties.getProperty("address-range", addressRange.getAddressRange());
		addressRange.setTon(ton);
		addressRange.setNpi(npi);
		try {
			addressRange.setAddressRange(addr);
		} catch (WrongLengthOfStringException e) {
			System.out.println("The length of address-range parameter is wrong.");
		}

		ton = getByteProperty("source-ton", sourceAddress.getTon());
		npi = getByteProperty("source-npi", sourceAddress.getNpi());
		addr = properties.getProperty("source-address", sourceAddress.getAddress());
		setAddressParameter("source-address", sourceAddress, ton, npi, addr);

		ton = getByteProperty("destination-ton", destAddress.getTon());
		npi = getByteProperty("destination-npi", destAddress.getNpi());
		addr = properties.getProperty("destination-address", destAddress.getAddress());
		setAddressParameter("destination-address", destAddress, ton, npi, addr);

		serviceType = properties.getProperty("service-type", serviceType);
		systemType = properties.getProperty("system-type", systemType);
		bindMode = properties.getProperty("bind-mode", bindOption);
		if (bindMode.equalsIgnoreCase("transmitter")) {
			bindMode = "t";
		} else if (bindMode.equalsIgnoreCase("receiver")) {
			bindMode = "r";
		} else if (bindMode.equalsIgnoreCase("transciever")) {
			bindMode = "tr";
		} else if (!bindMode.equalsIgnoreCase("t") && !bindMode.equalsIgnoreCase("r") && !bindMode.equalsIgnoreCase("tr")) {
			System.out.println("The value of bind-mode parameter in " + "the configuration file " + fileName + " is wrong. " + "Setting the default");
			bindMode = "t";
		}
		bindOption = bindMode;

		// receive timeout in the cfg file is in seconds, we need milliseconds
		// also conversion from -1 which indicates infinite blocking
		// in the cfg file to Data.RECEIVE_BLOCKING which indicates infinite
		// blocking in the library is needed.
		if (receiveTimeout == Data.RECEIVE_BLOCKING) {
			rcvTimeout = -1;
		} else {
			rcvTimeout = ((int) receiveTimeout) / 1000;
		}
		rcvTimeout = getIntProperty("receive-timeout", rcvTimeout);
		if (rcvTimeout == -1) {
			receiveTimeout = Data.RECEIVE_BLOCKING;
		} else {
			receiveTimeout = rcvTimeout * 1000;
		}

		syncMode = properties.getProperty("sync-mode", (asynchronous ? "async" : "sync"));
		if (syncMode.equalsIgnoreCase("sync")) {
			asynchronous = false;
		} else if (syncMode.equalsIgnoreCase("async")) {
			asynchronous = true;
		} else {
			asynchronous = false;
		}

	}

	/**
	 * Gets a property and converts it into byte.
	 */
	private byte getByteProperty(String propName, byte defaultValue) {
		return Byte.parseByte(properties.getProperty(propName, Byte.toString(defaultValue)));
	}

	/**
	 * Gets a property and converts it into integer.
	 */
	private int getIntProperty(String propName, int defaultValue) {
		return Integer.parseInt(properties.getProperty(propName, Integer.toString(defaultValue)));
	}

	/**
	 * Sets attributes of <code>Address</code> to the provided values.
	 */
	private void setAddressParameter(String descr, Address address, byte ton, byte npi, String addr) {
		address.setTon(ton);
		address.setNpi(npi);
		try {
			address.setAddress(addr);
		} catch (WrongLengthOfStringException e) {
			System.out.println("The length of " + descr + " parameter is wrong.");
		}
	}

	/**
	 * Returns the current system time
	 */
	private static String getCurrentTime() {
		Calendar cal = Calendar.getInstance();
		SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY-MM-dd HH:mm:ss");
		return dateFormat.format(cal.getTime());
	}

	private class ReceivedPDUsProcessor implements Runnable {

		long receiveTimeout = 3;
		ServerPDUEvent serverPDUEvent = null;
		int commandId = 0;
		PDU pdu = null;

		public ReceivedPDUsProcessor() {
			System.out.println("Starting processor to process received PDUs...");
		}

		public void run() {
			while (true) {
				if (pduListener != null) {
					serverPDUEvent = pduListener.getRequestEvent(receiveTimeout);
					if (serverPDUEvent != null) {
						pdu = serverPDUEvent.getPDU();
						commandId = pdu.getCommandId();
						System.out.println(getCurrentTime() + " Processed PDU from Queue: " + commandId);
						switch (commandId) {
						case DELIVER_SM_COMMAND_ID:
							processDeliverSMPDU(pdu);
							break;
						case ENQUIRE_LINK_COMMAND_ID:
							processEnquireLinkPDU(pdu);
							break;
						case QUERY_SM_RESP_COMMAND_ID:
							processQuerySMRespPDU(pdu);
							break;
						case SUBMIT_SM_RESP_COMMAND_ID:
							processSubmitSMRespPDU(pdu);
							break;
						default:
							System.out.println(getCurrentTime() + " Unhandled command ID recieved " + commandId + " " + SUBMIT_SM_RESP_COMMAND_ID);
							break;
						}
					}
				}
			}
		}
	}
}
/*
 */
