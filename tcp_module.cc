// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be 
// copied over as part of the build process

/*
Austin Choi, Clark Nicolas
CS 1652 F15
Project 2
*/

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"

// New imports
#include "tcpstate.h"
#include <exception>

using namespace std;

/*
struct TCPState {
    // need to write this
    std::ostream & Print(std::ostream &os) const { 
	os << "TCPState()" ; 
	return os;
    }
};
*/

/*
Packet createPacket(ConnectionToStateMapping<TCPState> &a_mapping, int payload_size, char flags) {
	Packet p;
	IPHeader ip;
	TCPHeader tcp;
	int packet_size = payload_size + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;
	
	// Set IP header
	ip.SetProtocol(IP_PROTO_TCP);
	ip.SetTotalLength(packet_size);
	ip.SetSourceIP(a_mapping.connection.src);
	ip.SetDestIP(a_mapping.connection.dest);
	p.PushFrontHeader(ip);
	
	// Set TCP header
	tcp.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);
	tcp.SetWinSize(a_mapping.state.GetN(), p);
	tcp.SetAckNum(a_mapping.state.GetLastRecvd(), p);
	tcp.SetSeqNum(a_mapping.state.GetLastAcked() + 1, p);
	tcp.SetSourcePort(a_mapping.connection.srcport, p);
	tcp.SetDestPort(a_mapping.connection.destport, p);
	tcp.RecomputeChecksum(p);
	p.PushBackHeader(tcp);
	return p;
}
*/
Packet createPacket(const Connection conn, const int payload_size, const char flags) {
	Packet p;
	int packet_size = payload_size + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;
	TCPHeader tcp;
	IPHeader ip;	
	cout << "Creating " << packet_size << " B packet...\n";
	// Set IP header
	try 
	{
		ip.SetProtocol(IP_PROTO_TCP);
		ip.SetTotalLength(packet_size);
		ip.SetSourceIP(conn.src);
		ip.SetDestIP(conn.dest);
		p.PushFrontHeader(ip);	
		
	} 
	catch (exception& e) 
	{
		 cout << "Error setting IP header on packet:" << '\n' << e.what() << '\n';
	}
	// Set TCP header
	try
	{
		tcp.SetHeaderLen(5, p);
		tcp.SetWinSize(3, p);
		tcp.SetAckNum(1, p);
		tcp.SetSeqNum(100, p);
		tcp.SetSourcePort(conn.srcport, p);
		tcp.SetDestPort(conn.destport, p);
		tcp.SetFlags(flags, p);
		tcp.RecomputeChecksum(p);	
		p.PushBackHeader(tcp);		
	} catch (exception& e)
	{
		cout << "Error setting TCP header on packet:" << '\n' << e.what() << '\n';
	}
	
	return p;
}

struct PacketInfo {
	unsigned int seq;
	unsigned int ack;
	unsigned char flags;
	unsigned char tcp_header_len;
	unsigned char ip_header_len;
	unsigned short buffer_len;
	unsigned short total_len;
	unsigned short src_port;
	unsigned short dest_port;	
	IPAddress src_ip;
	IPAddress dest_ip;
	Buffer buffer;
	PacketInfo(Packet &p) {
		// Extract headers (temporary)
		p.ExtractHeaderFromPayload<TCPHeader>(TCPHeader :: EstimateTCPHeaderLength(p));
		TCPHeader tcp_header = p.FindHeader(Headers :: TCPHeader); 
		IPHeader ip_header = p.FindHeader(Headers :: IPHeader);	
		// Read TCP vars
		tcp_header.GetFlags(flags);
		tcp_header.GetSeqNum(seq);
		tcp_header.GetAckNum(ack);
		tcp_header.GetSourcePort(src_port);
		tcp_header.GetDestPort(dest_port);
		// Read IP vars
		ip_header.GetSourceIP(src_ip);
		ip_header.GetDestIP(dest_ip);
		// Read length vars
		ip_header.GetTotalLength(total_len);
		ip_header.GetHeaderLength(ip_header_len);
		tcp_header.GetHeaderLen(tcp_header_len);
		buffer_len = total_len - ip_header_len - tcp_header_len;
		// Read buffer
		buffer = p.GetPayload().ExtractFront(buffer_len);	
	} 
};

void printPacketInfo(char * name, PacketInfo pi) {
	cout << name << "\n---------------\n";
	// Print #
	cout << "SEQ: " << pi.seq << " ACK: " << pi.ack << endl;
	// Print flags
	cout << "Flags: ";
	if  (IS_SYN(pi.flags)|| IS_ACK(pi.flags)) {
		if (IS_SYN(pi.flags)) cout << "SYN";	
		if (IS_ACK(pi.flags)) cout << "ACK";
	} else if (pi.flags == 0) cout << "NONE";
	else cout << "N/A";
	cout << endl;
	// Print IP & ports
	cout << "SRC: " << pi.src_ip << ":" << pi.src_port << endl; 
	cout << "DEST: " << pi.dest_ip << ":" << pi.dest_port << endl; 
	cout << "---------------\n";
}


int main(int argc, char * argv[]) {
	/* Minet setup */
    MinetHandle mux;
    MinetHandle sock;
    MinetInit(MINET_TCP_MODULE);

    mux = MinetIsModuleInConfig(MINET_IP_MUX) ?  
		MinetConnect(MINET_IP_MUX) : 
		MINET_NOHANDLE;

		sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? 
		MinetAccept(MINET_SOCK_MODULE) : 
		MINET_NOHANDLE;

		if ( (mux == MINET_NOHANDLE) && (MinetIsModuleInConfig(MINET_IP_MUX)) ) {
			MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));
			return -1;
		}
		if ( (sock == MINET_NOHANDLE) && (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {
			MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));
			return -1;
		}
    
    cout << "tcp_module auc5|cmn26 handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module auc5|cmn26 handling tcp traffic........"));

    MinetEvent event;
    double timeout = 1;

	/* Single connection */
	IPAddress src_ip("192.168.102.5");
	IPAddress dest_ip("192.168.102.5");
	unsigned short src_port = 5050;
	unsigned short dest_port = 5050;
	unsigned char proto = IP_PROTO_TCP;
	Connection conn(src_ip, dest_ip, src_port, dest_port, proto);
	/* Single tcp state */
	unsigned int current_tcp_state = LISTEN;

    while (MinetGetNextEvent(event, timeout) == 0) {

		if ((event.eventtype == MinetEvent::Dataflow) && 
	    (event.direction == MinetEvent::IN)) {
	    
	    if (event.handle == mux) {
		/* Handle IP packet */

			Packet p;	
			Packet p_send;
			SockRequestResponse request;
			SockRequestResponse response;
			
			// Get packet
			MinetReceive(mux,p);
			// Pass contents of packet into convenient struct
			PacketInfo p_in(p);
			// Print contents of packet
			printPacketInfo("Incoming packet", p_in);

		  // ConnectionList stores a list (queue) of ConnectionToStateMappings
			/*
		    Connection conn;
			ConnectionList<TCPState> :: iterator connections_iterator = clist.FindMatching(conn);
			ConnectionToStateMapping maps connection addresses to TCP connection state (TCPState)
		    ConnectionToStateMapping<TCPState> & connstate = (*connections_iterator);
			*/

			// Grabs current TCP state
			//unsigned int current_tcp_state = (connstate).state.GetState();

			switch(current_tcp_state) {
				
				case CLOSED: {
					cout << "MUX: CLOSED\n";
					break;
				}
				// Waiting connection request from any remote TCP & port
				// Handle passive open
				case LISTEN: {
					cout << "MUX: LISTEN\n";
					if (IS_SYN(p_in.flags)) {
						cout << "Conn request received.\n";
						// Update state
						//connstate.state.SetState(SYN_RCVD);
						//connstate.connection = conn;
						current_tcp_state = SYN_RCVD;
						// Update connection
						conn.dest = p_in.dest_ip;
						// Send SYN ACK
						cout << "Sending ack...\n";
						unsigned char flags = 0;
						SET_ACK(flags);
						SET_SYN(flags);
						Packet ack = createPacket(conn, 0, flags);
						MinetSend(mux, ack);
					}
					break;
				}
				// Waiting for an ack after having both received & sent a conn req (host)
				case SYN_RCVD: {
					cout << "MUX: SYN_RCVD\n";
					if (IS_ACK(p_in.flags)) {
						cout << "Ack acknowledged.\n";
						// Update state
						//connstate.state.SetState(ESTABLISHED);
						//connstate.state.SetLastAcked(ack);
						current_tcp_state = ESTABLISHED;
						
						//response
						response.type = STATUS;
						response.connection = conn;
						MinetSend(sock, response);
					}
					break;
				}
				// Represents waiting for a matching conn request after having sent one (client)
				case SYN_SENT: {
					cout << "MUX: SYN_SENT\n";
					if(IS_SYN(p_in.flags) && IS_ACK(p_in.flags)) {
						unsigned char flags = 0;
						SET_ACK(flags);
						// Ack packet
						//p_send = createPacket(connstate, 0, flags);
						p_send = createPacket(conn, 0, flags);
						MinetSend(mux, p_send);
						// Update state
						//connstate.state.SetState(ESTABLISHED);
						current_tcp_state = ESTABLISHED;
						//SockRequestResponse write (WRITE, connstate.connection, buffer, 0, EOK);
						//SockRequestResponse write (WRITE, conn, buffer, 0, EOK);
						//MinetSend(sock, write);
					}

					break;
				}

				case SYN_SENT1: {
					break;
				}

				case ESTABLISHED: {
					break;
				}

				case SEND_DATA: {
					break;
				}

				case CLOSE_WAIT: {
					break;
				}

				case FIN_WAIT1: {
					break;
				}

				case CLOSING: {
					break;
				}

				case LAST_ACK: {
					break;
				}

				case FIN_WAIT2: {
					break;
				}

				case TIME_WAIT: {
					break;
				}
			}

	    }

	    if (event.handle == sock) {
		/* Handle socket request or response */
			SockRequestResponse request;
			SockRequestResponse response;

			MinetReceive(sock, request);
			switch (request.type) {
				case CONNECT: {
					cout << "SOCK: CONNECT\n";
					/*
					Packet p;
					ConnectionToStateMapping<TCPState> mapping;
					// TCPState: LISTEN, SYN_RCVD, SYN_SENT, SYN_SENT1, ESTABLISHED, SEND_DATA, CLOSE_WAIT, FIN_WAIT1, CLOSING, LAST_ACK, DIN_WAIT2, TIME_WAIT
					// Note: TCP states represent the state AFTER the departure or arrival of the segment (RFC 793)
					// TCPState(unsigned int initialSequenceNum, unsigned int state, unsigned int timertries)
					TCPState next_tcp_state = TCPState(1, SYN_SENT, 3); // What to assign to timertries? Just put 3 because 3 way handshake l0l
					Packet packet_to_send;
					*/
					break;
				}
				case ACCEPT: {
					cout << "SOCK: ACCEPT\n";
					/*
					TCPState tcp_state(0, LISTEN, 3);
					ConnectionToStateMapping<TCPState> tcp_mapping(request.connection, Time(), tcp_state, false);
					clist.push_front(tcp_mapping);
					*/
					break;
				}
				case STATUS:
					cout << "SOCK: STATUS\n";
					// ignored, no response needed
					break;
				case WRITE:
					cout << "SOCK: WRITE\n";
					break;
				case FORWARD:
					cout << "SOCK: FORWARD\n";
					break;
				case CLOSE:
					cout << "SOCK: CLOSE\n";
					break;
				default:
					cout << "SOCK REQ/RESP\n";
			}			
	    }
	}

	if (event.eventtype == MinetEvent::Timeout) {
	    /* Handle timeout. Probably need to resend some packets */
		//cerr << "Timeout!\n";
	}

    }

    MinetDeinit();

    return 0;
}
