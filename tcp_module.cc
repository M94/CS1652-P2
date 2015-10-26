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


int main(int argc, char * argv[]) {
    MinetHandle mux;
    MinetHandle sock;
    
    ConnectionList<TCPState> clist;

    MinetInit(MINET_TCP_MODULE);

    mux = MinetIsModuleInConfig(MINET_IP_MUX) ?  
	MinetConnect(MINET_IP_MUX) : 
	MINET_NOHANDLE;
    
    sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? 
	MinetAccept(MINET_SOCK_MODULE) : 
	MINET_NOHANDLE;

    if ( (mux == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_IP_MUX)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));

	return -1;
    }

    if ( (sock == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));

	return -1;
    }
    
    cerr << "tcp_module auc5 handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module auc5|cmn26 handling tcp traffic........"));

    MinetEvent event;
    double timeout = 1;

    while (MinetGetNextEvent(event, timeout) == 0) {

	if ((event.eventtype == MinetEvent::Dataflow) && 
	    (event.direction == MinetEvent::IN)) {
	    
	    if (event.handle == mux) {
		/* Handle IP packet */

	    	/* Packet class includes methods for extracting portions of the payload */
			Packet p;	// Consists of a list of packet Headers, a Buffer that represents the payload of the packet, and a list of packet Trailers
			unsigned short len;	// Packet length
			bool checksumok;
			TCPHeader tcp_header; // TCPHeader - wraps the raw data of a TCP header into a convenient abstraction
			IPHeader ip_header;	// IPHeader - provides convenient access to the fields of an IPv4 header

			// However, it is possible to extract raw data from the headers, payload, and trailers of a packet
			MinetReceive(mux,p);

			// The size of a TCP Header is 20 bytes.. I think
			p.ExtractHeaderFromPayload<TCPHeader>(20);

			// virtual Header FindHeader(Headers::HeaderType ht) const;
			tcp_header = p.FindHeader(Headers :: TCPHeader);
			ip_header = p.FindHeader(Headers :: IPHeader);
			
			// TCP header vars
			unsigned char tcp_flags;
			tcp_header.GetFlags(tcp_flags);

			// bool IsCorrectChecksum(const Packet &p) const;
			checksumok = tcp_header.IsCorrectChecksum(p);

			Connection conn;
			// ConnectionList stores a list (queue) of ConnectionToStateMappings
			ConnectionList<TCPState> :: iterator connections_iterator = clist.FindMatching(conn);
			// ConnectionToStateMapping maps connection addresses to TCP connection state (TCPState)
			ConnectionToStateMapping<TCPState> & connstate = (*connections_iterator);

			// Grabs current TCP state
			unsigned int current_tcp_state = (connstate).state.GetState();

			switch(current_tcp_state) {
				// Waiting connection request from any remote TCP & port
				// Handle passive open
				case LISTEN: {
					cout << "LISTEN\n";
					if (IS_SYN(tcp_flags)) {
						cout << "Conn request received.\n";
						// Update state
						connstate.state.SetState(SYN_RCVD);
						connstate.connection = conn;
						// Send SYN ACK
						cout << "Sending ack...\n";
						unsigned char flags = 0;
						SET_ACK(flags);
						Packet ack_packet = createPacket(connstate, 0, flags);
						MinetSend(mux, ack_packet);
					}
					break;
				}
				// Waiting for an ack after having both received & sent a conn req
				case SYN_RCVD: {
					cout << "SYN_RCVD\n";
					if (IS_ACK(tcp_flags)) {
						cout << "Ack acknowledged.\n";
						// Update state
						connstate.state.SetState(ESTABLISHED);
					}
					break;
				}
				// Represents waiting for a matching conn request after having sent one
				case SYN_SENT: {
					cout << "SYN_SENT\n";
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
					/*
					cerr << "CONNECT\n";
				
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

				case ACCEPT:
				cerr << "ACCEPT\n";
					break;
				case STATUS:
				cerr << "STATUS\n";
				  // ignored, no response needed
				  break;
				case WRITE:
				cerr << "WRITE\n";
				  break;
				case FORWARD:
				cerr << "FORWARD\n";
					break;
				case CLOSE:
				cerr << "CLOSE\n";
					break;
				default:
				cerr << "SOCK REQ/RESP\n";
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
