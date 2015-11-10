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
#include <exception>
#include "tcp.h"
#include "ip.h"
#include "buffer.h"
#include "packet.h"
#include "tcpstate.h"
#include "constate.h"

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

// Extracts data from IP and TCP header and stores it in a struct
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
	PacketInfo(IPHeader ip_header, TCPHeader tcp_header) {
		// Read TCP vars
		tcp_header.GetFlags(flags);
		tcp_header.GetSeqNum(seq);
		tcp_header.GetAckNum(ack);
		tcp_header.GetSourcePort(src_port);
		tcp_header.GetDestPort(dest_port);
		tcp_header.GetHeaderLen(tcp_header_len);
		// Read IP vars
		ip_header.GetSourceIP(src_ip);
		ip_header.GetDestIP(dest_ip);
		ip_header.GetTotalLength(total_len);
		ip_header.GetHeaderLength(ip_header_len);
		// buffer
		buffer_len = total_len - tcp_header_len - ip_header_len;
	} 
	void print() {
		cout << "---------------\n";
		// Print #
		cout << "SEQ: " << seq << " ACK: " << ack << endl;
		// Print flags
		cout << "FLAGS: ";
		if  (IS_SYN(flags)|| IS_ACK(flags)) {
			if (IS_SYN(flags)) cout << "SYN";	
			if (IS_ACK(flags)) cout << "ACK";
		} else if (flags == 0) cout << "NONE";
		else cout << "N/A";
		cout << endl;
		// Print IP & ports
		cout << "SRC: " << src_ip << ":" << src_port << endl; 
		cout << "DEST: " << dest_ip << ":" << dest_port << endl; 
		// Print lengths
		cout << "TCP-LEN: " << (int) tcp_header_len << " IP-LEN: " << (int) ip_header_len << endl; 
		cout << "BUFFER-LEN: " << buffer_len << " TOTAL-LEN: " << total_len << endl;
		cout << "---------------\n";
	}
};

Packet createPacket(Connection conn, Buffer buffer, char flags, unsigned int ack, unsigned int seq) {
	Packet p(buffer);
	int payload_size = buffer.GetSize();
	int packet_size = payload_size + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;
	// Set IP header
	IPHeader ip;
	ip.SetProtocol(IP_PROTO_TCP);
	ip.SetTotalLength(packet_size);
	ip.SetSourceIP(conn.src); 		
	ip.SetDestIP(conn.dest);			
	p.PushFrontHeader(ip);
	// Set TCP header
	TCPHeader tcp;
	tcp.SetWinSize(14600, p);
	tcp.SetAckNum(ack, p);

	tcp.SetSeqNum(seq, p);
	tcp.SetSourcePort(conn.srcport, p);	
	tcp.SetDestPort(conn.destport, p); 	
	tcp.SetFlags(flags, p);
	tcp.SetHeaderLen(5, p); // Header len in WORDS
	tcp.RecomputeChecksum(p);
	p.PushBackHeader(tcp);		
	PacketInfo p_in(ip, tcp);
	cout << "Created packet...\n";
	p_in.print();
	return p;
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
    double timeout = 3;

    // ConnectionList stores a list (queue) of ConnectionToStateMappings
    ConnectionList<TCPState> conn_list;

    while (MinetGetNextEvent(event, timeout) == 0) {

		if ((event.eventtype == MinetEvent::Dataflow) && 
	    (event.direction == MinetEvent::IN)) {
	    
	    if (event.handle == mux) {
		/* Handle IP packet */

			Packet p;	
			SockRequestResponse request;
			//SockRequestResponse response;
			
			// Get packet
			MinetReceive(mux,p);

			// Extract Headers
			p.ExtractHeaderFromPayload<TCPHeader>(TCPHeader :: EstimateTCPHeaderLength(p));
			TCPHeader p_tcp = p.FindHeader(Headers :: TCPHeader); 
			p.ExtractHeaderFromPayload<IPHeader>(IPHeader :: EstimateIPHeaderLength(p));
			IPHeader p_ip = p.FindHeader(Headers :: IPHeader);

			// Copy contents of packet into convenient struct
			PacketInfo p_in(p_ip, p_tcp);
			cout << "Received packet..." << endl;
			p_in.print();

			// Get connection from packet
			Connection conn;
			conn.src = p_in.dest_ip; // src = this machine
			conn.dest = p_in.src_ip;
			conn.srcport = p_in.dest_port;
			conn.destport = p_in.src_port;
			conn.protocol = IP_PROTO_TCP;

			// Buffer
			Buffer buffer = p.GetPayload().ExtractFront(p_in.buffer_len);

			// Grab TCP state if existing connection
			unsigned int current_tcp_state;
			ConnectionList<TCPState> :: iterator conn_list_iterator = conn_list.FindMatching(conn);
 			ConnectionToStateMapping<TCPState> & conn2state = (*conn_list_iterator);
			TCPState * tcp_state;
			if (conn2state.Matches(conn)) {
 				tcp_state = &(conn2state).state;
				current_tcp_state = tcp_state->GetState();
			}

			// Else set to LISTEN
			else {
				current_tcp_state = LISTEN;
			} 


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

						// Add new conn-state mapping
						TCPState new_state(p_in.seq, SYN_RCVD, 3);
						tcp_state = &new_state;
						ConnectionToStateMapping<TCPState> c2state(conn, Time(5), *tcp_state, true); 
						conn_list.push_front(c2state);

						// Send SYN ACK
						unsigned char flags = 0;
						unsigned int ack = tcp_state->GetLastAcked() + 1;
						Buffer b;
						SET_ACK(flags);
						SET_SYN(flags);

						Packet ack_packet = createPacket(conn, b, flags, ack, 300);
						MinetSend(mux, ack_packet); // First one discarded
						MinetSend(mux, ack_packet);
					}
					break;
				}
				// Waiting for an ack after having both received & sent a conn req (host)
				case SYN_RCVD: {
					cout << "MUX: SYN_RCVD\n";

					if (IS_ACK(p_in.flags)) {
						cout << "Ack acknowledged.\n";

						// Update state
						conn_list_iterator->state.SetState(ESTABLISHED);

						conn_list_iterator->state.SetLastAcked(p_in.ack);
						conn_list_iterator->state.SetLastSent(p_in.seq + 1);
						
						//response
						SockRequestResponse response = SockRequestResponse(WRITE, conn, buffer, 0, EOK);
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
						Buffer b;
						Packet ack_packet = createPacket(conn, b, flags, conn_list_iterator->state.GetLastRecvd(), conn_list_iterator->state.GetLastSent());
						MinetSend(mux, ack_packet);

						// Update state
						conn_list_iterator->state.SetState(ESTABLISHED);

						// response
						SockRequestResponse response = SockRequestResponse(WRITE, conn, buffer, 0, EOK);
						MinetSend(sock, response);
					}

					break;
				}

				case SYN_SENT1: {
					break;
				}

				case ESTABLISHED: {
					if(IS_ACK(p_in.flags)) {
						conn_list_iterator->state.SetLastRecvd(p_in.seq);
						conn_list_iterator->state.SetLastAcked(p_in.ack);
					}

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

			ConnectionList<TCPState>::iterator conn_list_iterator = conn_list.FindMatching(request.connection);

				switch (request.type) {
					case CONNECT: {
						cout << "SOCK: CONNECT\n";

						TCPState next_tcp_state = TCPState(1, SYN_SENT, 3); // What value to assign to tiemertries?
						
						ConnectionToStateMapping<TCPState> newMap(request.connection, Time(5), next_tcp_state, true); 
						conn_list.push_front(newMap);

						unsigned char flags = 0;
						SET_SYN(flags);

						// Syn Packet
						Buffer b;
						Packet send = createPacket(newMap.connection, b, flags, conn_list_iterator->state.GetLastRecvd(), conn_list_iterator->state.GetLastSent());
						MinetSend(mux, send);
						MinetSend(mux, send);

						break;
					}
					case ACCEPT: {
						cout << "SOCK: ACCEPT\n";

						TCPState next_tcp_state = TCPState(1, LISTEN, 3); // What value to assign to tiemertries?

						ConnectionToStateMapping<TCPState> newMap(request.connection, Time(5), next_tcp_state, true); 
						conn_list.push_front(newMap);

						break;
					}
					case STATUS:
						cout << "SOCK: STATUS\n";
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
		//cerr << "Timed out\n";
	}

    }

    MinetDeinit();

    return 0;
}
