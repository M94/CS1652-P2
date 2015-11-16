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
#include <stdlib.h>

using namespace std;

// Extracts data from IP and TCP header and stores it in a struct
struct PacketInfo {
	unsigned int seq;
	unsigned int ack;
	unsigned char flags;
	unsigned char tcp_header_len; // words
	unsigned char ip_header_len; // words
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
		// Read payload size
		buffer_len = total_len - (int) (tcp_header_len * 4) - (int) (ip_header_len * 4);
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
		cout << "TCP-LEN: " << (int) tcp_header_len * 4 << "B IP-LEN: " << (int) ip_header_len * 4 << "B" << endl; 
		cout << "BUFFER-LEN: " << buffer_len << "B TOTAL-LEN: " << total_len <<  "B" << endl;
		cout << "---------------\n";
	}
	void printShort() {
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
		cout << "\n---------------\n";
	}
	void printMsg(char * msg) {
		cout << msg << " ";
		if (IS_SYN(flags)) cout << "SYN-";
		if (IS_ACK(flags)) cout << "ACK-";
		cout << seq << "-" << ack;
		if (buffer_len > 0) cout << " (" << buffer_len << "B)";
		cout << endl;
	}
};

Packet createPacket(Connection conn, Buffer buffer, char flags, unsigned int ack, unsigned int seq, unsigned int payload_size) {
	Packet p(buffer);
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
	p_in.printMsg("Created");
	return p;
}

void printBuffer(Buffer &buffer) {
	unsigned int size = buffer.GetSize();
	char buf[size + 1];
	buf[size] = '\0';
	buffer.GetData(buf, size, 0);
	cout << "Buffer: " << buf << endl;
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
			Packet p_send;	
			
			// Get packet
			MinetReceive(mux,p);

			// Extract Headers
			p.ExtractHeaderFromPayload<TCPHeader>(TCPHeader :: EstimateTCPHeaderLength(p));
			TCPHeader p_tcp = p.FindHeader(Headers :: TCPHeader); 
			p.ExtractHeaderFromPayload<IPHeader>(IPHeader :: EstimateIPHeaderLength(p));
			IPHeader p_ip = p.FindHeader(Headers :: IPHeader);

			// Copy contents of packet into convenient struct
			PacketInfo p_in(p_ip, p_tcp);
			p_in.printMsg("Received");

			// Get connection from packet
			Connection conn;
			conn.src = p_in.dest_ip; // src = this machine
			conn.dest = p_in.src_ip;
			conn.srcport = p_in.dest_port;
			conn.destport = p_in.src_port;
			conn.protocol = IP_PROTO_TCP;

			// Get buffer from packet
			Buffer buffer = p.GetPayload().ExtractFront(p_in.buffer_len);

			// Grab TCP state if existing connection
			unsigned int current_tcp_state;
			ConnectionList<TCPState> :: iterator conn_list_iterator = conn_list.FindMatching(conn);
 			ConnectionToStateMapping<TCPState> & conn2state = (*conn_list_iterator);
			TCPState * tcp_state;
			if (conn2state.Matches(conn)) {
 				tcp_state = &conn_list_iterator->state;
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
				// Waiting connection request from any remote TCP & port (host)
				// (PASSIVE OPEN)
				case LISTEN: {
					cout << "MUX: LISTEN\n";
					if (IS_SYN(p_in.flags) && !IS_ACK(p_in.flags)) {
						cout << "Conn request received.\n";
						// New TCPState
						TCPState new_state(p_in.seq, SYN_RCVD, 3);
						tcp_state = &new_state;
						tcp_state->SetLastRecvd(p_in.seq);
						// Send SYN ACK
						unsigned char flags = 0;
						unsigned int ack = p_in.seq + 1;		// Next seq expected from client
						unsigned int server_isn = rand() % 300; 	// Server initial seq # 
						Buffer b;
						SET_ACK(flags);
						SET_SYN(flags);
						p_send = createPacket(conn, b, flags, ack, server_isn, 0); 
						MinetSend(mux, p_send); // First one discarded
						MinetSend(mux, p_send);
						// Update state for sent packet
						tcp_state->SetLastSent(server_isn);
						if (!tcp_state->SetLastAcked(ack)) cout << "Error setting LastAcked\n";
						// Push new state mapping
						ConnectionToStateMapping<TCPState> c2state(conn, Time(5), *tcp_state, true); 
						conn_list.push_front(c2state);
					}
					break;
				}
				// Waiting for an ack after having both received & sent a conn req (host)
				// Do not respond...
				case SYN_RCVD: {
					cout << "MUX: SYN_RCVD\n";

					if (IS_ACK(p_in.flags)) {
						// Update state for received packet
						tcp_state->SetLastRecvd(p_in.seq);
						
						// Socket response
						SockRequestResponse response = SockRequestResponse(WRITE, conn, buffer, 0, EOK);
						MinetSend(sock, response);

						// TCP state transition
						tcp_state->SetState(ESTABLISHED);

						cout << "Handshake done.\n";
					}
					break;
				}
				// Represents waiting for a matching conn request after having sent one (client)
				case SYN_SENT: {
					cout << "MUX: SYN_SENT\n";
					if(IS_SYN(p_in.flags) && IS_ACK(p_in.flags)) {
						unsigned int lastRecvd = tcp_state->GetLastRecvd();
						unsigned int lastAcked = tcp_state->GetLastAcked();
						unsigned int lastSent = tcp_state->GetLastSent();

						// Update state for received packet
						tcp_state->SetLastRecvd(p_in.seq);

						// Ack packet
						unsigned char flags = 0;
						SET_ACK(flags);
						unsigned int ack = p_in.seq + 1;
						unsigned int seq = p_in.ack;
						Buffer b;
						p_send = createPacket(conn, b, flags, ack, seq, 0);
						MinetSend(mux, p_send);

						// Update state for sent packet
						if (!tcp_state->SetLastAcked(ack)) cout << "Error setting LastAcked\n";
						tcp_state->SetLastSent(seq);

						// Socket response
						SockRequestResponse response = SockRequestResponse(WRITE, conn, buffer, 0, EOK);
						MinetSend(sock, response);

						// TCP state transition
						tcp_state->SetState(ESTABLISHED);

						cout << "Handshake done.\n";
					}

					break;
				}

				case SYN_SENT1: {
					cout << "MUX: SYN_SENT1\n";
					break;
				}

				case ESTABLISHED: {
					cout << "MUX: ESTABLISHED\n";
					if(IS_ACK(p_in.flags)) {
						// Updated state for received packet
						tcp_state->SetLastRecvd(p_in.seq);

						unsigned int lastRecvd = tcp_state->GetLastRecvd();
						unsigned int lastAcked = tcp_state->GetLastAcked();
						unsigned int lastSent = tcp_state->GetLastSent();

						// Handle connection close
						if (IS_FIN(p_in.flags)) {
							cout << "Close request recvd" << endl;
							tcp_state->SetState(CLOSE_WAIT);
						}

						// Ack packet
						{ 
							// Send ack
							unsigned char flags = 0;
							unsigned int ack = p_in.seq + p_in.buffer_len; // Move ack fwd by data len recvd
							unsigned int seq = p_in.ack; 
							SET_ACK(flags);
							p_send = createPacket(conn, buffer, flags, ack, seq, p_in.buffer_len); 	// Echo back buffer
							MinetSend(mux, p_send);
							// Update state for sent packet
							if (!tcp_state->SetLastAcked(ack)) cout << "Error setting LastAcked\n";
							tcp_state->SetLastSent(seq);
						}
							
					}
					// Forward data to socket
					//SockRequestResponse request = SockRequestResponse(WRITE, conn, buffer, p_in.buffer_len, EOK);
					//MinetSend(sock, request);
					break;
				}

				case SEND_DATA: {
					cout << "SEND_DATA\n";
					break;
				}
				// Send FIN after sending ack for close (host)
				case CLOSE_WAIT: {
					cout << "MUX: CLOSE_WAIT\n";
					// Send FIN 
					unsigned int lastSent = tcp_state->GetLastSent();
					unsigned char flags = 0;
					unsigned int ack = 0; 
					unsigned int seq = lastSent + 1; 
					SET_FIN(flags);
					Buffer b;
					p_send = createPacket(conn, b, flags, ack, seq, 0);
					MinetSend(mux, p_send);	
					// Update state for sent packet
					if (!tcp_state->SetLastAcked(ack)) cout << "Error setting LastAcked\n";
					tcp_state->SetLastSent(seq);	
					// TCP state transition
					tcp_state->SetState(LAST_ACK);
									
					break;
				}

				// Receive ack, send nothing (client)
				case FIN_WAIT1: {
					cout << "MUX: FIN_WAIT1\n";
					if (IS_ACK(p_in.flags)) {
						// TCP state transition
						tcp_state->SetState(FIN_WAIT2);
					}
					break;
				}

				case CLOSING: {
					cout << "MUX: CLOSING\n";
					break;
				}

				// Receive last ack & close (host)
				case LAST_ACK: {
					cout << "MUX: LAST_ACK\n";
					if (IS_ACK(p_in.flags)) {
						// Close connection
						conn_list.erase(conn_list_iterator);
						cout << "Connection closed." << endl;	
					}
					break;
				}

				// Receive fin, send ack (client)
				case FIN_WAIT2: {
					cout << "MUX: FIN_WAIT2\n";
					if (IS_FIN(p_in.flags)) {
						// Send ack
						unsigned char flags = 0;
						unsigned int ack = p_in.seq + p_in.buffer_len; // Move ack fwd by data len recvd
						unsigned int seq = p_in.ack; 
						SET_ACK(flags);
						p_send = createPacket(conn, buffer, flags, ack, seq, p_in.buffer_len); 	// Echo back buffer
						MinetSend(mux, p_send);
						// Update state for sent packet
						if (!tcp_state->SetLastAcked(ack)) cout << "Error setting LastAcked\n";
						tcp_state->SetLastSent(seq);
						// TCP state transition
						tcp_state->SetState(TIME_WAIT);
					}
					break;
				}

				// Receive fin, wait 30 sec, and close (client)
				case TIME_WAIT: {
					cout << "MUX: TIME_WAIT\n";
					
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
 			ConnectionToStateMapping<TCPState> & conn2state = (*conn_list_iterator);
			// Grab TCP state if possible
			TCPState * tcp_state;
			if (conn2state.Matches(request.connection)) {
 				tcp_state = &conn_list_iterator->state;
			}

				switch (request.type) {
					// Send connection request (ACTIVE OPEN) (client)
					case CONNECT: {
						cout << "SOCK: CONNECT\n";

						// Send SYN 
						unsigned char flags = 0;
						SET_SYN(flags);
						unsigned int ack = 0;
						unsigned int client_isn = rand() % 300; 	// Client initial seq
						Buffer b;
						Packet send = createPacket(request.connection, b, flags, ack, client_isn, 0);
						MinetSend(mux, send); // First is discarded
						sleep(2);
						MinetSend(mux, send);

						// New TCPState
						TCPState new_state(client_isn, SYN_SENT, 3); // What value to assign to timertries?
						// Update TCPState
						new_state.SetLastAcked(ack);
						new_state.SetLastSent(client_isn);
						// Push TCPState
						ConnectionToStateMapping<TCPState> new_map(request.connection, Time(5), new_state, true); 
						conn_list.push_front(new_map);
						break;
					}
					// Accept connection request (PASSIVE OPEN) (host)
					case ACCEPT: {
						cout << "SOCK: ACCEPT\n";

						TCPState next_tcp_state = TCPState(1, LISTEN, 3); // What value to assign to timertries?

						ConnectionToStateMapping<TCPState> newMap(request.connection, Time(5), next_tcp_state, true); 
						conn_list.push_front(newMap);
						
						break;
					}
					case STATUS:
						cout << "SOCK: STATUS\n";
						break;
					// Send data packet					
					case WRITE:
						/*
						cout << "SOCK: WRITE\n";
 						TCPState * tcp_state = &conn_list_iterator->state;
						unsigned int lastRecvd = tcp_state->GetLastRecvd();
						unsigned int lastAcked = tcp_state->GetLastAcked();
						unsigned int lastSent = tcp_state->GetLastSent();
						// Send packet
						unsigned char flags = 0;
						SET_ACK(flags);
						unsigned int ack = lastRecvd + 1;	// Next seq expected from client
						unsigned int seq = lastSent + 1; 	// Initial seq
						Buffer data = request.data;
						Packet send = createPacket(request.connection, data, flags, ack, seq);
						MinetSend(mux, send);
						// Update TCPState
						tcp_state->SetLastAcked(ack);
						tcp_state->SetLastSent(seq);
				*/
						break;
					case FORWARD:
						cout << "SOCK: FORWARD\n";
						break;
					// Send close request (client)
					case CLOSE: {
						cout << "SOCK: CLOSE\n";
						// Send FIN 
						unsigned char flags = 0;
						unsigned int ack = 0; 
						unsigned int seq = rand() % 300; 
						SET_FIN(flags);
						Buffer b;
						Packet fin = createPacket(request.connection, b, flags, ack, seq, 0);
						MinetSend(mux, fin);	
						// Update state for sent packet
						if (!tcp_state->SetLastAcked(ack)) cout << "Error setting LastAcked\n";
						tcp_state->SetLastSent(seq);		
						break;

					}
					default:
						cout << "SOCK REQ/RESP\n";
				} 
	    }
	}

	if (event.eventtype == MinetEvent::Timeout) {
	    /* Handle timeout. Probably need to resend some packets */
		//cout << "Timed out, resending packet\n";
		//MinetSend(mux, p_send);
	}

    }

    MinetDeinit();

    return 0;
}
