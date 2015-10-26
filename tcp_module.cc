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

using namespace std;

struct TCPState {
    // need to write this
    std::ostream & Print(std::ostream &os) const { 
	os << "TCPState()" ; 
	return os;
    }
};


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

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module auc5 handling tcp traffic........"));

    MinetEvent event;
    double timeout = 1;

    while (MinetGetNextEvent(event, timeout) == 0) {

	if ((event.eventtype == MinetEvent::Dataflow) && 
	    (event.direction == MinetEvent::IN)) {
	    
	    if (event.handle == mux) {
		/* Handle IP packet */
			Packet p;
			unsigned short len;
			bool checksumok;
			MinetReceive(mux,p);
			Buffer payload = p.GetPayload();
			cerr << payload.GetSize();
			cerr << "B IP packet\n";
	    }

	    if (event.handle == sock) {
		/* Handle socket request or response */
			SockRequestResponse req
			MinetReceive(sock, req);
			switch (req.type) {
				case CONNECT:
				
					break;
				case ACCEPT:

					break;
				case STATUS:
				  // ignored, no response needed
				  break;
				case WRITE:
				  break;
				case FORWARD:
				  
					break;
				case CLOSE:
					break;
				default:

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
