#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define DAEMON_NAME "deal"

int quit = 0;


static void sigint_handler(int sig){
	syslog (LOG_NOTICE,"Received signal %d ",sig);
	quit = 1;
}

static void scanBluetooth(){
	int sock = 0;
	struct hci_filter flt;
	inquiry_cp cp;
	write_inquiry_mode_cp cp1;
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	hci_event_hdr *hdr;
	char canceled = 0;
	inquiry_info_with_rssi *info_rssi;
	inquiry_info *info;
	int results, i, len;
	struct pollfd p;
	char name[248] = { 0 };

//	dev_id = hci_get_route(NULL);
	syslog(LOG_NOTICE,"Opening socket on hci%d for bluetooth scanning",dev_id);
	sock = hci_open_dev( dev_id );
	if (dev_id < 0 || sock < 0) {
		syslog(LOG_NOTICE,"Can't open socket for bluetooth scanning");
		quit = 1;
		return;
	}

	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_set_event(EVT_INQUIRY_RESULT, &flt);
	hci_filter_set_event(EVT_INQUIRY_RESULT_WITH_RSSI, &flt);
	hci_filter_set_event(EVT_INQUIRY_COMPLETE, &flt);
syslog(LOG_NOTICE,"applying filter");
	if (setsockopt(sock, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		syslog(LOG_NOTICE,"BT: Can't set HCI filter");
		close(sock);
		return;
	}
while(!quit){
	cp1.mode = 1;
	if (hci_send_cmd(sock, OGF_HOST_CTL, OCF_WRITE_INQUIRY_MODE, WRITE_INQUIRY_MODE_CP_SIZE, &cp1) < 0) {

		syslog(LOG_NOTICE,"BT: Can't set inquiry mode");
		close(sock);
		return;
	}

	memset (&cp, 0, sizeof(cp));
	cp.lap[2] = 0x9e;
	cp.lap[1] = 0x8b;
	cp.lap[0] = 0x33;
	cp.num_rsp = 0;
	cp.length = Length;

//	syslog(LOG_NOTICE,"Starting inquiry with RSSI...\n");


	if (hci_send_cmd (sock, OGF_LINK_CTL, OCF_INQUIRY, INQUIRY_CP_SIZE, &cp) < 0) {

		syslog(LOG_NOTICE,"BT: Can't start inquiry");
		close(sock);
		return;
	}

	p.fd = sock;
	p.events = POLLIN | POLLERR | POLLHUP;
	canceled = 0;
	while(!canceled) {
		p.revents = 0;

		/* poll the BT device for an event */
		if (poll(&p, 1, -1) > 0) {
			len = read(sock, buf, sizeof(buf));

			if (len < 0)
				continue;
			else if (len == 0)
				break;

			hdr = (void *) (buf + 1);
			ptr = buf + (1 + HCI_EVENT_HDR_SIZE);

			results = ptr[0];

			switch (hdr->evt) {
				case EVT_INQUIRY_RESULT:
					for (i = 0; i < results; i++) {
						info = (void *)ptr + (sizeof(*info) * i) + 1;
//						print_result(&info->bdaddr, 0, 0);
					}
					break;

				case EVT_INQUIRY_RESULT_WITH_RSSI:
					for (i = 0; i < results; i++) {
						info_rssi = (void *)ptr + (sizeof(*info_rssi) * i) + 1;
						add_device_to_list(info_rssi);
					}
					break;

				case EVT_INQUIRY_COMPLETE:
					canceled = 1;
					break;
			}
		}
	}//while(!cancelled)
	//syslog(LOG_NOTICE,"Inquiry complete...\n");

	
	} //while(!quit)
	close(sock);

}
//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////// wifi functions //////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
void addWIFIDevice(const u_char *packet){
	int lengthOfAPString,i,j;
	long current_time;
	char name[31];
	int8_t rssi;
	WIFIDevice *curr;
	WIFIDevice *tcurr;
	openFile();
	lengthOfAPString = packet[0x2b];
	i = 1;
	if ( lengthOfAPString > 0 ){
		if( lengthOfAPString > MaxLengthOfAP-1 )
				lengthOfAPString = MaxLengthOfAP - 1;
		for(i = 0, j = 0x2c; i < lengthOfAPString; i++,j++){
			name[i] = packet[j];
		}
		name[i]=0;
	}
	else 
		name[0] = 0;

	current_time = time(NULL);
	fwrite(&current_time,sizeof(long),1,fptr);
	fwrite(&packet[0x1c],1,6,fptr);
	rssi = packet[0x0e] - 256;
	fwrite(&rssi,sizeof(int8_t),1,fptr);
	fwrite(name,sizeof(char),i,fptr);
	fputc(fptr,0);
	curr = (WIFIDevice *) malloc(sizeof(WIFIDevice));
	if (curr){
		memcpy(curr->mac,&packet[0x1c],6);
		strcpy(curr->AP,name);
		curr->date_time = current_time;
		curr->rssi = rssi;
		curr->next = NULL;
		pthread_mutex_lock(&WIFIDmutex);
		tcurr = firstOnSend;
		if( NULL != tcurr ){
			while( tcurr->next ){
				tcurr = tcurr->next;
			}
			tcurr->next = curr;
		} else {
			firstOnSend = curr;
		}
		pthread_mutex_unlock(&WIFIDmutex);
	}

}
void data_received(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet){
	int i=0; 
	int j = 0;
	char name[50];
	memset(name,0,50);
	
	if( header->len > 0x2b ){
		addWIFIDevice(packet);
	}
}

static void scanWifi(){
		
		char dev[] = "mon0";			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "type mgt subtype probe-req";	/* The filter expression */
		bpf_u_int32 mask = 0;		/* Our netmask */
		bpf_u_int32 net = 0;		/* Our IP *ave to cast it ourselves, according to our needs in the callback function).*/
		const u_char *packet;		/* The actual packet */
		/* Define the device */
//		dev = pcap_lookupdev(errbuf);
		memset(errbuf,0x00,sizeof(errbuf));
		/* Open the session in promiscuous mode */

		
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "WIFI: Couldn't open device %s: %s\n",dev, errbuf);
			return(2);
		}
		/* Compile and apply the filter */

		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "WIFI: Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}

		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "WIFI: Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		/* Grab a packet */
//		while(!quit)
		
		
		pcap_loop(handle, 0, data_received, NULL);
//		packet = pcap_next(handle, &header);
		/* Print its length */
		/* And close the session */
		pcap_freecode(&fp);
		pcap_close(handle);
		return(0);

}

//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////// BLE functions ///////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////


static void scanBLE(){

}

int main(int argc, char *argv[]) {	

	pid_t pid, sid;
	pthread_t bluetoothThread;
	pthread_t bleThread;
	pthread_t wifiThread;
    //Set our Logging Mask and open the Log
    //setlogmask(LOG_UPTO(LOG_NOTICE));
    openlog(DAEMON_NAME, LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = 0;
	sa.sa_handler = sigint_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

    
#ifdef DEMONIZE
   //Fork the Parent Process
    pid = fork();

    if (pid < 0) { exit(EXIT_FAILURE); }

    //We got a good pid, Close the Parent Process
    if (pid > 0) { exit(EXIT_SUCCESS); }
    //Change File Mask
   umask(0);

    //Create a new Signature Id for our child
    sid = setsid();
    if (sid < 0) { exit(EXIT_FAILURE); }

    //Change Directory
    //If we cant find the directory we exit with failure.
    if ((chdir("/")) < 0) { exit(EXIT_FAILURE); }

    //Close Standard File Descriptors

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

#endif

	
	quit = 0;

	rc = pthread_create(&bluetoothThread,NULL,scanBluetooth,NULL);
	if (rc){
		syslog (LOG_NOTICE,"Cannot create thread for scanning bluetooth");
		quit = 1;
	} else {
		syslog (LOG_NOTICE,"Bluetooth Thread started");
	}

	rc = pthread_create(&bleThread,NULL,scanBLE,NULL);
	if (rc){
		syslog (LOG_NOTICE,"Cannot create thread for scanning BLE");
		quit = 1;
	} else {
		syslog (LOG_NOTICE,"BLE Thread started");
	}

	rc = pthread_create(&wifiThread,NULL,scanWifi,NULL);
	if (rc){
		syslog (LOG_NOTICE,"Cannot create thread for scanning Wifi");
		quit = 1;
	} else {
		syslog (LOG_NOTICE,"Wifi Thread started");
	}

	while(!quit){
	}

	syslog (LOG_NOTICE, "exiting" );
	
	exit(0);
}
