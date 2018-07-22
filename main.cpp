#include <pcap.h>
#include <stdio.h>



void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
static int cnt;
void print_file(struct pcap_pkthdr* header,const u_char* packet,FILE *fp){
int sport_num=0;
int dport_num=0;

int i;
	for(i=0;i<header->len;i++){

	    	if (i<6){
		if (i==0)
		   fprintf(fp,"Destination mac : "); 
		   fprintf(fp,"%02x :",packet[i]);
		   	
		}else{
		 	if (i<12){
				if(i==6)
		   		fprintf(fp,"source mac : ");
		   		fprintf(fp,"%02x :",packet[i]);

			}else{
				if (i==12)
	    			fprintf(fp,"\n\n\n ");
				if(packet[12]==0x8 &&packet[13]==0x00){
					if(i<34&&i>25){
					if(i==26)
	    					fprintf(fp,"source ip :  ");
					if(i==30)
	    					fprintf(fp,"destination ip :  ");
			  			fprintf(fp,"%d .",packet[i]);


					}else{
						if(i>=34){
						if(packet[23]==0x06){
							if (i>=34&&i<=35){
							if(i==34){
	    						fprintf(fp,"\n\n\n ");
							fprintf(fp,"source port : ");
							sport_num =(int)(packet[i]<<8);
							}else{
								sport_num+=(int)packet[i];
			  				fprintf(fp,"%d ",sport_num);
							}
							}
							if(i>=36&&i<=37){
								if(i==36){
								fprintf(fp,"destination port : ");
								dport_num =(int)(packet[i]<<8);
								}else{
								dport_num+=(int)packet[i];
			  					fprintf(fp,"%d ",dport_num);
									
								}
							}
							if(i==37)
	    							fprintf(fp,"\n\n\n ");
							if(i>37){
			  				fprintf(fp,"%x ",packet[i]);
							if (cnt >=16)
								break;
							cnt++;
							}
						}else{
								break;
							}
						}
					
				}	
					
				}else{
					break;
				}
			}
		}
		
	    }
	    	fprintf(fp,"\n\n\n ");


}




void print_console(struct pcap_pkthdr* header,const u_char* packet){
int sport_num=0;
int dport_num=0;
cnt=0;
int i;
	for(i=0;i<header->len;i++){

	    	if (i<6){
		if (i==0)
		   printf("Destination mac : ");
		if(i!=5) 
		   printf("%02x :",packet[i]);
		else
		    printf("%02x ",packet[i]);
		   	
		}else{
		 	if (i<12){
				if(i==6)
		   		printf("source mac : ");

				if(i!=11) 
		   			printf("%02x :",packet[i]);
				else
		    			printf("%02x ",packet[i]);

			}else{
				if (i==12)
	    			printf("\n\n\n ");
				if(packet[12]==0x8 &&packet[13]==0x00){
					if(i<34&&i>25){
					if(i==26)
	    					printf("source ip :  ");
					if(i==30)
	    					printf("destination ip :  ");
					if(i!=33) 
			   			printf("%d .",packet[i]);
					else
			    			printf("%d ",packet[i]);
			  			


					}else{
						if(i>=34){
						if(packet[23]==0x06){
							if (i>=34&&i<=35){
							if(i==34){
	    						printf("\n\n\n ");
							printf("source port : ");
							sport_num =(int)(packet[i]<<8);
							}else{
								sport_num+=(int)packet[i];
			  				printf("%d ",sport_num);
							}
							}
							if(i>=36&&i<=37){
								if(i==36){
								printf("destination port : ");
								dport_num =(int)(packet[i]<<8);
								}else{
								dport_num+=(int)packet[i];
			  					printf("%d ",dport_num);
									
								}
							}
							if(i==37)
	    							printf("\n\n\n ");
							if(i>37){
			  				printf("%x ",packet[i]);
							if (cnt >=16)
								break;
							cnt++;
							}
						}else{
								break;
							}
						}
					
				}	
					
				}else{
					break;
				}
			}
		}
		
	    }
	    	printf("\n\n\n ");


}




int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

FILE *fp;

fp =fopen("test.txt","w");

  while (true) {

    	cnt=0;
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\t", header->caplen);
    
     fprintf(fp,"-----------------------------------------------\n ");
	printf("-----------------------------------------------\n ");
    	print_file(header, packet,fp);
	print_console(header, packet);
  }





  fclose(fp);
  pcap_close(handle);
  return 0;
}
