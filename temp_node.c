#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "dev/sys-ctrl.h"
//#include "net/ipv6/multicast/uip-mcast6.h"
//#include "net/ip/uip-debug.h"

//#undef CIPHMODE
//#define CIPHMODE		2 	//AES = 0, SkipJack = 1, Default HW Cipher = 2
#if CIPHMODE == 0
  #include "aes256.h"
  #include "sha2.h"
  #define KEYSIZE		32 	// In byte 
  #define BLOCKSIZE		16 	// In byte 
#elif CIPHMODE == 1
  #include "skipjack.c"
  #include "sha2.h"
  #define KEYSIZE		10 	// In byte
  #define BLOCKSIZE		8 	// In byte 
#elif CIPHMODE == 2
  #include "crypto-hw.h"
  #define KEYSIZE		32 	// In byte
  #define BLOCKSIZE		16 	// In byte
#endif

#include "net/uip-ds6.h"
#include "hmac_sha2.h"
#include <stdio.h>

/*
#define ENERG_EN		ENERGEST_CONF_ON 	// 0 or 1
#if ENERG_EN
  #include "sys/energest.h"
#endif
*/
#define DEBUG 			DEBUG_NONE
#define DEBUG_GREP		0
#include "net/uip-debug.h"
#define ID_LENGTH		4 	// In byte
#define MCAST_SINK_UDP_PORT	3001 	// Host byte order
#define NODE_SIZE		7
#define SUBG_SIZE		7

static uint8_t inp_dec[240];
static uint8_t counter = 1;
static uint8_t nnode = xxxx;
static uint8_t nsubg = xxxx;
static uint8_t refrKey[KEYSIZE]; 	// Refresh Key 
static uint8_t groupKey[KEYSIZE] = {xxxx};	// Group Key 
static uint8_t nodeKey[KEYSIZE] = {xxxx}; 	// Node Key 
static uint8_t subgKey[KEYSIZE] = {xxxx}; 	// Subgroup Key 
static uint32_t nodeID = xxxx;
static uint32_t subgID = xxxx;

static struct uip_udp_conn *motes_conn;
//typedef 
struct key_material{
	uint32_t	ID;
	uint8_t		Token[KEYSIZE];
};
struct key_material key_mem_node[NODE_SIZE], key_mem_subg[SUBG_SIZE];
/*---------------------------------------------------------------------------*/
PROCESS(motes_process, "Multicast Sink");
AUTOSTART_PROCESSES(&motes_process);
/*---------------------------------------------------------------------------*/
/*
static void
PRINTARR(char* title, uint8_t* arry, uint8_t size) 
{
  uint8_t i;
  printf(title);
  for (i = 0; i < size; i++)		
    printf("%02x", arry[i]);
  printf("\n");
}
*/
/*---------------------------------------------------------------------------*/
static void
key_material_init(void)
{
  // Token Backward Initiation
//here
}
/*---------------------------------------------------------------------------*/
static void
msg_dec(uint8_t* appdata, uint8_t appdataLen)
{ 
  // Initilization
  uint8_t i;
  uint8_t j;
  uint8_t record	= 99;
  uint8_t type		= appdata[0];

  // Following equation is specific to block cipher and keys length
#if ((CIPHMODE == 0) || (CIPHMODE == 2))
  uint8_t len_inp 	= 3 * BLOCKSIZE + 2 * BLOCKSIZE * ((type == 1) || (type == 3)) - 2 * BLOCKSIZE * (type == 12);
#elif CIPHMODE == 1
  uint8_t len_inp 	= 2 * BLOCKSIZE + BLOCKSIZE * ((type == 1) || (type == 3)) - BLOCKSIZE * (type == 12);
#endif
  uint32_t idtemp1;
  uint32_t idtemp2;

  // Static Data
  uint8_t staticData[32] = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};

  // Defining the key
  uint8_t key[KEYSIZE];

  // Master Token
  uint8_t MToken[KEYSIZE];

  // HMAC Output
  uint8_t hmac_output[KEYSIZE];

  // Choosing the key and data to be encrypted
  uint8_t out_dec[240];

  // Get SID
  memcpy(&idtemp1, &appdata[1], sizeof(uint32_t));

  if (idtemp1 != subgID) {
    if ((type == 1) || (type == 4) || (type == 7) || (type == 10)) return;
  }
  else {
    //if ((type == 2) || (type == 3) || (type == 5) || (type == 6)) return;
    if ((type == 2) || (type == 5) || (type == 6)) return;
  }

  // Set default encryption key
  memcpy(key, groupKey, KEYSIZE * sizeof(uint8_t));

  // Processing the message
  switch (type) {
    case 1 :	// Save JM1En
		//JM1En = 1;

		// Get nid
		memcpy(&idtemp1, &appdata[ID_LENGTH + 1], sizeof(uint32_t));

		// Check if nid is already existed
		for(i = 0; i < nnode; i++) {
    		  memcpy(&idtemp2, &key_mem_node[i].ID, sizeof(uint32_t));
  		  if (idtemp1 == idtemp2) record = 1;
  		}
  		if ((nnode > 0) && (record == 1)) return;

		// Encryption preparation
		memcpy(key, subgKey, KEYSIZE * sizeof(uint8_t));
		memcpy(inp_dec, &appdata[2 * ID_LENGTH + 1], len_inp * sizeof(uint8_t));
		break;

    case 2 :	// Same processing with DATA
    case 12 :	// Encryption preparation
		memcpy(inp_dec, &appdata[(1 + (type == 2) * ID_LENGTH)], len_inp * sizeof(uint8_t));
		break;

    case 3 :	// Check if sid is already existed
  		for(i = 0; i < nsubg; i++) {
    		  memcpy(&idtemp2, &key_mem_subg[i].ID, sizeof(uint32_t));
  		  if (idtemp1 == idtemp2) record = 1;
  		}
  		if ((nsubg > 0) && (record == 1)) return;

		// Encryption preparation
		memcpy(inp_dec, &appdata[ID_LENGTH + 1], len_inp * sizeof(uint8_t));
		break;

    case 4 :	// Get nid
		memcpy(&idtemp1, &appdata[ID_LENGTH + 1], sizeof(uint32_t));

		// Get Backward/Forward node token of nid
		for(i = 0; i < nnode; i++) {
    		  memcpy(&idtemp2, &key_mem_node[i].ID, sizeof(uint32_t));
		  if (idtemp1 == idtemp2) record = i;
		}

		if (record == 99) return;

		// Encryption preparation
		hmac_sha256(key_mem_node[record].Token, KEYSIZE, staticData, 32, key, KEYSIZE);
		if (nodeID < idtemp1) {
		  memcpy(inp_dec, &appdata[2 * ID_LENGTH + 1], len_inp * sizeof(uint8_t));
		}
		else {
#if ((CIPHMODE == 0) || (CIPHMODE == 2))
		  memcpy(inp_dec, &appdata[2 * ID_LENGTH + 3 * BLOCKSIZE + 1], len_inp * sizeof(uint8_t));
#elif CIPHMODE == 1
		  memcpy(inp_dec, &appdata[2 * ID_LENGTH + 2 * BLOCKSIZE + 1], len_inp * sizeof(uint8_t));
#endif
		}
		break;

    case 5 :	// Same processing with LM3
    case 6 :	// Get Backward/Forward subgroup token of sid
		for(i = 0; i < nsubg; i++) {
    		  memcpy(&idtemp2, &key_mem_subg[i].ID, sizeof(uint32_t));
		  if (idtemp1 == idtemp2) record = i;
  		}

		if (record == 99) return;

		// Encryption preparation
		hmac_sha256(key_mem_subg[record].Token, KEYSIZE, staticData, 32, key, KEYSIZE);

		if (subgID < idtemp1) {
		  memcpy(inp_dec, &appdata[ID_LENGTH + 1], len_inp * sizeof(uint8_t));
		}
		else {
#if ((CIPHMODE == 0) || (CIPHMODE == 2))
		  memcpy(inp_dec, &appdata[ID_LENGTH + 3 * BLOCKSIZE + 1], len_inp * sizeof(uint8_t));
#elif CIPHMODE == 1
		  memcpy(inp_dec, &appdata[ID_LENGTH + 2 * BLOCKSIZE + 1], len_inp * sizeof(uint8_t));
#endif
		}
		break;

    case 7 :	// Encryption preparation
		record = appdata[ID_LENGTH + 1];
		memcpy(&idtemp1, &appdata[ID_LENGTH + 2], sizeof(uint32_t));

		if (nodeID < idtemp1) {
		  memcpy(inp_dec, &appdata[ID_LENGTH + 2 + ID_LENGTH * record], len_inp * sizeof(uint8_t));
		}
		else {
		  memcpy(&idtemp1, &appdata[2 + ID_LENGTH * record], sizeof(uint32_t));
		  if (nodeID > idtemp1) {
#if ((CIPHMODE == 0) || (CIPHMODE == 2))
		    memcpy(inp_dec, &appdata[ID_LENGTH + 2 + 3 * BLOCKSIZE + ID_LENGTH * record], len_inp * sizeof(uint8_t));
#elif CIPHMODE == 1
		    memcpy(inp_dec, &appdata[ID_LENGTH + 2 + 2 * BLOCKSIZE + ID_LENGTH * record], len_inp * sizeof(uint8_t));
#endif
		  }
		  else return;
		}
		for(j = 0; j < nnode; j++) {
		  if (idtemp1 == key_mem_node[(j)].ID) hmac_sha256(key_mem_node[(j)].Token, KEYSIZE, staticData, 32, key, KEYSIZE);
		}
		break;
	
    case 8 :	// Encryption preparation
		memcpy(key, nodeKey, KEYSIZE * sizeof(uint8_t));
		memcpy(&inp_dec[((counter) - 1) * 63], &appdata[1 + ID_LENGTH + 2], (appdataLen - (1 + ID_LENGTH + 2)) * sizeof(uint8_t));
		if (counter == appdata[2 + ID_LENGTH]) {
		  //63 is the max bytes can be transmit, also declared in Key Manager side
		  len_inp = appdataLen - (1 + ID_LENGTH + 2) + 63 * (counter - 1); 
		  counter = 1;
		}
		else {
		  counter++;
		  return;
		}
		break;

    case 9 :	// Get sid of the oldest compromised subgroup and compare to its own Subgroup ID
		if (subgID < idtemp1) {
		  memcpy(inp_dec, &appdata[2 * ID_LENGTH + 1], len_inp * sizeof(uint8_t));
		}
		else {
		  // Get sid of the youngest compromised subgroup
		  memcpy(&idtemp1, &appdata[ID_LENGTH + 1], sizeof(uint32_t));
		  if (subgID > idtemp1) {
#if ((CIPHMODE == 0) || (CIPHMODE == 2))
		    memcpy(inp_dec, &appdata[2 * ID_LENGTH + 3 * BLOCKSIZE + 1], len_inp * sizeof(uint8_t));
#elif CIPHMODE == 1
		    memcpy(inp_dec, &appdata[2 * ID_LENGTH + 2 * BLOCKSIZE + 1], len_inp * sizeof(uint8_t));
#endif
		  }
		  else return;
		}

		// Get the encryption key
  		for(i = 0; i < nsubg; i++) {
    		  memcpy(&idtemp2, &key_mem_subg[i].ID, sizeof(uint32_t));
  		  if (idtemp1 == idtemp2) record = i;
  		}

		if (record == 99) return;

  		hmac_sha256(key_mem_subg[(record)].Token, KEYSIZE, staticData, 32, key, KEYSIZE);
		break;

    case 10 :	// Encryption preparation
		memcpy(key, subgKey, KEYSIZE * sizeof(uint8_t));
		memcpy(inp_dec, &appdata[1 + ID_LENGTH], len_inp * sizeof(uint8_t));
		break;

    case 11 :	// Encryption preparation
		record = appdata[1];
#if ((CIPHMODE == 0) || (CIPHMODE == 2))
		len_inp = 16 * (((ID_LENGTH * record) << 4) + 1);
#elif CIPHMODE == 1
		len_inp = 8 * (((ID_LENGTH * record) << 3) + 1);
#endif
		memcpy(inp_dec, &appdata[2], len_inp * sizeof(uint8_t));
		break;

    default :	return;
    }

    // AES CBC Decryption
#if CIPHMODE == 0
    aes256_decrypt_cbc(inp_dec, len_inp, key, out_dec);
#elif CIPHMODE == 1
    doSJDecrypt(key, inp_dec, len_inp, out_dec);
#elif CIPHMODE == 2
    //memcpy(out_dec, inp_dec, len_inp * sizeof(uint8_t));
    aes256_decrypt_cbc_hw(inp_dec, len_inp, key, out_dec);
#endif

    // Display the input and output of AES CBC decryption
#if DEBUG_GREP
      PRINTARR("Decryption Input: ", inp_dec, len_inp);
      PRINTARR("Decryption Key: ", key, KEYSIZE);
      PRINTARR("Decryption Output: ", out_dec, len_inp);
#endif

    // Verifying Decryption result by checking the padding
    uint8_t padlen = (uint8_t) out_dec[(len_inp) - 1];

    if (padlen > 16) {
    	printf("AES Decryption result is NOT OK with padding length %u byte(s)\n", padlen);
    	return;
    }
    // Copy the padding part of decryption result
    uint8_t padtemp1[16];
    memset(&padtemp1, 0, padlen * sizeof(uint8_t));
    memcpy(&padtemp1, &out_dec[len_inp - padlen], padlen * sizeof(uint8_t));
#if DEBUG_GREP
      PRINTARR("Result Padding1: ", padtemp1, padlen);
#endif

    // Generate the template for padding checking by copying the last byte of decryption result (X) X times
    uint8_t padtemp2[16];
    memset(&padtemp2, padlen, padlen * sizeof(uint8_t));
#if DEBUG_GREP
      PRINTARR("Result Padding2: ", padtemp2, padlen);
#endif

    int verify = memcmp(padtemp1, padtemp2, padlen * sizeof(uint8_t));
#if DEBUG_GREP
    if (verify == 0) printf("AES Decryption result is OK with padding length %u byte(s)\n", padlen);
    else printf("AES Decryption result is NOT OK with padding length %u byte(s)\n", padlen);
#endif

    // Extracting Refresh Key
    if (type == 8) memcpy(&refrKey, &out_dec[len_inp - padlen - KEYSIZE], KEYSIZE * sizeof(uint8_t));
    else memcpy(&refrKey, &out_dec[KEYSIZE * ((type == 1) || (type == 3))], KEYSIZE * sizeof(uint8_t));

    // Calculate new Group Key except for LM1. Calculation will be done when LM2 is received
    if (type != 11) {
      hmac_sha256(groupKey, KEYSIZE, refrKey, KEYSIZE, hmac_output, KEYSIZE);
      memcpy(groupKey, hmac_output, KEYSIZE * sizeof(uint8_t));
    }

    // Calculate new subgroup key
    if ((type == 1) || (type == 4) || (type == 7) || (type == 8)) {
      hmac_sha256(subgKey, KEYSIZE, refrKey, KEYSIZE, hmac_output, KEYSIZE);
      memcpy(subgKey, hmac_output, KEYSIZE * sizeof(uint8_t));
    }

    // Calculate new forward node token
    if ((type == 1) || (type == 3)) {
      memcpy(MToken, &out_dec[0], KEYSIZE * sizeof(uint8_t));
      hmac_sha256(MToken, KEYSIZE, refrKey, KEYSIZE, hmac_output, KEYSIZE);
    }


    // Post processing
    if (type == 1) {
    	// Save node nid information
      	//printf("nnode bfr %u \n", nnode);
      	memcpy(&key_mem_node[nnode].ID, &idtemp1, sizeof(uint32_t));
      	memcpy(&key_mem_node[nnode].Token, &hmac_output, KEYSIZE * sizeof(uint8_t));
      	nnode++;
      	//printf("nnode aft %u \n", nnode);
#if DEBUG_GREP
        goto print;
#else
   		return;
#endif
    }
    else if (type == 3) {
    	// Save subgroup sid information
    	memcpy(&key_mem_subg[nsubg].ID, &idtemp1, sizeof(uint32_t));
    	memcpy(&key_mem_subg[nsubg].Token, hmac_output, KEYSIZE * sizeof(uint8_t));
    	nsubg++;
#if DEBUG_GREP
    	goto print;
#else
    	return;
#endif
    }
    else if (type == 4) {
    	// Remove node nid information
		key_mem_node[(record)] = key_mem_node[(nnode--) - 1];
    	//memmove(&key_mem_node[record], &key_mem_node[record + 1], (nnode - record - 1) * (KEYSIZE + ID_LENGTH) * sizeof(uint8_t));
    	//nnode--;
    	goto stop1;
    }
    else if ((type == 5)||(type == 9)) {
        goto stop2;
    }
    else if (type == 6) {
    	// Remove subgroup sid information
    	key_mem_subg[(record)] = key_mem_subg[(nsubg--) - 1];
    	//memmove(&key_mem_subg[record], &key_mem_subg[record + 1], (nsubg - record - 1) * (KEYSIZE + ID_LENGTH) * sizeof(uint8_t));
    	//nsubg--;
    	goto stop2;
    }
    else if ((type == 7)||(type == 8)) {
        // Delete compromised nodes
    	if (type == 8) record = out_dec[0];

    	for(i = 0; i < record; i++) {
    		if (type == 7) memcpy(&idtemp1, &appdata[ID_LENGTH * (i + 1) + 2], sizeof(uint32_t));
    		else memcpy(&idtemp1, &out_dec[ID_LENGTH * (i)], sizeof(uint32_t));

    		for(j = 0; j < nnode; j++) {
    			if (idtemp1 == key_mem_node[(j)].ID) {
    				key_mem_node[(j)] = key_mem_node[(nnode--) - 1];
    			    //memmove(&key_mem_node[(j)], &key_mem_node[(j) + 1], (nnode-- - (j) - 1) * (KEYSIZE + ID_LENGTH) * sizeof(uint8_t));
    			}
    		}
    	}
    	goto stop1;
    }
    else if (type == 11) {
        // Delete compromised subgroups
    	for(i = 0; i < record; i++) {
    		memcpy(&idtemp1, &out_dec[ID_LENGTH * (i)], sizeof(uint32_t));

    		for(j = 0; j < nsubg; j++) {
    			if (idtemp1 == key_mem_subg[(j)].ID)
    				key_mem_subg[(j)] = key_mem_subg[(nsubg--) - 1];
    				//memmove(&key_mem_subg[(j)], &key_mem_subg[(j) + 1], (nsubg-- - (j) - 1) * (KEYSIZE + ID_LENGTH) * sizeof(uint8_t));
    		}
    	}
#if DEBUG_GREP
	goto print;
#else
	return;
#endif
    }
    else {
#if DEBUG_GREP
	goto print;
#else
	return;
#endif
    }

/*
    // Generating new key based on received informations
    switch (type) {
    case 1 :	// Save node nid information
  		//printf("nnode bfr %u \n", nnode);
  		memcpy(&key_mem_node[nnode].ID, &idtemp1, sizeof(uint32_t));
  		memcpy(&key_mem_node[nnode].Token, &hmac_output, KEYSIZE * sizeof(uint8_t));
  		nnode++;
  		//printf("nnode aft %u \n", nnode);
#if DEBUG_GREP
    		goto print;
#else
    		return;
#endif

    case 3 :	// Save subgroup sid information
  		memcpy(&key_mem_subg[nsubg].ID, &idtemp1, sizeof(uint32_t));
  		memcpy(&key_mem_subg[nsubg].Token, hmac_output, KEYSIZE * sizeof(uint8_t));
  		nsubg++;
#if DEBUG_GREP
    		goto print;
#else
    		return;
#endif

    case 4 :	// Remove node nid information
		memmove(&key_mem_node[record], &key_mem_node[record + 1], (nnode - record - 1) * (KEYSIZE + ID_LENGTH) * sizeof(uint8_t));
		nnode--;
		goto stop1;

    case 5: 	// Same processing with RM3
    case 9 :	goto stop2;

    case 6 :	// Remove subgroup sid information
		memmove(&key_mem_subg[record], &key_mem_subg[record + 1], (nsubg - record - 1) * (KEYSIZE + ID_LENGTH) * sizeof(uint8_t));
		nsubg--;
		goto stop2;

    case 8 :	// Delete compromised nodes
		record = out_dec[0];
		// Same processing with RM1
		break;

    case 7 :	for(i = 0; i < record; i++) {
		  if (type == 7) memcpy(&idtemp1, &appdata[ID_LENGTH * (i + 1) + 2], sizeof(uint32_t));
		  else memcpy(&idtemp1, &out_dec[ID_LENGTH * (i)], sizeof(uint32_t));
		  for(j = 0; j < nnode; j++) {
		    if (idtemp1 == key_mem_node[(j)].ID)
		      memmove(&key_mem_node[(j)], &key_mem_node[(j) + 1], (nnode-- - (j) - 1) * (KEYSIZE + ID_LENGTH) * sizeof(uint8_t));
		  }
		}
		goto stop1;

    case 11 :	// Delete compromised subgroups
		for(i = 0; i < record; i++) {
		  memcpy(&idtemp1, &out_dec[ID_LENGTH * (i)], sizeof(uint32_t));
		  for(j = 0; j < nsubg; j++) {
		    if (idtemp1 == key_mem_subg[(j)].ID)
		      memmove(&key_mem_subg[(j)], &key_mem_subg[(j) + 1], (nsubg-- - (j) - 1) * (KEYSIZE + ID_LENGTH) * sizeof(uint8_t));
		  }
		}
#if DEBUG_GREP
    		goto print;
#else
    		return;
#endif

    default:
#if DEBUG_GREP
    		goto print;
#else
    		return;
#endif
    }*/

// Calculate new forward node token
stop1:
  for(i = 0; i < nnode; i++) {
	//PRINTARR("NEW HELLO1  : ", key_mem_node[i].Token, KEYSIZE);
    memcpy(out_dec + KEYSIZE + (type == 8) * (appdataLen - (1 + ID_LENGTH + padlen + KEYSIZE)), &key_mem_node[(i)].Token, KEYSIZE * sizeof(uint8_t));
#if ((CIPHMODE == 0) || (CIPHMODE == 1))
    sha256(out_dec + (type == 8) * (appdataLen - (1 + ID_LENGTH + padlen + KEYSIZE)), 2 * KEYSIZE, key_mem_node[(i)].Token, KEYSIZE);
#elif CIPHMODE == 2
    sha256_hw(out_dec + (type == 8) * (appdataLen - (1 + ID_LENGTH + padlen + KEYSIZE)), 2 * KEYSIZE, key_mem_node[(i)].Token, KEYSIZE);
#endif
    //PRINTARR("NEW HELLO2  : ", key_mem_node[i].Token, KEYSIZE);
  }

// Calculate new forward subgroup token
stop2:
  for(i = 0; i < nsubg; i++) {
    memcpy(out_dec + KEYSIZE + (type == 8) * (appdataLen - (1 + ID_LENGTH + padlen + KEYSIZE)), &key_mem_subg[(i)].Token, KEYSIZE * sizeof(uint8_t));
#if ((CIPHMODE == 0) || (CIPHMODE == 1))
    sha256(out_dec + (type == 8) * (appdataLen - (1 + ID_LENGTH + padlen + KEYSIZE)), 2 * KEYSIZE, key_mem_subg[(i)].Token, KEYSIZE);
#elif CIPHMODE == 2
    sha256_hw(out_dec + (type == 8) * (appdataLen - (1 + ID_LENGTH + padlen + KEYSIZE)), 2 * KEYSIZE, key_mem_subg[(i)].Token, KEYSIZE);
#endif
  }

#if DEBUG_GREP
print:
  PRINTARR("New Group Key: ", groupKey, KEYSIZE);
  PRINTARR("New Subgroup Key: ", subgKey, KEYSIZE);
  PRINTARR("Refresh Key: ", refrKey, KEYSIZE);
  for(j = 0; j < nnode; j++) {
    printf("nodeTokenForwardID: %lu \n", key_mem_node[j].ID);
    PRINTARR("nodeTokenForward  : ", key_mem_node[j].Token, KEYSIZE);
  }
  for(j = 0; j < nsubg; j++) {
    printf("subgroupTokenForwardID: %lu \n", key_mem_subg[j].ID);
    PRINTARR("subgroupTokenForward  : ", key_mem_subg[j].Token, KEYSIZE);
  }
#endif
}
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  uint8_t *appdata;
  uint8_t appdataLen;

  if(uip_newdata()) {
    if(memcmp(&appdata, &uip_appdata, uip_datalen() * sizeof(uint8_t))) {
      appdata = (uint8_t *)uip_appdata;
      appdata[uip_datalen()] = 0;
      appdataLen = uip_datalen();

#if DEBUG_GREP
      PRINTARR("Buffer Data: ", appdata, appdataLen);
#endif

      msg_dec(appdata, appdataLen);
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
set_addr(void)
{
  uip_ipaddr_t addr;

  /* First, set our v6 global */
  uip_ip6addr(&addr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&addr, &uip_lladdr);
  uip_ds6_addr_add(&addr, 0, ADDR_AUTOCONF);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(motes_process, ev, data)
{
  PROCESS_BEGIN();
  NETSTACK_MAC.off(1);
/*
#if ENERG_EN
  uint32_t cpu_start_time, cpu_time;
  ENERGEST_OFF(ENERGEST_TYPE_CPU);
  ENERGEST_ON(ENERGEST_TYPE_CPU);
#endif
*/
  set_addr();
  motes_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(motes_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));
  key_material_init();

#if DEBUG_GREP
    PRINTARR("Current Group Key: ", groupKey, KEYSIZE);
    PRINTARR("Current Subgroup Key: ", subgKey, KEYSIZE);
#endif

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
/*
#if ENERG_EN
      cpu_start_time = energest_type_time(ENERGEST_TYPE_CPU);
#endif
*/
      tcpip_handler();
/*
#if ENERG_EN
      cpu_time = energest_type_time(ENERGEST_TYPE_CPU) - cpu_start_time;
      printf("Time: CPU %lu\n", cpu_time);
#endif
*/
    }
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
