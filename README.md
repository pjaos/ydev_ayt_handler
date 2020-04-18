# Y device are you there handler
Handle the receiption of Y device are you there messages

## Introduction

Y devices respond to UDP broadcast messages that have a particular signiture.
The messages received are JSON messages and have an identifier string to indicate 
a valid sender. If this string is detected in the JSON message for AYT (are you there) key
then a function is called to send a response.
This function is provided by the caller and should send a JSON message in
reply.

### API

Only two functions are available

void init_ydev_ayt_handler(void *__send_ayt_response)
Into which the AYT message sender function pointer must be passed. After this has 
been called if a UDP message matching the signiture detailed above is received then 
the function pointer is called.

int get_ayt_msg_count(void)
This returns an integer that increments every time a valid AYT message is received.

### Example Application

#### mos.yml

#Define the configuration attributes here
```
config_schema:
  - ["ydevayth",                 "o",                                                                     {title: "Y device are you there handler"}]
  - ["ydevayth.ayt_msg",         "s", "CHANGEMECHANGEMECHANGEMECHANGEMECHANGEMECHANGEMECHANGEMECHANGEME", {title: "The Y device are you there message."}]
  - ["ydevayth.max_ayt_msg_len", "i", 64,                                                                 {title: "The maximum length of the AYT message."}]
```

#### Application

```
#include "mgos.h"
#include "ydev_ayt_handler.h"

#define IP_BUF_SIZE 16
#define JSON_BUFFER_SIZE 4096
extern  struct mg_connection *aty_response_con;
static 	char icons_gateway_ip_buf[IP_BUF_SIZE];

/**
 * Send a response to the are you there message from the ICONS gateway.
 **/
void send_ayt_response(struct mg_connection *nc) {
	const char *unit_name   = mgos_sys_config_get_user_unit_name();
  char *group_name        = (char *)mgos_sys_config_get_user_group_name();
  char *product_id        = (char *)mgos_sys_config_get_user_product_id();
  char *ip_address        = "";
  char *services  		    = "WEB:80";
  char *os  				      = "MONGOOSE_OS";
  static char sta_ip[IP_BUF_SIZE];
  static struct mgos_net_ip_info 	ip_info;
  static char    jbuf[JSON_BUFFER_SIZE];
  static struct  json_out 		out1 = JSON_OUT_BUF(jbuf, JSON_BUFFER_SIZE);
	char 					remote_addr[30];
  char 					udp_remote_addr[36];

  mg_conn_addr_to_str(nc, remote_addr, sizeof(remote_addr), MG_SOCK_STRINGIFY_REMOTE | MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT );
	snprintf(udp_remote_addr, sizeof(udp_remote_addr), "udp://%s", remote_addr);

  memset(sta_ip, 0, IP_BUF_SIZE);
  //We don't check wifiStatus == MGOS_WIFI_IP_ACQUIRED as we may miss this state during polling.
  if (mgos_net_get_ip_info(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_STA, &ip_info)) {
    if( &ip_info.ip ) {
      mgos_net_ip_to_str(&ip_info.ip, sta_ip);
    }
  }

  static char *beacon_resp_str = "{\n\
UNIT_NAME:%Q,\n\
GROUP_NAME:%Q,\n\
PRODUCT_ID:%Q,\n\
IP_ADDRESS:%Q,\n\
SERVICE_LIST:%Q,\n\
OS:%Q\n\
}";

	json_printf(&out1, beacon_resp_str, unit_name,
                                      group_name,
										                  product_id,
										                  sta_ip,
										                  services,
										                  os);

  if( aty_response_con == NULL ) {
		aty_response_con = mg_connect(mgos_get_mgr(), udp_remote_addr, NULL, NULL);
		aty_response_con->flags |= MG_F_SEND_AND_CLOSE;
	}

	if( aty_response_con != NULL ) {
		mg_send(aty_response_con, jbuf, strlen(jbuf) );
		aty_response_con = NULL;

	}

}

enum mgos_app_init_result mgos_app_init(void) {

  add_ayt_response_handler(send_ayt_response);

  return MGOS_APP_INIT_SUCCESS;
}
```

This application will return a basic JSON message to the Y IoT system.
Extra JSON key=value pairs may be added for the new device developed.


