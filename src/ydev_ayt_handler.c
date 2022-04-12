#include "mgos.h"
#include "mgos_wifi.h"
#include "mgos_syslog.h"
#include "ydev_ayt_handler.h"

//The function pointer passed when the ayt handler was inited
static void (*_send_ayt_response)(struct mg_connection *nc);

struct mg_connection *aty_response_con;
static int ayt_msg_count;
static struct mg_connection *udp_bcast_rx_con;

#define ADDR_PORT_BUF_SIZE 30

static char gateway_ip_addr_port[ADDR_PORT_BUF_SIZE];
static char gateway_ip_addr[ADDR_PORT_BUF_SIZE];

/**
 * @brief Get the number of are you there (AYT) messages that this device has received.
 * @return The AYT message count
 */
int mgos_get_ayt_msg_count(void) {
	return ayt_msg_count;
}

/**
 * @brief Convert an IP address from 32 bit value to string.
 * @param ip The IP as a 32 bit value.
 * @param ip_buf The buffer to hold the string.
 * @param ip_buf_len The length of the IP buffer.
 * @return void.
 */
void ip_to_str(uint32_t ip, char *ip_buf, int ip_buf_len) {
    int a,b,c,d;
    a = ip&0xff;
    b = (ip>>8)&0xff;
    c = (ip>>16)&0xff;
    d = (ip>>24)&0xff;
    snprintf(ip_buf, ip_buf_len, "%d.%d.%d.%d", a,b,c,d);
}

static bool init_syslog = true;
#define IP_BUF_LEN 16
#define SYSLOG_MSG_BUF_SIZE 256

/**
 * @brief Check is a connection is from a host on the local subnet.
 * @param nc An mg_connection instance.
 * @return true if connection is from the local subnet as is not the default gateway.
 */
static bool con_inside_local_subnet(struct mg_connection *nc) {
    static char src_ip_str_buf[IP_BUF_LEN];
    static char local_ip_str_buf[IP_BUF_LEN];
    static char netmask_ip_str_buf[IP_BUF_LEN];
    static char syslog_msg_buf[SYSLOG_MSG_BUF_SIZE];

    bool _con_from_local_subnet = false;
    struct mgos_net_ip_info ip_info;


    if (mgos_net_get_ip_info(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_STA, &ip_info)) {
        if( &ip_info.ip ) {
            uint32_t src_ip = nc->sa.sin.sin_addr.s_addr;
            uint32_t local_ip = ip_info.ip.sin_addr.s_addr;
            uint32_t netmask_ip = ip_info.netmask.sin_addr.s_addr;
            uint32_t mask_ip1 = local_ip & netmask_ip;
            uint32_t mask_ip2 = src_ip &netmask_ip;

            memset(src_ip_str_buf, 0, IP_BUF_LEN);
            memset(local_ip_str_buf, 0, IP_BUF_LEN);
            memset(netmask_ip_str_buf, 0, IP_BUF_LEN);

            ip_to_str(local_ip, local_ip_str_buf, IP_BUF_LEN);
            ip_to_str(src_ip, src_ip_str_buf, IP_BUF_LEN);
            ip_to_str(netmask_ip, netmask_ip_str_buf, IP_BUF_LEN);

            if( init_syslog ) {
                reinit_syslog(src_ip_str_buf, "");
                init_syslog=false;
            }

            //If the src address of the connection is on the same subnet this device.
            if( mask_ip1 == mask_ip2 ) {
                _con_from_local_subnet = true;
            }
            memset(syslog_msg_buf, 0, SYSLOG_MSG_BUF_SIZE);
            snprintf(syslog_msg_buf, SYSLOG_MSG_BUF_SIZE, "local_ip: %s, src_ip: %s, netmask: %s\n", local_ip_str_buf, src_ip_str_buf, netmask_ip_str_buf);
            mgos_syslog_log_info(__FUNCTION__, syslog_msg_buf);

            //Report the memory usage as this is useful for detecting memory leaks
            memset(syslog_msg_buf, 0, SYSLOG_MSG_BUF_SIZE);
            snprintf(syslog_msg_buf, SYSLOG_MSG_BUF_SIZE, "uptime: %.2lf, RAM: %lu, %lu free", mgos_uptime(), (unsigned long) mgos_get_heap_size(), (unsigned long) mgos_get_free_heap_size());
            mgos_syslog_log_info(__FUNCTION__, syslog_msg_buf);

        }
        else {
            mgos_syslog_log_info(__FUNCTION__, "Failed to read device IP address");
        }
    }
    else {
        mgos_syslog_log_info(__FUNCTION__, "Failed to get device IP info.");
    }

    if( _con_from_local_subnet ) {
        mgos_syslog_log_info(__FUNCTION__, "Connection from within local subnet.");
    }
    else {
        mgos_syslog_log_info(__FUNCTION__, "Connection outside local subnet.");
    }

    return _con_from_local_subnet;
}

/**
 * @brief Handle UDP broadcast RX messages (I.E ICONS messages)
 * @param mg_connection
 * @param ev
 * @param ev_data
 * @param user_data
 */
static void udp_broadcast_handler(struct mg_connection *nc, int ev, void *ev_data, void *user_data) {
    struct mbuf *io = &nc->recv_mbuf;
    char *ydev_hashtag = (char *)mgos_sys_config_get_ydevayth_hashtag();

    if( ev == MG_EV_RECV ) {
        char *ayt_id_str = NULL;
        char *rx_str = malloc(io->len+1);

        memcpy(rx_str, io->buf, io->len);
        if( rx_str != NULL ) {
            rx_str[io->len]=0;

            json_scanf(rx_str, io->len, "{AYT:%Q}", &ayt_id_str);

            //If we have an ICONS AYT message
            if( ayt_id_str != NULL && strlen(ayt_id_str) ) {
                //If we have a null pointer then no hashtag has been learnt
                if( !ydev_hashtag ) {
                    ydev_hashtag = malloc(strlen(ayt_id_str)+1);
                    if( ydev_hashtag ) {
                        strncpy(ydev_hashtag, ayt_id_str, strlen(ayt_id_str)+1);
                        mgos_sys_config_set_ydevayth_hashtag(ydev_hashtag);
                        save_cfg(&mgos_sys_config, NULL);
                        free(ydev_hashtag);
                        ydev_hashtag = (char *)mgos_sys_config_get_ydevayth_hashtag();
                    }
                }
                else {
                    if( strcmp(ayt_id_str, ydev_hashtag) == 0 ) {

                        mg_conn_addr_to_str(nc, gateway_ip_addr_port, sizeof(gateway_ip_addr_port),
                                MG_SOCK_STRINGIFY_REMOTE | MG_SOCK_STRINGIFY_IP
                                        | MG_SOCK_STRINGIFY_PORT);

                        //If we have a function to send a response and the connection was inside the local subnet
                        if( _send_ayt_response != NULL && con_inside_local_subnet(nc) ) {

                            //Call function pointer provided by caller to build response message and send it.
                            (_send_ayt_response)(nc);
                        }

                    }
                }
            }

            if( ayt_id_str != NULL ) {
                free(ayt_id_str);
            }

            free(rx_str);
        }
	}

	(void)ev_data;
	(void)user_data;
}

bool mgos_ydev_ayt_handler_init(void) {

	return true;
}


/**
 * @brief Send response back to AYT message source.
 * @param buf The buffer holding the data to be sent.
 * @param len The length of the data in the buffer to be sent.
 * @return true if message was sent.
 */
bool socket_send_ayt_response(const void *buf, int len) {
    bool success = false;

    if (aty_response_con == NULL) {
        char udp_gateway_ip_addr_port[36];
        snprintf(udp_gateway_ip_addr_port, sizeof(udp_gateway_ip_addr_port), "udp://%s", gateway_ip_addr_port);
        aty_response_con = mg_connect(mgos_get_mgr(), udp_gateway_ip_addr_port, NULL, NULL);
        aty_response_con->flags |= MG_F_SEND_AND_CLOSE;
    }

    if (aty_response_con != NULL) {
        mg_send(aty_response_con, buf, len);
        aty_response_con = NULL;
        success = true;
    }

    return success;
}

/**
 * @brief Get the ICON gateway IP address.
 *        This is a wrapper for get_icons_gateway_ip_addr to preserve backwards compatibility.
 */
char *get_gateway_ip_addr(void) {
    return get_icons_gateway_ip_addr();
}

/**
 * @brief Get the ICON gateway IP address.
 */
char *get_icons_gateway_ip_addr(void) {
    char *colon_ptr=NULL;

    memset(gateway_ip_addr, 0, ADDR_PORT_BUF_SIZE);
    strncpy(gateway_ip_addr, gateway_ip_addr_port, ADDR_PORT_BUF_SIZE-1);
    colon_ptr = strchr(gateway_ip_addr, ':');
    if( colon_ptr ) {
        colon_ptr[0] = 0;
    }
    return gateway_ip_addr;
}

/**
 * @brief Init the are you there message handler.
 * @param __send_ayt_response The send_ayt_response function pointer.
 */
void add_ayt_response_handler(void *__send_ayt_response) {
	_send_ayt_response = __send_ayt_response;
	if( _send_ayt_response ) {
		udp_bcast_rx_con = mg_bind( mgos_get_mgr(), ICONS_CLIENT_NET_IF, udp_broadcast_handler, 0);
		udp_bcast_rx_con->flags |= MG_F_ENABLE_BROADCAST;
	}
}
