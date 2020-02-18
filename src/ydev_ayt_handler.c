#include "mgos.h"

#include "ydev_ayt_handler.h"

//The function pointer passed when the ayt handler was inited
static void (*_send_ayt_response)(struct mg_connection *nc);

struct mg_connection *aty_response_con;
static int ayt_msg_count;
static struct mg_connection *udp_bcast_rx_con;
static char *expected_ayt_message;

/**
 * @brief Get the number of are you there (AYT) messages that this device has received.
 * @return The AYT message count
 */
int mgos_get_ayt_msg_count(void) {
	return ayt_msg_count;
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

	if( ev == MG_EV_RECV ) {
		char *ayt_id_str = NULL;
		char *rx_str = malloc(io->len+1);

		memcpy(rx_str, io->buf, io->len);
		rx_str[io->len]=0;

		json_scanf(rx_str, io->len, "{AYT:%Q}", &ayt_id_str);

        //If the AYT message has not been set yet
        if (ayt_id_str
                && strcmp(mgos_sys_config_get_ydevayth_ayt_msg(),
                        UNSET_AYT_MESSAGE) == 0) {
            int rx_ayt_msg_len = strlen(ayt_id_str);
            if (rx_ayt_msg_len < MIN_AYT_MSG_LEN) {
                LOG(LL_INFO,
                        ("AYT msg is too short <%s> (min = %d bytes)\n", ayt_id_str, MIN_AYT_MSG_LEN ));
            } else if (rx_ayt_msg_len > MAX_AYT_MSG_LEN) {
                LOG(LL_INFO,
                        ("AYT msg is too long <%s> (max = %d bytes)\n", ayt_id_str, MAX_AYT_MSG_LEN ));
            } else {
                mgos_sys_config_set_ydevayth_ayt_msg(ayt_id_str);
                mgos_sys_config_save(&mgos_sys_config, false, NULL);
                expected_ayt_message =
                        (char *) mgos_sys_config_get_ydevayth_ayt_msg();
                LOG(LL_INFO, ("Set AYT msg to %s\n", expected_ayt_message ));
            }
        }

		//If we have an ICONS AYT message then get the ICONS gateway IP address
		if( ayt_id_str != NULL ) {
			if( strcmp(ayt_id_str, expected_ayt_message) == 0 ) {

				//If we have a function to send a response
				if( _send_ayt_response != NULL ) {
					(_send_ayt_response)(nc);
				}

				ayt_msg_count++;

			}
			free(ayt_id_str);
		}

		free(rx_str);
	}

	(void)ev_data;
	(void)user_data;
}

bool mgos_ydev_ayt_handler_init(void) {
    expected_ayt_message =  (char *)mgos_sys_config_get_ydevayth_ayt_msg();
	return true;
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
