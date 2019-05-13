#include "mgos.h"

#include "ydev_ayt_handler.h"

//The function pointer passed when the ayt handler was inited
static void (*_send_ayt_response)(struct mg_connection *nc);

struct mg_connection *aty_response_con;
static int ayt_msg_count;
static struct mg_connection *udp_bcast_rx_con;

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

		//If we have an ICONS AYT message then get the ICONS gateway IP address
		if( ayt_id_str != NULL ) {
			if( strcmp(ayt_id_str, ICONS_AYT_MESSAGE) == 0 ) {

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
