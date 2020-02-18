#ifndef _AYT_HANDLER
#define _AYT_HANDLER

#define UNSET_AYT_MESSAGE "CHANGEMECHANGEMECHANGEMECHANGEMECHANGEMECHANGEMECHANGEMECHANGEME"
#define MIN_AYT_MSG_LEN 8
#define MAX_AYT_MSG_LEN 64
#define ICONS_CLIENT_NET_IF "udp://:2934"

bool mgos_ydev_ayt_handler_init(void);
void add_ayt_response_handler(void *__send_ayt_response);
int mgos_get_ayt_msg_count(void);

#endif
