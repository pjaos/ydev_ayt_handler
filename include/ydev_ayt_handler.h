#ifndef _AYT_HANDLER
#define _AYT_HANDLER

#define ICONS_AYT_MESSAGE "-!#8[dkG^v's!dRznE}6}8sP9}QoIR#?O&pg)Qra"
#define ICONS_CLIENT_NET_IF "udp://:2934"

bool mgos_ydev_ayt_handler_init(void);
void add_ayt_response_handler(void *__send_ayt_response);
int mgos_get_ayt_msg_count(void);
char *get_gateway_ip_addr(void); //Deprecated, use get_icons_gateway_ip_addr instead.
char *get_icons_gateway_ip_addr(void);
bool socket_send_ayt_response(const void *buf, int len);

#endif
