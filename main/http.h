#ifndef HTTP_H
#define HTTP_H

void http_client_init();
void http_client_post(char *path, char* data, size_t data_len, char* response);


#endif