#define SERVER_PORT 4343
#define MAX_BACKLOG 5
#define MAX_EVENTS 10

void setnonblocking(int sock);
int create_listener();
char *search_notschar(char *buffer, char *word);
int switch_reaction(int client, char *buffer);
void wait_telnet();

void show_map_cache(int client, int af);
void write_route_info_v4(int client, struct info *ptr);
void write_route_info_v6(int client, struct info *ptr);
