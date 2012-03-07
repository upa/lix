#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sys/socket.h>

#include "main.h"
#include "parser.h"

int parse_config(){
	FILE *fp;
	char readline[1024];

	struct root_layer_data *data;
	struct config *current_config;

	/* allocate memory for each config structure */
	current_config = &config_root;
	current_config->under_layers = (void **)malloc(sizeof(void *) * ROOT_LAYER_MODE_NUM);
	memset(current_config->under_layers, 0, sizeof(void *) * ROOT_LAYER_MODE_NUM);
	add_statement_to_list(&states_root, current_config->under_layers);
	current_config->data = (void *)malloc(sizeof(struct root_layer_data));
	memset(current_config->data, 0, sizeof(sizeof(struct root_layer_data)));
	data = (struct root_layer_data *)current_config->data;
	add_statement_to_list(&states_root, data);

	if((fp = fopen(config_path, "r")) == NULL) {
		err(EXIT_FAILURE, "failed to read saved config");
	}

	while (fgets(readline, 1024, fp) != NULL) {
		int i;
		char *command[] = {ROOT_LAYER_COMMAND};
		char *mode[] = {ROOT_LAYER_MODE};
		int command_num = ROOT_LAYER_COMMAND_NUM;
		int mode_num = ROOT_LAYER_MODE_NUM;

		if(strstr(readline, "#") != NULL){
			continue;
		}

		for(i = 0; i < command_num; i++){
			if(strstr(readline, command[i]) != NULL){
				if(i == DEFAULTTTL_COMMAND){
					strtok(readline, " ");
					data->default_ttl = atoi(strtok(NULL, ";"));
				}else if(i == CONTROLIPVERSION_COMMAND){
					strtok(readline, " ");
					data->control_ip_version = atoi(strtok(NULL, ";"));
				}else if(i == SENDMAPREGISTER_COMMAND){
					strtok(readline, " ");
					data->send_map_register = atoi(strtok(NULL, ";"));
				}else if(i == AUTHENTICATIONKEY_COMMAND){
					strtok(readline, " ");
					strcpy(data->authentication_key, strtok(NULL, ";"));
				}else if(i == SYSLOGFACILITY_COMMAND){
					strtok(readline, " ");
					strcpy(data->syslog_facility, strtok(NULL, ";"));
				}
			}
		}

		for(i = 0; i < mode_num; i++){
			if(strstr(readline, mode[i]) != NULL){
				void (*parse_func)();

				if(i == EID_LAYER){
					parse_func = parse_eid;
				}else if(i == RLOC_LAYER){
					parse_func = parse_rloc;
				}else if(i == MAPSERVER_LAYER){
					parse_func = parse_mapserver;
				}else if(i == MAPRESOLVER_LAYER){
					parse_func = parse_mapresolver;
				}else if(i == MAPCACHE_LAYER){
					parse_func = parse_mapcache;
				}

				current_config->under_layers[i] = malloc(sizeof(struct config));
				memset(current_config->under_layers[i], 0, sizeof(struct config));
				add_statement_to_list(&states_root, current_config->under_layers[i]);
				(*parse_func)(fp, current_config->under_layers[i], &states_root);
			}
		}
	}

	fclose(fp);

}

void flush_config(struct config *config_root, struct state_list *states_root){
	struct state_list *ptr;

	if(states_root->next != NULL){

		ptr = states_root->next;

		do{
			struct state_list *temp;
			temp = ptr;
			ptr = ptr->next;
			free(temp);
		}while(ptr != NULL);
	}

	memset(states_root, 0, sizeof(struct state_list));
	memset(config_root, 0, sizeof(struct config));
}

void add_statement_to_list(struct state_list *states_root, void *data){
	struct state_list *ptr = states_root;

	while(ptr->next != NULL){
		ptr = ptr->next;
	}
	ptr->next = malloc(sizeof(struct state_list));
	ptr = ptr->next;
	memset(ptr, 0, sizeof(struct state_list));
	ptr->ptr = data;
}

struct address_list *alloc_address_list(struct address_list *root, struct state_list *states_root){
	struct address_list *ptr = root;

	while(ptr->next != NULL){
		ptr = ptr->next;
	}

	ptr->next = malloc(sizeof(struct address_list));
	ptr = ptr->next;
	memset(ptr, 0, sizeof(struct address_list));
	add_statement_to_list(states_root, ptr);

	return ptr;
}

void parse_eid(FILE *fp, struct config *current_config, struct state_list *states_root){
	char readline[1024];
	int i;
	char *command[] = {EID_LAYER_COMMAND};
	char *mode[] = {EID_LAYER_MODE};
	int command_num = EID_LAYER_COMMAND_NUM;
	int mode_num = EID_LAYER_MODE_NUM;
	struct eid_layer_data *data;

	/* allocate memory for each config structure */
	current_config->data = (void *)malloc(sizeof(struct eid_layer_data));
	memset(current_config->data, 0, sizeof(sizeof(struct eid_layer_data)));
	data = (struct eid_layer_data *)current_config->data;
	add_statement_to_list(states_root, data);

	while (fgets(readline, 1024, fp) != NULL) {

		if(strstr(readline, "#") != NULL){
			continue;
		}

		for(i = 0; i < command_num; i++){
			if(strstr(readline, command[i]) != NULL){
				if(i == V6PREFIX_COMMAND){
					struct address_list *ptr;

					strtok(readline, " ");
					ptr = alloc_address_list(&(data->v6prefix), states_root);
					strcpy(ptr->address, strtok(NULL, "/"));
					ptr->prefix = atoi(strtok(NULL, ";"));
				}else if(i == V4PREFIX_COMMAND){
					struct address_list *ptr;

					strtok(readline, " ");
					ptr = alloc_address_list(&(data->v4prefix), states_root);
					strcpy(ptr->address, strtok(NULL, "/"));
					ptr->prefix = atoi(strtok(NULL, ";"));
				}
			}
		}

		for(i = 0; i < mode_num; i++){
			// No mode statement here
		}

		if(strstr(readline, "}") != NULL){
			break;
		}
	}
}

void parse_rloc(FILE *fp, struct config *current_config, struct state_list *states_root){
	char readline[1024];
	int i;
	char *command[] = {RLOC_LAYER_COMMAND};
	char *mode[] = {RLOC_LAYER_MODE};
	int command_num = RLOC_LAYER_COMMAND_NUM;
	int mode_num = RLOC_LAYER_MODE_NUM;
	struct rloc_layer_data *data;

	/* allocate memory for each config structure */
	current_config->data = (void *)malloc(sizeof(struct rloc_layer_data));
	memset(current_config->data, 0, sizeof(sizeof(struct rloc_layer_data)));
	data = (struct rloc_layer_data *)current_config->data;
	add_statement_to_list(states_root, data);

	while (fgets(readline, 1024, fp) != NULL) {

		if(strstr(readline, "#") != NULL){
			continue;
		}

		for(i = 0; i < command_num; i++){
			if(strstr(readline, command[i]) != NULL){
				if(i == V6ADDRESS_COMMAND){
					struct address_list *ptr;

					strtok(readline, " ");
					ptr = alloc_address_list(&(data->v6address), states_root);
					strcpy(ptr->address, strtok(NULL, ";"));
				}else if(i == V4ADDRESS_COMMAND){
					struct address_list *ptr;

					strtok(readline, " ");
					ptr = alloc_address_list(&(data->v4address), states_root);
					strcpy(ptr->address, strtok(NULL, ";"));
				}
			}
		}

		for(i = 0; i < mode_num; i++){
			// No mode statement here
		}

		if(strstr(readline, "}") != NULL){
			break;
		}
	}
}

void parse_mapserver(FILE *fp, struct config *current_config, struct state_list *states_root){
	char readline[1024];
	int i;
	char *command[] = {MAPSERVER_LAYER_COMMAND};
	char *mode[] = {MAPSERVER_LAYER_MODE};
	int command_num = MAPSERVER_LAYER_COMMAND_NUM;
	int mode_num = MAPSERVER_LAYER_MODE_NUM;
	struct mapserver_layer_data *data;

	/* allocate memory for each config structure */
	current_config->data = (void *)malloc(sizeof(struct mapserver_layer_data));
	memset(current_config->data, 0, sizeof(sizeof(struct mapserver_layer_data)));
	data = (struct mapserver_layer_data *)current_config->data;
	add_statement_to_list(states_root, data);

	while (fgets(readline, 1024, fp) != NULL) {

		if(strstr(readline, "#") != NULL){
			continue;
		}

		for(i = 0; i < command_num; i++){
			if(strstr(readline, command[i]) != NULL){
				if(i == V6ADDRESS_COMMAND){
					struct address_list *ptr;

					strtok(readline, " ");
					ptr = alloc_address_list(&(data->v6address), states_root);
					strcpy(ptr->address, strtok(NULL, ";"));
				}else if(i == V4ADDRESS_COMMAND){
					struct address_list *ptr;

					strtok(readline, " ");
					ptr = alloc_address_list(&(data->v4address), states_root);
					strcpy(ptr->address, strtok(NULL, ";"));
				}
			}
		}

		for(i = 0; i < mode_num; i++){
			// No mode statement here
		}

		if(strstr(readline, "}") != NULL){
			break;
		}
	}
}

void parse_mapresolver(FILE *fp, struct config *current_config, struct state_list *states_root){
	char readline[1024];
	int i;
	char *command[] = {MAPRESOLVER_LAYER_COMMAND};
	char *mode[] = {MAPRESOLVER_LAYER_MODE};
	int command_num = MAPRESOLVER_LAYER_COMMAND_NUM;
	int mode_num = MAPRESOLVER_LAYER_MODE_NUM;
	struct mapresolver_layer_data *data;

	/* allocate memory for each config structure */
	current_config->data = (void *)malloc(sizeof(struct mapresolver_layer_data));
	memset(current_config->data, 0, sizeof(sizeof(struct mapresolver_layer_data)));
	data = (struct mapresolver_layer_data *)current_config->data;
	add_statement_to_list(states_root, data);

	while (fgets(readline, 1024, fp) != NULL) {

		if(strstr(readline, "#") != NULL){
			continue;
		}

		for(i = 0; i < command_num; i++){
			if(strstr(readline, command[i]) != NULL){
				if(i == V6ADDRESS_COMMAND){
					struct address_list *ptr;

					strtok(readline, " ");
					ptr = alloc_address_list(&(data->v6address), states_root);
					strcpy(ptr->address, strtok(NULL, ";"));
				}else if(i == V4ADDRESS_COMMAND){
					struct address_list *ptr;

					strtok(readline, " ");
					ptr = alloc_address_list(&(data->v4address), states_root);
					strcpy(ptr->address, strtok(NULL, ";"));
				}
			}
		}

		for(i = 0; i < mode_num; i++){
			// No mode statement here
		}

		if(strstr(readline, "}") != NULL){
			break;
		}
	}
}


void parse_mapcache(FILE *fp, struct config *current_config, struct state_list *states_root){
	char readline[1024];
	int i;
	char *command[] = {MAPCACHE_LAYER_COMMAND};
	char *mode[] = {MAPCACHE_LAYER_MODE};
	int command_num = MAPCACHE_LAYER_COMMAND_NUM;
	int mode_num = MAPCACHE_LAYER_MODE_NUM;
	struct mapcache_layer_data *data;

	/* allocate memory for each config structure */
	current_config->data = (void *)malloc(sizeof(struct mapcache_layer_data));
	memset(current_config->data, 0, sizeof(sizeof(struct mapcache_layer_data)));
	data = (struct mapcache_layer_data *)current_config->data;
	add_statement_to_list(states_root, data);

	while (fgets(readline, 1024, fp) != NULL) {

		if(strstr(readline, "#") != NULL){
			continue;
		}

		for(i = 0; i < command_num; i++){
			if(strstr(readline, command[i]) != NULL){
				if(i == V6STATIC_COMMAND){
					struct address_list *ptr;

					strtok(readline, " ");
					ptr = alloc_address_list(&(data->v6static), states_root);
					strcpy(ptr->address, strtok(NULL, "/"));
					ptr->prefix = atoi(strtok(NULL, " "));
					strcpy(ptr->nexthop, strtok(NULL, ";"));

					int ai_family = get_addr_af(ptr->nexthop);
					if(ai_family == AF_INET){
						ptr->nexthop_af = 1;
					}else if(ai_family == AF_INET6){
						ptr->nexthop_af = 2;
					}
				}else if(i == V4STATIC_COMMAND){
					struct address_list *ptr;

					strtok(readline, " ");
					ptr = alloc_address_list(&(data->v4static), states_root);
					strcpy(ptr->address, strtok(NULL, "/"));
					ptr->prefix = atoi(strtok(NULL, " "));
					strcpy(ptr->nexthop, strtok(NULL, ";"));

					int ai_family = get_addr_af(ptr->nexthop);
					if(ai_family == AF_INET){
						ptr->nexthop_af = 1;
					}else if(ai_family == AF_INET6){
						ptr->nexthop_af = 2;
					}
				}
			}
		}

		for(i = 0; i < mode_num; i++){
			// No mode statement here
		}

		if(strstr(readline, "}") != NULL){
			break;
		}
	}
}

