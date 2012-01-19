#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>

#include "main.h"
#include "queue.h"

int enqueue(struct queue_item *start, char *address){
	struct queue_item *ptr = start;
	struct queue_item *new = malloc(sizeof(struct queue_item));
	memset(new, 0, sizeof(struct queue_item));
	memcpy(new->address, address, 16);
	
	while(ptr->next_item != NULL){
		ptr = ptr->next_item;
	}

	ptr->next_item = new;

	return 0;
}

int dequeue(struct queue_item *start, char *address){
	struct queue_item *ptr = start->next_item;
	memcpy(address, ptr->address, 16);

	start->next_item = ptr->next_item;
	free(ptr);

	return 0;
}

int check_queue(struct queue_item *start){
	if(start->next_item == NULL){
		return 0;
	}else{
		return 1;
	}
}

