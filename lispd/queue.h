struct queue_item{
	struct queue_item *next_item;
	char address[16];
};

int enqueue(struct queue_item *start, char *address);
int dequeue(struct queue_item *start, char *address);
int check_queue(struct queue_item *start);
