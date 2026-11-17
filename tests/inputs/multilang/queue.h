#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>

struct queue_node {
    int value;
    struct queue_node *next;
};

typedef struct {
    struct queue_node *head;
    struct queue_node *tail;
    int size;
} Queue;

void queue_init(Queue *q);
bool queue_push(Queue *q, int value);
bool queue_pop(Queue *q, int *out_value);
int queue_size(const Queue *q);

#endif
