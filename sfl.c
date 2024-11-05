
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define DIE(assertion, call_description)				\
	do {								\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",			\
					__FILE__, __LINE__);		\
			perror(call_description);			\
			exit(errno);				        \
		}							\
	} while (0)

#define MAXSIZE 99999

////////////////// STRUCTURI ///////////////////////////
typedef struct dll_node_t dll_node_t;
struct dll_node_t {
	void *data;
	dll_node_t *prev, *next;
};

typedef struct dll dll;
struct dll {
	dll_node_t *head;
	dll_node_t *tail;
	int size;
};

typedef struct heap heap;
struct heap {
	dll **lists;
	int total_memory;
	int free_memory;
	int nr_lists;
	int nr_bytes_per_list;
	int allocated_bytes;
	int free_blocks;
	int fragmentations;
	int frees;
	int mallocs;
};

typedef struct node_info node_info;
struct node_info {
	unsigned int address;
	int used;
	int size;
	char *content;
};


int min(int a, int b)
{
	if (a < b)
		return a;
	return b;
}

int interval(int x, int a, int b)
{
	if (x >= a && x < b)
		return 1;
	return 0;
}

dll_node_t *create_node(unsigned int address, int block_size)
{
	dll_node_t *node = malloc(sizeof(*node));
	DIE(!node, "uite nodu nu e nodu");
	node->data = malloc(sizeof(node_info));
	DIE(!node->data, "ce bagi vere acolo");
	node->next = NULL;
	node->prev = NULL;
	((node_info *)node->data)->address = address;
	((node_info *)node->data)->size = block_size;
	((node_info *)node->data)->content = NULL;
	((node_info *)node->data)->used = 0;
	return node;
}

void
dll_add_nth_node(dll *list, int n, unsigned int address, int block_size)
{
	dll_node_t *node = create_node(address, block_size);
	if (!list->head) {
		list->head = node;
		list->tail = node;
		node->prev = node;
		node->next = NULL;
		list->size++;
		return;
	}
	if (n == 0) {
 aici:
		node->prev = NULL;
		node->next = list->head;
		list->head->prev = node;
		list->head = node;
		list->size++;
		return;
	}
	dll_node_t *current = list->head;
	if (n >= list->size) {
		if (list->size == 0)
			goto aici;
		for (int i = 0; i < list->size - 1; ++i)
			current = current->next;
		current->next = node;
		node->next = NULL;
		node->prev = current;
		list->size++;
		return;
	}
	for (int i = 0; i < n - 1; ++i)
		current = current->next;
	node->next = current->next;
	node->prev = current;
	current->next = node;
	list->size++;
}

dll *dll_create_with_memory(int sizeofblock, int address, int list_size)
{
	dll *list = malloc(sizeof(dll));
	DIE(!list, "mai ancearca");
	list->head = NULL;
	list->tail = NULL;
	list->size = 0;
	int list_mem = sizeofblock;
	while (list_mem <= list_size) {
		dll_add_nth_node(list, list->size, address, sizeofblock);
		address += sizeofblock;
		list_mem += sizeofblock;
	}
	return list;
}

dll *create_list(void)
{
	dll *list = malloc(sizeof(dll));
	DIE(!list, "mai ancearca");
	list->head = NULL;
	list->tail = NULL;
	list->size = 0;
	return list;
}

dll_node_t *dll_remove_nth_node(dll *list, int n)
{
	dll_node_t *current = list->head, *deleted;
	if (list->size == 1) {
		current = list->head;
		list->head = NULL;
		list->tail = NULL;
		list->size = 0;
		return current;
	}
	if (n == 0) {
		list->head = current->next;
		list->head->prev = NULL;
		current->next = NULL;
		list->size--;
		return current;
	}
	if (n >= list->size - 1) {
		for (int i = 0; i < list->size - 1; ++i)
			current = current->next;
		current->next = NULL;
		list->size--;
		return current;
	}
	for (int i = 0; i < n - 1; ++i)
		current = current->next;
	deleted = current->next;
	current->next = current->next->next;
	current->next->prev = current;
	list->size--;
	return deleted;
}

void dll_free(dll **pp_list)
{
	dll_node_t *current = (*pp_list)->head, *urm;
	for (int i = 0; i < (*pp_list)->size; ++i) {
		urm = current->next;
		if (((node_info *)current->data)->used)
			free(((node_info *)current->data)->content);
		free(current->data);
		free(current);
		current = urm;
	}
	free(*pp_list);
	*pp_list = NULL;
}

/////////////// FUNCTII HEAP //////////////////////////

void add_sorted_list(dll *list, node_info *data)
{
	if (!list)
		return;
	if (!list->head) {
		dll_add_nth_node(list, 0, data->address, data->size);
	} else {
		dll_node_t *current = list->head;
		int i;
		for (i = 0; i < list->size; ++i) {
			node_info *cur_data = (node_info *)current->data;
			if (cur_data->address > data->address)
				break;
			current = current->next;
		}
		dll_add_nth_node(list, i, data->address, data->size);
	}
}

void add_sorted_heap(heap *heap, node_info *data)
{
	if (!heap)
		return;
	if (!heap->lists[data->size]->head)
		dll_add_nth_node(heap->lists[data->size], 0, data->address, data->size);
	else
		add_sorted_list(heap->lists[data->size], data);
}

heap *heap_init(int start, int nr_liste, int nr_bytes)
{
	heap *first_heap = malloc(sizeof(heap));
	DIE(!first_heap, "heap was not allocated");
	first_heap->nr_bytes_per_list = nr_bytes;
	first_heap->nr_lists = nr_liste;
	first_heap->fragmentations = 0;
	first_heap->allocated_bytes = 0;
	first_heap->mallocs = 0;
	first_heap->frees = 0;
	first_heap->free_memory = 0;
	first_heap->total_memory = 0;
	first_heap->free_blocks = 0;
	first_heap->lists = calloc((nr_bytes + 1), sizeof(dll *));
	int block_size = 8;
	DIE(!first_heap->lists, "heap was not allocated");
	for (int i = 8; i <= nr_bytes && nr_liste--; i *= 2) {
		first_heap->lists[i] =
			dll_create_with_memory(block_size, start, nr_bytes);
		first_heap->total_memory += block_size * first_heap->lists[i]->size;
		first_heap->free_blocks += first_heap->lists[i]->size;
		start += nr_bytes;
		block_size *= 2;
		DIE(!first_heap->lists[i], "list was not allocated");
	}
	for (int i = 0; i <= nr_bytes; ++i)
		if (!first_heap->lists[i])
			first_heap->lists[i] = create_list();
	first_heap->free_memory = first_heap->total_memory;
	return first_heap;
}

void my_malloc(heap *free_l, dll *allocated, int memsize)
{
	if (memsize > free_l->free_memory || memsize > free_l->nr_bytes_per_list) {
		printf("Out of memory\n");
		return;
	}
	if (free_l->lists[memsize]->head) {
		free_l->allocated_bytes += memsize;
		free_l->free_memory -= memsize;
		free_l->mallocs++;
		free_l->free_blocks--;
		dll_node_t *removed = dll_remove_nth_node(free_l->lists[memsize], 0);
		node_info *data = (node_info *)removed->data;
		add_sorted_list(allocated, data);
		free(removed);
		free(data);
		return;
	}
	for (int i = memsize + 1; i <= free_l->nr_bytes_per_list; ++i) {
		if (free_l->lists[i]->head) {
			free_l->allocated_bytes += memsize;
			free_l->mallocs++;
			free_l->free_memory -= memsize;
			free_l->fragmentations++;
			dll_node_t *removed = dll_remove_nth_node(free_l->lists[i], 0);
			node_info *data = (node_info *)removed->data;
			int adr0 = data->address;
			int new_addr = data->address + memsize;
			int new_size = data->size - memsize;
			data->address = new_addr;
			data->size = new_size;
			add_sorted_heap(free_l, data);
			data->address = adr0;
			data->size = memsize;
			add_sorted_list(allocated, data);
			free(removed);
			free(data);
			return;
		}
	}
	printf("Out of memory\n");
}

void my_free(heap *free_l, dll *allocated,
			 unsigned int address)
{
	int found = 0;
	dll_node_t *current = allocated->head;
	for (int i = 0; i < allocated->size; ++i) {
		node_info *data = (node_info *)current->data;
		if (data->address == address) {
			found = 1;
			free_l->frees++;
			free_l->allocated_bytes -= data->size;
			free_l->free_blocks++;
			free_l->free_memory += data->size;
			dll_node_t *removed = dll_remove_nth_node(allocated, i);
			add_sorted_heap(free_l, data);
			if (((node_info *)current->data)->used) {
				free(((node_info *)current->data)->content);
				((node_info *)current->data)->used = 0;
			}
			free(removed->data);
			free(removed);
			return;
		}
		current = current->next;
	}
	if (!found)
		printf("Invalid free\n");
}

void show_dump(heap *heap, dll *allocated)
{
	printf("+++++DUMP+++++\n");
	printf("Total memory: %d bytes\n", heap->total_memory);
	printf("Total allocated memory: %d bytes\n", heap->allocated_bytes);
	heap->free_memory = heap->total_memory - heap->allocated_bytes;
	printf("Total free memory: %d bytes\n", heap->free_memory);
	printf("Free blocks: %d\n", heap->free_blocks);
	printf("Number of allocated blocks: %d\n", allocated->size);
	printf("Number of malloc calls: %d\n", heap->mallocs);
	printf("Number of fragmentations: %d\n", heap->fragmentations);
	printf("Number of free calls: %d\n", heap->frees);
	for (int i = 1; i <= heap->nr_bytes_per_list; ++i) {
		if (heap->lists[i]->head) {
			int blocksize = ((node_info *)heap->lists[i]->head->data)->size;
			printf("Blocks with %d bytes - %d free block(s) :", blocksize,
				   heap->lists[i]->size);
			dll_node_t *current = heap->lists[i]->head;
			for (int j = 0; j < heap->lists[i]->size; ++j) {
				printf(" 0x%x", ((node_info *)current->data)->address);
				current = current->next;
			}
			printf("\n");
		}
	}
	printf("Allocated blocks :");
	if (allocated->size > 0) {
		dll_node_t *current = allocated->head;
		for (int i = 0; i < allocated->size; ++i) {
			printf(" (0x%x - %d)", ((node_info *)current->data)->address,
				   ((node_info *)current->data)->size);
			current = current->next;
		}
	}
	printf("\n");
	printf("-----DUMP-----\n");
}

void destroy_heap(heap *free_l, dll *allocated)
{
	if (!free_l)
		return;
	for (int i = 0; i <= free_l->nr_bytes_per_list; ++i)
		dll_free(&free_l->lists[i]);
	free(free_l->lists);
	free(free_l);
	dll_free(&allocated);
}

void write(heap *free_l, dll *allocated, int address,
		   char *str, int bytes)
{
	int found = 0, valid = 0;
	if (bytes >= strlen(str))
		bytes = strlen(str);
	else
		str[bytes] = '\0';
	if (bytes > free_l->allocated_bytes) {
		printf("Segmentation fault (core dumped)\n");
		show_dump(free_l, allocated);
		return;
	}
	dll_node_t *current = allocated->head;
	dll_node_t *check;
	for (int i = 0; i < allocated->size; ++i) {
		node_info *cur_data = (node_info *)current->data;
		int curadr = cur_data->address;
		if (curadr == address ||
			interval(address, curadr, curadr + cur_data->size)) {
			found = 1;
			break;
		}
		current = current->next;
	}
	if (found) {
		node_info *cur_data = (node_info *)current->data;
		int d = address - cur_data->address;
		if (address + bytes <= cur_data->address + cur_data->size) {
			if (cur_data->used != 0) {
				strcat(str, ((node_info *)current->data)->content + d + bytes);
				strncpy(((node_info *)current->data)->content + d, str, bytes);
				return;
			}
			((node_info *)current->data)->content = malloc(cur_data->size);
			strncpy(((node_info *)current->data)->content, str, bytes);
			((node_info *)current->data)->content[bytes] = '\0';
			((node_info *)current->data)->used = bytes;
			return;
		}
		check = current;
		int available = 0;
		while (current) {
			node_info *cur_data = (node_info *)current->data;
			available += cur_data->size;
			if (!current->next)
				break;
			if (cur_data->address + cur_data->size ==
				((node_info *)current->next->data)->address)
				current = current->next;
			else
				break;
			}
		if (bytes <= available)
			valid = 1;
	}
	if (found && valid) {
		dll_node_t *current = check;
		node_info *cur_data = (node_info *)current->data;
		int btr;
		btr = cur_data->address + cur_data->size - address;
		int d = address - cur_data->address;
		while (bytes) {
			btr =
				min(((node_info *)current->data)->size - d, strlen(str));
				((node_info *)current->data)->content = malloc(btr + 1);
			strncpy(((node_info *)current->data)->content, str,
					btr);
			((node_info *)current->data)->content[btr] = '\0';
			((node_info *)current->data)->used =
				((node_info *)current->data)->size;
			d = 0;
			str += ((node_info *)current->data)->size;
			bytes -= btr;
			current = current->next;
		}
	} else {
		printf("Segmentation fault (core dumped)\n");
		show_dump(free_l, allocated);
	}
}

void read(heap *free_l, dll *allocated, int address, int bytes)
{
	int found = 0, valid = 0;
	dll_node_t *current = allocated->head;
	dll_node_t *check;
	for (int i = 0; i < allocated->size; ++i) {
		node_info *cur_data = (node_info *)current->data;
		int final = cur_data->address + cur_data->size;
		if (cur_data->address == address ||
			interval(address, cur_data->address, final)) {
			found = 1;
			break;
		}
		current = current->next;
	}
	if (found) {
		//printf("baga aici\n");
		node_info *cur_data = (node_info *)current->data;
		int decalation = address - cur_data->address;
		if (bytes <= cur_data->used) {
			for (int i = 0; i < strlen(cur_data->content) && bytes--; ++i)
				printf("%c", cur_data->content[i + decalation]);
			printf("\n");
			return;
		}
		check = current;
		int available = 0;
		while (current) {
			node_info *cur_data = (node_info *)current->data;
			available += cur_data->size;
			if (!current->next)
				break;
			if (cur_data->address + cur_data->size ==
				((node_info *)current->next->data)->address)
				current = current->next;
			else
				break;
		}
		if (bytes <= available)
			valid = 1;
	}
	if (found && valid) {
		//printf("vine aici\n");
		current = check;
		node_info *cur_data = (node_info *)current->data;
		int decalation = address - cur_data->address;
		//printf("decal %d\n", decalation);
		while (bytes > 0 && current) {
			node_info *cur_data = (node_info *)current->data;
			int size = cur_data->used;
			for (int i = 0; i < cur_data->used && bytes; ++i) {
				printf("%c", cur_data->content[i + decalation]);
				bytes--;
			}
			decalation = 0;
			current = current->next;
		}
		printf("\n");
	} else {
		printf("Segmentation fault (core dumped)\n");
		show_dump(free_l, allocated);
	}
}

int main(void)
{
	char command[12];
	unsigned int start_addr, nr_liste, nr_bytes;
	heap *free_heap;
	dll *allocated_heap;
	while (1) {
		//printf("citeste vere\n");
		scanf("%s", command);
		if (strncmp(command, "INIT_HEAP", 9) == 0) {
			int type;
			scanf("%x%d%d%d", &start_addr, &nr_liste, &nr_bytes, &type);
			free_heap = heap_init(start_addr, nr_liste, nr_bytes);
			allocated_heap = create_list();
		}
		if (strncmp(command, "PRINT_HEAP", 10) == 0) {
			printf("se afiseaza lista free\n");
			for (int i = 0; i <= nr_bytes; ++i) {
				if (free_heap->lists[i]->head) {
					printf("lista %d\n", i);
					dll_node_t *current = free_heap->lists[i]->head;
					for (int j = 0; j < free_heap->lists[i]->size; ++j) {
						printf("0x%x ", ((node_info *)current->data)->address);
						current = current->next;
					}
					printf("\n");
				}
			}
			printf("se afiseaza lista alocata de dim %d\n",
				   allocated_heap->size);
			if (allocated_heap->size > 0) {
				dll_node_t *current = allocated_heap->head;
				for (int i = 0; i < allocated_heap->size; ++i) {
					printf("0x%x ", ((node_info *)current->data)->address);
					current = current->next;
				}
				printf("\n");
			}
		}
		if (strncmp(command, "MALLOC", 6) == 0) {
			int size;
			scanf("%d", &size);
			my_malloc(free_heap, allocated_heap, size);
		}
		if (strncmp(command, "FREE", 4) == 0) {
			int addr;
			scanf("%x", &addr);
			my_free(free_heap, allocated_heap, addr);
		}
		if (strncmp(command, "READ", 4) == 0) {
			int addr, bytes;
			scanf("%x%d", &addr, &bytes);
			read(free_heap, allocated_heap, addr, bytes);
		}
		if (strncmp(command, "WRITE", 5) == 0) {
			int addr, bytes;
			char *str = malloc(MAXSIZE), c, message[MAXSIZE], arg[MAXSIZE];
			scanf("%c", &c);
			scanf("%x", &addr);
			scanf("%c", &c);
			fgets(str, MAXSIZE, stdin);
			int i = 1;
			while (str[i] != '"')
				i++;
			strncpy(message, str + 1, i - 1);
			message[i - 1] = '\0';
			strcpy(arg, str + strlen(message) + 3);
			bytes = atoi(arg);
			write(free_heap, allocated_heap, addr, message, bytes);
			free(str);
		}
		if (strncmp(command, "DUMP_MEMORY", 11) == 0)
			show_dump(free_heap, allocated_heap);
		if (strncmp(command, "DESTROY_HEAP", 13) == 0) {
			destroy_heap(free_heap, allocated_heap);
			return 0;
		}
	}
	return 0;
}