#include "routing_table.h"

int cmp_route(const void *a, const void *b) {
	rt_entry* entry1 = (rt_entry *) a;
	rt_entry* entry2 = (rt_entry *) b;

	// daca mastile sunt egale se returneaza adresa de retea mai mica
	if (entry1->mask == entry2->mask) {
		if (entry1->network < entry2->network) {
			return -1;
		}

		return 1;
	} else if (entry1->mask < entry2->mask) {
		return -1;
	} else {
		return 1;
	}
}

void parse_routing_table(rt_entries *rt_table) {
	FILE *in;
	in = fopen("rtable.txt", "r");

	int i = 0;
	char line[MAX_ROUTING_ENTRTY_SIZE];

	while (fgets(line, sizeof(line), in) != NULL) {
		// ignora '\n'
		line[strlen(line) - 1] = '\0';

		// separa informatia utila
		char* info = strtok(line, " ");
		rt_table->entries[i].network = ntohl(inet_addr(info));

		info = strtok(NULL, " ");
		rt_table->entries[i].next_hop = ntohl(inet_addr(info));

		info = strtok(NULL, " ");
		rt_table->entries[i].mask = ntohl(inet_addr(info));

		info = strtok(NULL, " ");
		rt_table->entries[i].intf = atoi(info);
		
		++i;
	}
	
	// se sorteaza tabela de rutare dupa functia cmp_route
	rt_table->len = i;
	qsort(rt_table->entries, rt_table->len, sizeof(rt_entry), cmp_route);

	fclose(in);
}

rt_entry* get_best_route(uint32_t dest_ip, rt_entries* rt_table) {
	int msb = log2(rt_table->len);
	// se cauta intrarea cu cea mai lunga masca de retea
	for (int mask_size = MAX_MASK_SIZE; mask_size >= 0; --mask_size) {
		uint32_t mask = ((1LL << MAX_MASK_SIZE) - 1)
												<< (MAX_MASK_SIZE - mask_size);
		int left = 0;
		int right = 0;

		/* se cauta binar un interval [left, right] in care se regasesc numai 
		intrari cu masca egala cu mask */

		// se cauta binar left
		for (int bit = msb; bit >= 0; --bit) {
			int index = left + (1 << bit);
			if (index < rt_table->len && rt_table->entries[index].mask < mask) {
				left += (1 << bit);
			}
		}

		if (rt_table->entries[0].mask != mask) {
			++left;
		}

		// se cauta binar right
		for (int bit = msb; bit >= 0; --bit) {
			int index = right + (1 << bit);
			if (index < rt_table->len
				&& rt_table->entries[index].mask <= mask) {
				right += (1 << bit);
			}
		}

		/* se cauta binar un match in intervalul [left, right] pentru adresa 
		primita ca parametru */
		int answer = left;
		uint32_t network = dest_ip & mask;

		for (int bit = log2(right); bit >= 0; --bit) {
			int index = answer + (1 << bit);
			if (index < rt_table->len
				&& rt_table->entries[index].network <= network) {
				answer += (1 << bit); 
			}
		}

		// daca nu se gaseste un match se va incerca o masca mai mica
		if (rt_table->entries[answer].network == network) {
			return &rt_table->entries[answer];
		}
	}

	// daca nu exista niciun match pentru adresa trimisa se returneaza NULL
	return NULL;
}
