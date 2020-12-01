#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <bitmap.h>
#include "devices/block.h"
#include <stdbool.h>
#include "vm/page.h"

void swap_init ();
size_t find_empty_swap_slot (); 
bool swap_out (struct frame_table_entry *);
bool swap_in (struct sPage_table_entry *);

#endif
