#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <bitmap.h>
#include "devices/block.h"
#include <stdbool.h>
#include "vm/page.h"
#include "vm/frame.h"

void swap_init ();
size_t find_empty_swap_slot (); 
bool swap_out (struct frame_table_entry *);
bool swap_in (struct sPage_table_entry *, struct frame_table_entry *);  
void delete_swap_table_entry(uint32_t);

#endif
