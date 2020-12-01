#include <bitmap.h>
#include <block.h>

void swap_init ();
size_t find_empty_swap_slot (); 
bool swap_out (struct frame_table_entry *);
bool swap_in (struct sPage_table_entry *);
