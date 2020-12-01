#include "vm/swap.h"
#include "vm/page.h"

static struct block *swap_slots;          // Swap Block Device
static struct bitmap *swap_table;          // Swap Bitmap Table

void swap_init(){
  swap_slots = block_get_role(BLOCK_SWAP);              // Get Swap block device
  swap_table = bitmap_create(swap_slots->size / 8);     // Create swap table with size of #sector/8
  bitmap_set_all(swap_table, false);                    // Initialize swap table
}

uint32_t find_empty_swap_slot(){                        // Find empy swap slot
  return bitmap_scan_and_flip(swap_table, 0, 1, false);
}

bool swap_out (struct frame_table_entry *e){


}

bool swap_in (struct sPage_table_entry *e){


}