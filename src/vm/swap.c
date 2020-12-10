#include "vm/swap.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include <stdlib.h>

static struct block *swap_slots;          // Swap Block Device
static struct bitmap *swap_table;          // Swap Bitmap Table
struct lock swap_lock;                    // Lock for swap devices

void swap_init(){
  swap_slots = block_get_role(BLOCK_SWAP);              // Get Swap block device
  swap_table = bitmap_create(block_size(swap_slots) / 8);     // Create swap table with size of #sector/8
  bitmap_set_all(swap_table, false);                    // Initialize swap table
  lock_init(&swap_lock);
}

size_t find_empty_swap_slot(){       
	size_t index;

	lock_acquire(&swap_lock);
  
  // Find empy swap slot
  index = bitmap_scan_and_flip(swap_table, 0, 1, false);     

	lock_release(&swap_lock);

	return index;
}

bool swap_out (struct frame_table_entry *fte){
  ASSERT (fte != NULL);

  size_t index;
  int i;
  
  // Get empty swap slot
  index = find_empty_swap_slot();                         
  if(index == BITMAP_ERROR)                             
    return false;

  // Store Frame Data into Swap slot
  lock_acquire(&swap_lock);
  for (i=0; i<8; i++)
    block_write(swap_slots, 8 * index + i, ((uintptr_t)fte->frame_number << 12) + BLOCK_SECTOR_SIZE * i);
  lock_release(&swap_lock);

  // modify location of the page and store swap index
  fte->s_pte->location = LOC_SWAP;
  fte->s_pte->slot_number = index;                           
  
  return true;
}

bool swap_in (struct sPage_table_entry *s_pte, struct frame_table_entry *fte){
  ASSERT (s_pte != NULL);
  ASSERT (fte != NULL);
  
  int i;

  //Read block in Swap table 
  lock_acquire(&swap_lock);
  for(i=0; i<8; i++)           
    block_read(swap_slots, 8 *s_pte->slot_number + i, ((uintptr_t)fte->frame_number << 12) + BLOCK_SECTOR_SIZE * i);
	lock_release(&swap_lock);

  // Set bitmap entry to 0
	delete_swap_table_entry(s_pte->slot_number);    

  // Install page dircetory 
  if (!install_page ((uintptr_t)s_pte->page_number << 12, (uintptr_t)fte->frame_number << 12, s_pte->writable)) {  
    palloc_free_page ((uintptr_t)fte->frame_number << 12);
    free(fte);
    return false; 
  }
  
  // Modify s_pte information
  s_pte->fte = fte;
  s_pte->location = LOC_PHYS;   // Set current location to Physical Memory

  // Modify fte information               
  fte->s_pte = s_pte;
  fte->thread = thread_current();
  fte->pin = false;
		
  // Insert new frame table entry into frame_table
  insert_frame(fte);     

  return true;
}

void delete_swap_table_entry(uint32_t slot_number){     
  // Delete swap table entry with swap lock
	lock_acquire(&swap_lock);
  bitmap_set(swap_table, slot_number, false);
	lock_release(&swap_lock);
}
