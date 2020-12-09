#include "vm/swap.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include <stdlib.h>

static struct block *swap_slots;          // Swap Block Device
static struct bitmap *swap_table;          // Swap Bitmap Table
struct lock swap_table_lock;                    // Lock for swap devices

void swap_init(){
  swap_slots = block_get_role(BLOCK_SWAP);              // Get Swap block device
  swap_table = bitmap_create(block_size(swap_slots) / 8);     // Create swap table with size of #sector/8
  bitmap_set_all(swap_table, false);                    // Initialize swap table
  lock_init(&swap_table_lock);
}

size_t find_empty_swap_slot(){       
  ASSERT (lock_held_by_current_thread(&swap_table_lock));
  
  return bitmap_scan_and_flip(swap_table, 0, 1, false);     // Find empy swap slot
}

bool swap_out (struct frame_table_entry *e){
  ASSERT (e != NULL);

  size_t index;
  int i;

  lock_acquire(&swap_table_lock);
  
  index = find_empty_swap_slot();                         // Get empty swap slot
  if(index == BITMAP_ERROR)                               // If no empty swap, return false
    return false;

  // Store Frame Data into Swap slot
	//printf("before block write in swap_out by %s %d\n", thread_current()->name, thread_current()->tid);
  for (i=0; i<8; i++) {
    block_write(swap_slots, 8 * index + i, ((uintptr_t)e->frame_number << 12) + BLOCK_SECTOR_SIZE * i);
  }
	//printf("finish block write in swap_out by %s %d\n", thread_current()->name, thread_current()->tid);

  e->s_pte->location = LOC_SWAP;
  e->s_pte->slot_number = index;                           // store swap index

  lock_release(&swap_table_lock);
  
  return true;
}

bool swap_in (struct sPage_table_entry *e, struct frame_table_entry *fte){
  ASSERT (e != NULL);
  ASSERT (fte != NULL);
  
  int i;

	//printf("before block read in swap_in by %s %d\n", thread_current()->name, thread_current()->tid);
  lock_acquire(&swap_table_lock);
  
  for(i=0; i<8; i++){            //Read block in Swap table 
    block_read(swap_slots, 8 * e->slot_number + i, (uintptr_t)fte->frame_number << 12 + BLOCK_SECTOR_SIZE * i);
  }
	//printf("finish block read in swap_in by %s %d\n", thread_current()->name, thread_current()->tid);
	//printf("2\n");

	delete_swap_table_entry(e->slot_number);    // Set bitmap entry to 0
  
	//printf("3\n");

  if (!install_page ((uintptr_t)e->page_number << 12, (uintptr_t)fte->frame_number << 12, e->writable)) {  // Bring Swap table entry to Physical memory
    palloc_free_page ((uintptr_t)fte->frame_number << 12);
    free((uintptr_t)fte->frame_number << 12);
    return false; 
  }
  
  e->fte = fte;
  e->location = LOC_PHYS;   // Set current location to Physical Memory

   // Initialize ftE                
  fte->s_pte = e;
  fte->thread = thread_current();
  fte->pin = false;

	//printf("4\n");
		
  insert_frame(fte);     // Insert new frame table entry into frame_table\

	//printf("5\n");
  lock_release(&swap_table_lock);

  return true;
}

void delete_swap_table_entry(uint32_t slot_number){     // Delete swap table entry 
  ASSERT (lock_held_by_current_thread(&swap_table_lock));

  bitmap_set(swap_table, slot_number, false);
}
