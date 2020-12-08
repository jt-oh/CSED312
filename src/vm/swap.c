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

size_t find_empty_swap_slot(){                        // Find empy swap slot
  return bitmap_scan_and_flip(swap_table, 0, 1, false);
}

bool swap_out (struct frame_table_entry *e){
  ASSERT (e != NULL);

  size_t index;
  int i;

  index = find_empty_swap_slot();                         // Get empty swap slot
  if(index == BITMAP_ERROR)                               // If no empty swap, return false
    return false;

  // Store Frame Data into Swap slot
  for (i=0; i<8; i++) {
    lock_acquire(&swap_lock);
		printf("before block write in swap_out by %s %d\n", thread_current()->name, thread_current()->tid);
    block_write(swap_slots, 8 * index + i, ((uintptr_t)e->frame_number << 12) + BLOCK_SECTOR_SIZE * i);
		printf("finish block write in swap_out by %s %d\n", thread_current()->name, thread_current()->tid);
    lock_release(&swap_lock);
  }

  e->s_pte->location = LOC_SWAP;
  e->s_pte->slot_number = index;                           // store swap index

  return true;
}

bool swap_in (struct sPage_table_entry *e){
  ASSERT (e != NULL);
  
  uint8_t *kpage;
  int i;
  struct frame_table_entry *fte;

  kpage = palloc_get_page (PAL_USER);
  if(kpage == NULL)
    return false;

	//printf("1\n");

  for(i=0; i<8; i++){            //Read block in Swap table 
    lock_acquire(&swap_lock);
		printf("before block read in swap_in by %s %d\n", thread_current()->name, thread_current()->tid);
    block_read(swap_slots, 8 * e->slot_number + i, kpage + BLOCK_SECTOR_SIZE * i);
		printf("finish block read in swap_in by %s %d\n", thread_current()->name, thread_current()->tid);
    lock_release(&swap_lock);
  }
	//printf("2\n");

	delete_swap_table_entry(e->slot_number);    // Set bitmap entry to 0
  
	//printf("3\n");

  if (!install_page ((uintptr_t)e->page_number << 12, kpage, e->writable)) {  // Bring Swap table entry to Physical memory
    palloc_free_page (kpage);
    return false; 
  }

  fte = (struct frame_table_entry *)malloc(sizeof(struct frame_table_entry));
  if(fte == NULL){
    palloc_free_page (kpage);
    return false;
  }
  
  e->fte = fte;
  e->location = LOC_PHYS;   // Set current location to Physical Memory

   // Initialize fte
  fte->frame_number = PG_NUM(kpage);                 
  fte->s_pte = e;
  fte->thread = thread_current();
  fte->pin = false;

	//printf("4\n");
		
  insert_frame(fte);     // Insert new frame table entry into frame_table\

	//printf("5\n");

  return true;
}

void delete_swap_table_entry(uint32_t slot_number){     // Delete swap table entry 
  bitmap_set(swap_table, slot_number, false);
}
