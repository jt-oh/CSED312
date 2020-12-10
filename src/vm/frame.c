#include "vm/frame.h"
//#include "vm/page.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "userprog/syscall.h"

static struct list frame_table;
static struct frame_table_entry *current_fte;        // current position in clock algorithm
static struct lock frame_table_lock;

static void progress_current_fte();
static void remove_frame_entry (struct frame_table_entry *);
static struct frame_table_entry *find_eviction_frame();

void frame_init (){
  list_init (&frame_table);
  current_fte = NULL;
  lock_init(&frame_table_lock);
}

void insert_frame(struct frame_table_entry *fte){                      // insert frame_table_entry before currnet_position
  ASSERT(fte != NULL);

  // Get lock for accessing shoring resources
  lock_acquire(&frame_table_lock);
  
  // Frame table is empty
  if(current_fte == NULL){                    
		list_push_front(&frame_table, &fte->elem);
    current_fte = fte;
  }
  else{      
    list_insert(&current_fte->elem, &fte->elem);
  }
  
  lock_release(&frame_table_lock);
}

void progress_current_fte(){
  ASSERT(lock_held_by_current_thread(&frame_table_lock));

	if(list_empty(&frame_table)){
		current_fte = NULL;
		return;
	}

  // Do increment of current_fte
  if (current_fte != list_entry(list_prev(list_end(&frame_table)), struct frame_table_entry, elem))
    current_fte = list_entry(list_next(&current_fte->elem), struct frame_table_entry, elem);
  else
    current_fte = list_entry(list_begin(&frame_table), struct frame_table_entry, elem);

  return;
}

struct frame_table_entry *find_eviction_frame(){
  struct thread *t;
  struct frame_table_entry *result;

	ASSERT ( current_fte != NULL );
  ASSERT(lock_held_by_current_thread(&frame_table_lock));
  
  // Find eviction candidate
  while(1){
    t = current_fte->thread;
   
    if (!pagedir_is_accessed(t->pagedir, (uintptr_t)current_fte->s_pte->page_number << 12) && (current_fte->pin == false)){
      break;
    }
    else{ 
      pagedir_set_accessed(t->pagedir, (uintptr_t)current_fte->s_pte->page_number << 12, false);

      // If current_fte arrives to the end of the frame table, set it to the start of the table
      progress_current_fte();
    }
  }
  result = current_fte;
  
  // Increment current_fte
  progress_current_fte();
    
  return result;
}

void delete_frame_entry (struct frame_table_entry *fte){
  ASSERT (fte != NULL);

  lock_acquire(&frame_table_lock);
  
  // If current_fte == deletion frame entry, move next to the current_fte
  if(current_fte == fte){               
    progress_current_fte(); 
  }

  // Delete Frame table entry from frame table and Deallocate frame table entry
  list_remove(&fte->elem);    
  free(fte);
  
	if(list_empty(&frame_table))
		current_fte = NULL;

  lock_release(&frame_table_lock);
}

void remove_frame_entry (struct frame_table_entry *fte){
  ASSERT (fte != NULL);
  ASSERT (lock_held_by_current_thread(&frame_table_lock));

  // If current_fte == deletion frame entry, move next to the current_fte
  if(current_fte == fte){               
    progress_current_fte(); 
  }

  // Delete Frame table entry from frame table and Deallocate frame table entry
  list_remove(&fte->elem); 
  
	if(list_empty(&frame_table))
		current_fte = NULL;
}

struct frame_table_entry *frame_alloc(){
  uint8_t *kpage;
  struct frame_table_entry *fte;

  lock_acquire(&frame_table_lock);

  /* Get a page of memory. */
  kpage = palloc_get_page (PAL_USER);
  
  if(kpage == NULL){
    struct frame_table_entry *eviction = find_eviction_frame();    // When Physical memory is full, execute eviction
    if(eviction->s_pte->type == TYPE_FILE){
      mmap_write_back (eviction->s_pte);
    }
    else{
			ASSERT (eviction->s_pte->type == TYPE_EXEC || eviction->s_pte->type == TYPE_STACK);
      if(!swap_out(eviction)){                                       // Swap evicted frame into the swap table
				lock_release(&frame_table_lock);
				return NULL;
			}
    }
	
    // Deallocate s_pte, Physical Memory and corresponding fte
	  eviction->s_pte->fte = NULL;

    remove_frame_entry(eviction);
    pagedir_clear_page(eviction->thread->pagedir, (uintptr_t)eviction->s_pte->page_number << 12);

		fte = eviction;
		fte->s_pte = NULL;
		fte->thread = NULL;
  }
  else{
    /* Get a fte of memory. */
    fte = (struct frame_table_entry *)malloc(sizeof(struct frame_table_entry));
    if (fte == NULL){
        palloc_free_page(kpage);
				lock_release(&frame_table_lock);
        return NULL;
    }

    fte->frame_number = PG_NUM(kpage); 
  }
  
  lock_release(&frame_table_lock);

  return fte;
}
