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

  lock_acquire(&frame_table_lock);
  
  if(current_fte == NULL){                     // Frame table is empty
    //printf("current_fte NULL\n");
		list_push_front(&frame_table, &fte->elem);
    current_fte = fte;
		//printf("vpage is %p\n", (uintptr_t)current_fte->s_pte->page_number << 12);
  }
  else{      
    //printf("current_fte not NULL\n");
		//printf("current_fte frame %p\n", current_fte);
		//printf("fte frame %p\n", fte->frame_number);
    list_insert(&current_fte->elem, &fte->elem);
  }
	//printf("insert_frame finish!\n");
  
  lock_release(&frame_table_lock);
}

void progress_current_fte(){

  ASSERT(lock_held_by_current_thread(&frame_table_lock));

	if(list_empty(&frame_table)){
		current_fte = NULL;
		return;
	}

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
		//printf("vpage is %p\n", (uintptr_t)current_fte->s_pte->page_number << 12);
   
    if (!pagedir_is_accessed(t->pagedir, (uintptr_t)current_fte->s_pte->page_number << 12) && current_fte->pin == false){
      //printf("1\n");
      break;
    }
    else{ 
      pagedir_set_accessed(t->pagedir, (uintptr_t)current_fte->s_pte->page_number << 12, false);
      //printf("2\n");

      // If current_fte arrives to the end of the frame table, set it to the start of the table
      progress_current_fte();
    }
  }
  result = current_fte;
	//printf("find eviction candidate in find_eviction_frame\n");
  
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

  fte->s_pte->fte = NULL;
  
	if(list_empty(&frame_table))
		current_fte = NULL;
}

struct frame_table_entry *frame_alloc(){
  uint8_t *kpage;
  struct frame_table_entry *fte;

  lock_acquire(&frame_table_lock);
  
  if(!check_physical_memory()){
	 	//printf("eviction occur!\n");
    struct frame_table_entry *eviction = find_eviction_frame();    // When Physical memory is full, execute eviction
		//printf("candidate find!\n");
    if(eviction->s_pte->type == TYPE_EXEC){
      if(!swap_out(eviction))                                       // Swap evicted frame into the swap table
        return false;

        //printf("swap out fail!\n");
    }
    else if(eviction->s_pte->type == TYPE_FILE){
      //printf("mmap_write_back ", TYPE_FILE);
      mmap_write_back (eviction->s_pte);
      // type == mmapped file
    }

			//printf("1\n");

		// Deallocate Physical Memory and corresponding fte
			// palloc_free_page((uintptr_t)eviction->frame_number << 12);
    remove_frame_entry(eviction);
    pagedir_clear_page(eviction->thread->pagedir, (uintptr_t)eviction->s_pte->page_number << 12);

		fte = eviction;
  }
  else{
    /* Get a page of memory. */
    kpage = palloc_get_page (PAL_USER);
    if (kpage == NULL)
        return NULL;

      //printf("1\n");

    /* Get a fte of memory. */
    fte = (struct frame_table_entry *)malloc(sizeof(struct frame_table_entry));
    if (fte == NULL){
        palloc_free_page(kpage);
        return NULL;
    }

    fte->frame_number = PG_NUM(kpage); 
  }
  
  lock_release(&frame_table_lock);

	//printf("page Alloc kpage %p\n", kpage);

  return fte;
}
