#include "vm/page.h"
#include "threads/pte.h"

struct list frame_table;

struct frame_table_entry *current_fte;        // current position in clock algorithm

unsigned get_hash(unsigned page_number){      // Get Hash value with page number
	return page_number % 1024;
}

unsigned s_pt_hash_func(const struct hash_elem *e, void *aux){                          // hash_hash_function
  struct sPage_table_entry *s_pte;
  unsigned page_number;
  unsigned hash_value;

  ASSERT(e != NULL);

  s_pte = hash_entry(e, struct sPage_table_entry, elem);      // get Supplementary Page Table Entry with hash_elem e
  page_number = s_pte->page_number;                                 // get Virtual Address with Supplementary Page Table Entry
  hash_value = get_hash(page_number);                           // get hash value with MSB 20 bits of Virtual Address 

  return hash_value;
}

bool s_pt_less_func (const struct hash_elem *a_, const struct hash_elem *b_){           // hash_less_function
  struct sPage_table_entry *a = hash_entry(a_, struct sPage_table_entry, elem);
  struct sPage_table_entry *b = hash_entry(b_, struct sPage_table_entry, elem);

  ASSERT (a != NULL);
  ASSERT (b != NULL);

  return a->page_number < b->page_number;
}

struct sPage_table_entry *find_s_pte (void *vaddr){
  unsigned page_number;
  unsigned hash;
  struct list *bucket;
  struct thread *t = thread_current();
  struct list_elem *e;
  struct sPage_table_entry *result;

	//printf("Hi! find_s_pte!\n");
    
  page_number = PG_NUM(vaddr);                       // get Page Number of vaddr
	
	//printf("find_s_pte get page number!\n");

  hash = get_hash(page_number);    						// get hash of vaddr

	//printf("find_s_pte got hash!\n");

	//printf("tid %d\n", t->tid);

  bucket = &t->sPage_table.buckets[hash % t->sPage_table.bucket_cnt];           // get bucket with hash in sPage_Table

	//printf("find_spte got bucket!\n");

  if(list_empty(bucket))                           // Case: Bucket is empty
    return NULL;

	//printf("find_s_pte before get hash element\n");
	//printf("bucket size : %d \n", list_size(bucket));

  for(e = list_begin(bucket); e != list_end(bucket); e = list_next(e)){
    result = hash_entry(list_elem_to_hash_elem(e), struct sPage_table_entry, elem);
		//printf("check! page number %x\n", result->page_number);
    if(result->page_number == page_number){
     //printf("find hash element\n");
		 return result;                                // Case: Find vaddr in sPage_table
  	}
	}

	//printf("can't find hash element\n");

  return NULL;                                      // Case: Can't find vaddr in sPage_table
}

void insert_frame(struct frame_table_entry *fte){                      // insert frame_table_entry before currnet_position
  ASSERT(fte != NULL);

  if(current_fte == NULL){                     // Frame table is empty
    //printf("current_fte NULL\n");
		list_push_front(&frame_table, &fte->elem);
    current_fte = fte;
  }
  else{      
    //printf("current_fte not NULL\n");
    list_insert(&current_fte->elem, &fte->elem);
  }
}

struct frame_table_entry *find_eviction_frame(){
  struct thread *t;
  struct frame_table_entry *result;
  
  while(1){
    t = current_fte->thread;
    if (!pagedir_is_accessed(&t->pagedir, (uintptr_t)current_fte->s_pte->page_number << 12))
      break;
    else{ 
      pagedir_set_accessed(&t->pagedir, (uintptr_t)current_fte->s_pte->page_number << 12, false);

      if (current_fte != list_prev(list_end(&frame_table)))
        current_fte = list_entry(list_next(&current_fte->elem), struct frame_table_entry, elem);
      else
        current_fte = list_entry(list_begin(&frame_table), struct frame_table_entry, elem);
    }
  }

  result = current_fte;
  
  if (current_fte != list_prev(list_end(&frame_table)))
    current_fte = list_entry(list_next(&current_fte->elem), struct frame_table_entry, elem);
  else
    current_fte = list_entry(list_begin(&frame_table), struct frame_table_entry, elem);
    
  return result;
}

void delete_frame_entry (struct frame_table_entry *e){
  ASSERT (e != NULL);

  if(current_fte == e){               // If current_fte == deletion frame entry, move next to the current_fte
    if (current_fte != list_prev(list_end(&frame_table)))
      current_fte = list_entry(list_next(&current_fte->elem), struct frame_table_entry, elem);
    else
      current_fte = list_entry(list_begin(&frame_table), struct frame_table_entry, elem);  
  }

  list_remove(&e->elem);              // Delete Frame table entry from frame table
  free(e);                            // Deallocate frame table entry
}
