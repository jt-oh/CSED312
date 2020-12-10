#include "vm/page.h"
#include "threads/pte.h"
#include <stdlib.h>
#include <stdio.h>
#include "userprog/syscall.h"
#include "userprog/exception.h"

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
    
  // get Page Number of vaddr
  page_number = PG_NUM(vaddr);                       

  // get hash of vaddr
  hash = get_hash(page_number);    						

  // get bucket with hash in sPage_Table
  bucket = &t->sPage_table.buckets[hash % t->sPage_table.bucket_cnt];           

  // Case: Bucket is empty
  if(list_empty(bucket))                           
    return NULL;

  // Case: Find vaddr in sPage_table
  for(e = list_begin(bucket); e != list_end(bucket); e = list_next(e)){
    result = hash_entry(list_elem_to_hash_elem(e), struct sPage_table_entry, elem);
    if(result->page_number == page_number)
		 return result;                                
	}

  // Case: Can't find vaddr in sPage_table
  return NULL;                                      
}

void s_pte_fte_ste_deallocator (struct hash_elem *e, void *aux){
  ASSERT (e != NULL);

  struct sPage_table_entry *s_pte;

  // Get s_pte
  s_pte = hash_entry(e, struct sPage_table_entry, elem);    

  if(s_pte->location == LOC_PHYS){
		palloc_free_page((uintptr_t)s_pte->fte->frame_number << 12);
		pagedir_clear_page(s_pte->fte->thread->pagedir, (uintptr_t)s_pte->page_number << 12);
    delete_frame_entry(s_pte->fte);
	}
  else if(s_pte->location == LOC_SWAP)
    delete_swap_table_entry(s_pte->slot_number);

  // Deallocate s_pte
  free(s_pte);
}

void deallocate_mmap_file (struct mmap_file *mm_file){
  struct list_elem *e;
  struct sPage_table_entry *s_pte;
  struct thread *t = thread_current();

  ASSERT ( mm_file != NULL);
  ASSERT ( t != NULL);

  // Deallocate all resources related to all s-pte in mmap table
  while(!list_empty(&mm_file->s_pte_list)){
    e = list_begin(&mm_file->s_pte_list);
    s_pte = list_entry(e, struct sPage_table_entry, mmap_table_elem);
    if(s_pte->location == LOC_PHYS){  
      // write back frame data into the file if the frame is dirty    
      mmap_write_back (s_pte);
      // deallocate physical memory and update page table
      palloc_free_page((uintptr_t)s_pte->fte->frame_number << 12);
	    pagedir_clear_page(s_pte->fte->thread->pagedir, (uintptr_t)s_pte->page_number << 12);

      // deallocate corresponding frame entry
      delete_frame_entry(s_pte->fte);
    }

    // deallocate s_pte
    list_remove(e);
    hash_delete (&t->sPage_table, &s_pte->elem);
    free(s_pte);
  }

  // deallocate mmap_file 
  lock_acquire(&file_lock);
  file_close(mm_file->file);
  lock_release(&file_lock);
  
  // deallocate mmapep file structrue
  list_remove(&mm_file->elem);
  free(mm_file);
}

void pin_buffer(void *buffer, size_t read_bytes){
  struct sPage_table_entry *s_pte;
  struct frame_table *fte;
  void *end = (uintptr_t)buffer + read_bytes;
  int n = PG_NUM(end) - PG_NUM(buffer) + 1;
  int i;

  for(i = 0; i < n; i++){
    s_pte = find_s_pte((uintptr_t)buffer + i * PGSIZE);
		if(s_pte == NULL)
			Exit(-1);

		if(s_pte->location == LOC_PHYS){
      // pin page with buffer + i * PGSIZE in physical memory
			s_pte->fte->pin = true;
			continue;

			NOT_REACHED();
		}

    // Check whether free physical memory space remained 
    fte = frame_alloc();
    if(fte == NULL)
      Exit(-1);

    switch(s_pte->location){      // Devide cases into where the Memory data's location is
      case LOC_NONE:
        if(s_pte->type == TYPE_STACK){
          if(!stack_growth(s_pte, fte))
            Exit(-1);
            break;
        }
      case LOC_FILE:
        if(!load_files(s_pte, fte))
          Exit(-1);
        break;
      case LOC_SWAP:
        if(!swap_in(s_pte, fte))
          Exit(-1);
        break;      
      default:
	   		break;
    }

    // pin page with buffer + i * PGSIZE in physical memory
    s_pte->fte->pin = true;
  }
}

void unpin_buffer(void *buffer, size_t read_bytes){
  struct sPage_table_entry *s_pte;
  void *end = (uintptr_t)buffer + read_bytes;
  int n = PG_NUM(end) - PG_NUM(buffer) + 1;
  int i;

  for(i = 0; i < n; i++){
    s_pte = find_s_pte((uintptr_t)buffer + i * PGSIZE);
    ASSERT (s_pte != NULL);
		ASSERT (s_pte->fte != NULL);
    
    // unpin page with buffer + i * PGSIZE in physical memory
    s_pte->fte->pin = false;
  }
}
