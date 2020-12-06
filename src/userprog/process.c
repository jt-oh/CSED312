#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

// SOS Implementation project 3
#include "vm/page.h"  
#include "threads/pte.h"
// End SOS Implementation project 3

#define DELIM " "   //SOS implementation

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  // SOS Implementation
  char *file_name_;   
  char *token;      
  char *next_ptr;    
  // End SOS Implementation

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);

  // SOS Implementation
  //file_name_ is used for first token of cmd line
	file_name_ = palloc_get_page(0);		
  if (fn_copy == NULL || file_name_ == NULL)
    return TID_ERROR;
  // End SOS Implementation

  strlcpy (fn_copy, file_name, PGSIZE);
  
  // SOS Implementation
  strlcpy(file_name_, file_name, PGSIZE);	
  token = strtok_r(file_name_, DELIM, &next_ptr);       // Extract file name in the command

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (token, PRI_DEFAULT, start_process, fn_copy);   

  palloc_free_page (file_name_);                        // free resources
  // End SOS Implementation

  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  /*SOS Implementation*/
  char *fn_copy;
  char **parse;     
  char *token;
  char *next_ptr;
  int token_cnt = 0;    
  int i;
  /* End SOS Implementation*/

  struct intr_frame if_;
  bool success;

  /* SOS Implementation project 2 */

  // allocate page to 'fn_copy'
  fn_copy = palloc_get_page (0);

  if (fn_copy == NULL){
  	sema_up(&thread_current()->parent->child_load);        // if page allocation fails
    palloc_free_page (file_name);                          // free resouces and exit thread
		thread_exit();
	}

  // count argc
  strlcpy (fn_copy, file_name, PGSIZE);
  token = strtok_r(fn_copy, DELIM, &next_ptr);
  while(token != NULL){
    token = strtok_r(NULL, DELIM, &next_ptr);
    token_cnt++;
  } 

  // allocate memory to 'parse'
  parse = (char **)malloc(sizeof(char *) * token_cnt);
	if(parse == NULL){                                        // if page allocation fails
  	sema_up(&thread_current()->parent->child_load);         // free resouces and exit thread
    palloc_free_page (file_name);
    palloc_free_page(fn_copy);
		thread_exit();
	}

  // store tokens into 'parse'
  strlcpy (fn_copy, file_name, PGSIZE);
  token = strtok_r(fn_copy, DELIM, &next_ptr);
    for(i=0; i<token_cnt; i++){      
      parse[i] = token;
      token = strtok_r(NULL, DELIM, &next_ptr);
    } 
  /* End SOS Implementation*/

  // SOS Implementation project 3
  if(!hash_init(&thread_current()->sPage_table, s_pt_hash_func, s_pt_less_func, NULL)){    //sPage table init
		free (parse);                                       // If hash init fails,
		palloc_free_page (file_name);                       // free resouces and exit thread
		palloc_free_page (fn_copy);    
    thread_exit();
  }

  // End SOS Implementation

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  // SOS Implementation project 2
  // passing first token of cmd line to load()
  success = load (parse[0], &if_.eip, &if_.esp);  

  // Inform to Parent that complete child's load
  sema_up(&thread_current()->parent->child_load);

  if (!success) {
		free (parse);                                       // If load fails,
		palloc_free_page (file_name);                       // free resouces and exit thread
		palloc_free_page (fn_copy);
		thread_exit();									
	}

  // push arguments into user stack 
  push_arg_to_stack(parse, token_cnt, &if_.esp);  
  free(parse);         
  // End SOS Implementation

  palloc_free_page (file_name);		// SOS Implementation project 2
	palloc_free_page (fn_copy);

	//printf("start process finish!\n");
	//printf("tid %d\n", thread_current()->tid);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  /* SOS Implementation Projcct 2 */
  struct thread *child = get_child_process(child_tid);
  int status;

  // Return with -1 when child_tid does not exist in Parent's child list
  if(!child)
    return -1;

  sema_down(&child->child_exit);    // Parent has to wait until the child exits

  status = child->exit_status;      // Store child's exit status

  remove_child_process(child);      // When a child exits, parent delete it

  return status;
}
/* End SOS Imlementation */

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  int i;    //SOS Implementation
  struct list_elem *e;
  struct mmap_file *mm_file;

	// SOS Implementation project3 - deallocate mmaped files
  while(!list_empty(&cur->mmap_table)){
    e = list_begin(&cur->mmap_table);
    mm_file = list_entry(e, struct mmap_file, elem);
    deallocate_mmap_file(mm_file);
  }
	// End SOS Implementation

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  
  /* SOS Implementation project 2*/
  if(cur->running_file != NULL)         // if there exists executable, 
		file_close(cur->running_file);      // allow write using file_close

  for(i=2; i<cur->fd; i++)              // Close all fd in the exiting process
    process_close_file(i);

  // Project 3 Deallocate sPage table
  hash_destroy(&cur->sPage_table, s_pte_fte_ste_deallocator);
  /*End SOS Implementation */
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

	//printf("file name: %s!\n", file_name);

  /* Open executable file. */
  file = filesys_open (file_name);   

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
							//printf("before load)segment\n");
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
							//printf("after load)segment\n");
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
	//printf("before setup_stack\n");
  if (!setup_stack (esp))
    goto done;
	//printf("after setup_stack\n");

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */

  /* SOS Implementation project 2 */
  if(success){                                // If load success,
		thread_current()->running_file = file;    // store executable and
  	file_deny_write(file);                    // deny write on executables
	}
	else{
		if(file != NULL)                          // if load success, 
			file_close (file);                      // make sure file closed
	}

	//printf("load Finish!\n");
  /* END SOS Implementation */
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  // SOS Implementation Project 3
  struct sPage_table_entry *s_pte;
  int i = 0;      
  
  // End SOS Implementation

  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      // SOS Implementation Project 3
 			s_pte = (struct sPage_table_entry *)malloc(sizeof(struct sPage_table_entry));
  
			if(s_pte == NULL)       // If allocation failed, return false
    		return false;

      s_pte->type = TYPE_EXEC;
      s_pte->location = LOC_NONE;     // Current location is just in Virtual Space
      s_pte->page_number = PG_NUM(upage);
      s_pte->writable = writable;
      s_pte->file = file;
      s_pte->fte = NULL;
      s_pte->offset = ofs + i * PGSIZE;
      s_pte->read_bytes = page_read_bytes;
      s_pte->zero_bytes = page_zero_bytes;

      hash_insert(&thread_current()->sPage_table, &s_pte->elem);
			//printf("%d page_number %x\n", i, s_pte->page_number);

      // End SOS Implementation

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      i++;                   // SOS Implementation Project 3
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  // SOS Implementation project 3
  struct sPage_table_entry *s_pte;           
  struct frame_table_entry *fte;
  // End SOS Implementation project 3

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);

  // SOS Implementation project 3
  s_pte = (struct sPage_table_entry *)malloc(sizeof(struct sPage_table_entry));      
  fte = (struct frame_table_entry *)malloc(sizeof(struct frame_table_entry));
  // End SOS Implementation project 3
  
  if (kpage != NULL && s_pte != NULL && fte != NULL)          // SOS Implementation project 3
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success){
        *esp = PHYS_BASE;
        
        // SOS Implementation project 3
        s_pte->type = TYPE_EXEC;                                       // Initialize s_pte
        s_pte->location = LOC_PHYS;                                    // Current location is in Physical memory
        s_pte->page_number = PG_NUM((uint8_t *)PHYS_BASE - PGSIZE);
        s_pte->writable = true;
        s_pte->file = NULL;
        s_pte->fte = fte;
        s_pte->offset = 0;
        s_pte->read_bytes = 0;
        s_pte->zero_bytes = PGSIZE;
        
        fte->frame_number = PG_NUM(kpage);                             // Initialize fte
        fte->s_pte = s_pte;
        fte->thread = thread_current();
        
        hash_insert(&thread_current()->sPage_table, &s_pte->elem);     // Insert s_pte into sPageTable
				//printf("page_number %x\n with frame number %x\n", s_pte->page_number, kpage);

        insert_frame(fte);                                      // Insert fte into frame_table
        
        // End SOS Implementation project 3
      }
      else{
        palloc_free_page (kpage);
        // SOS Implementation project 3
        free(s_pte);
        free(fte);
        // End SOS Implementation project 3
      }
    }

  // SOS Implementation project 3
  if(!success){                 // If not success but resources are allocated, free them
    if(kpage)
      palloc_free_page(kpage);
    if(s_pte)
      free(s_pte);
    if(fte)
      free(fte);
  }
  // End SOS Implementation project 3

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


// SOS Implemenatation
void push_arg_to_stack (char **argv, int argc, void **esp){
  int i, j;
  char **argv_address = (char **)malloc(sizeof(char *) * argc);

  // argv[n][m]
  for(i = argc - 1; i > -1; i--){
    for(j = strlen(argv[i]); j > -1; j--){
      *esp = (uintptr_t)*esp - (uintptr_t)1;
      **(char **)esp = argv[i][j];
    }
    argv_address[i] = (char *)*esp;
  }

  // alignment
  while((uintptr_t)*esp & (uintptr_t)3){
    *esp = (uintptr_t)*esp - (uintptr_t)1;
    *(uint8_t *)*esp = (uint8_t)0;
  }

  // argv[argc]
  *esp = (uintptr_t)*esp - (uintptr_t)4;
  *(char **)*esp = (char *)0;

  // argv[n]
  for(i = argc - 1; i > -1; i--){
    *esp = (uintptr_t)*esp - (uintptr_t)4;
    *(char **)*esp = argv_address[i];
  }

  // argv
  *esp = (uintptr_t)*esp - (uintptr_t)4;
  *(char ***)*esp = (uintptr_t)*esp + (uintptr_t)4;

  // argc
  *esp = (uintptr_t)*esp - (uintptr_t)4;
  *(int *)*esp = argc;

  // return address
  *esp = (uintptr_t)*esp - (uintptr_t)4;
  *(void **)*esp = (void *)0;

  free(argv_address);
  }

struct thread *get_child_process(tid_t tid){
  struct thread *t = thread_current();
  struct list_elem *e;

  ASSERT (t != NULL);

  // Find the child thread which has the same tid in child_list
  for(e = list_begin(&t->child_list); e != list_end(&t->child_list); e = list_next(e)){
    if(list_entry(e, struct thread, child_elem)->tid == tid)
      return list_entry(e, struct thread, child_elem);
  }

  // If tid doesn't exists, return NULL
  return NULL;  
}

void remove_child_process (struct thread *child){
  struct thread *t = thread_current();
  struct list_elem *e;
  
  ASSERT (t != NULL);
  ASSERT (child != NULL);

  // Delete child in Parent's child list
  for(e = list_begin(&t->child_list); e != list_end(&t->child_list); e = list_next(e)){
    if(list_entry(e, struct thread, child_elem) == child){
      list_remove(e);
      break;
    }
  }

  ASSERT (child->status == THREAD_DYING);
  ASSERT (child != t);

  // Free Resources
  if (child->status == THREAD_DYING && child != t){
    if(child->fd_table != NULL)
      palloc_free_page (child->fd_table);        
    palloc_free_page (child);
  }
}

// End SOS Implementation
