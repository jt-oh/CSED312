#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
// SOS Implementation
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/filesys.h"

#include "filesys/file.h"
#include "vm/page.h"
// End SOS Implementation


#define STDIN_FILENO 0
#define STDOUT_FILENO 1

static void syscall_handler (struct intr_frame *);

// SOS Implementation
struct lock file_lock;              // lock for accessing file system
static struct lock mapid_lock;      // lock for mapid allocation - project 3
// End SOS Implementation

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);    // SOS Implementation project2
	lock_init(&mapid_lock);		// SOS Implementation project3
}


/* SOS Implementation */
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int number;
  int *arg;
  uint32_t result;

  if(!isValid_Vaddr(f->esp))
    Exit(-1);

  // get syscall number
  number = *(int *)f->esp;

  // assign to each syscall handler func
  switch(number){
    case SYS_HALT:
            Halt();
          break;

    case SYS_EXIT:
            arg = (int *)malloc(sizeof(int) * 1);     // allocate arg for storing arguments
            pop_arg_from_stack(f->esp, arg, 1);       // get arg from user stack
            Exit(arg[0]);
          break;

    case SYS_EXEC:  
            arg = (int *)malloc(sizeof(int) * 1);
            pop_arg_from_stack(f->esp, arg, 1);
            if(!isValid_Vaddr(arg[0])){               // If user provided pointer is invalid Vaddr
              free(arg);                              // free resources and exit with -1
              Exit(-1);
            }
            result = Exec(arg[0]);
          break;

    case SYS_WAIT:
            arg = (int *)malloc(sizeof(int) * 1);
            pop_arg_from_stack(f->esp, arg, 1);
            result = Wait(arg[0]);
          break;

    case SYS_CREATE:
						arg = (int *)malloc(sizeof(int) * 2);
            pop_arg_from_stack(f->esp, arg, 2);
            if(!isValid_Vaddr(arg[0])){
              free(arg);
              Exit(-1);
            }
            result = Create(arg[0], arg[1]);
          break;

    case SYS_REMOVE:
            arg = (int *)malloc(sizeof(int) * 1);
            pop_arg_from_stack(f->esp, arg, 1);
            if(!isValid_Vaddr(arg[0])){
              free(arg);
              Exit(-1);
            }
            result = Remove(arg[0]);
          break;
            
    case SYS_OPEN:
            arg = (int *)malloc(sizeof(int) * 1);
            pop_arg_from_stack(f->esp, arg, 1);
            if(!isValid_Vaddr(arg[0])){
              free(arg);
              Exit(-1);
            }
            result = Open(arg[0]);
          break;
            
    case SYS_FILESIZE:
            arg = (int *)malloc(sizeof(int) * 1);
            pop_arg_from_stack(f->esp, arg, 1);
            result = Filesize(arg[0]);
          break;

    case SYS_READ:
            arg = (int *)malloc(sizeof(int) * 3);
            pop_arg_from_stack(f->esp, arg, 3);
            if(!isValid_Vaddr(arg[1])){
              free(arg);
              Exit(-1);
            }
            result = Read(arg[0], arg[1], arg[2]);
          break;
            
    case SYS_WRITE:  
            arg = (int *)malloc(sizeof(int) * 3);
            pop_arg_from_stack(f->esp, arg, 3);
            if(!isValid_Vaddr(arg[1])){
              free(arg);
              Exit(-1);
            }
            result = Write(arg[0], arg[1], arg[2]);
          break;

    case SYS_SEEK:
            arg = (int *)malloc(sizeof(int) * 2);
            pop_arg_from_stack(f->esp, arg, 2);
            Seek(arg[0], arg[1]);
          break;
            
    case SYS_TELL:
            arg = (int *)malloc(sizeof(int) * 1);
            pop_arg_from_stack(f->esp, arg, 1);
            result = Tell(arg[0]);
          break;
            
    case SYS_CLOSE:
            arg = (int *)malloc(sizeof(int) * 1);
            pop_arg_from_stack(f->esp, arg, 1);
            Close(arg[0]);
          break;

    case SYS_MMAP:
            arg = (int *)malloc(sizeof(int) * 2);
            pop_arg_from_stack(f->esp, arg, 2);
            result = Mmap(arg[0], arg[1]);
          break;

    case SYS_MUNMAP:
            arg = (int *)malloc(sizeof(int) * 1);
            pop_arg_from_stack(f->esp, arg, 1);
            Munmap(arg[0]);
          break;

    default:
					break;
  }

  // free arg
  switch(number){
    case SYS_HALT :
            break;
    default: free(arg);
  }

  // put return value to EAX
  switch(number){
    case SYS_CLOSE:
    case SYS_SEEK:
    case SYS_EXIT:
		case SYS_MUNMAP:
            break;
    default:
            f->eax = result;
  }
}

bool isValid_Vaddr (void *addr){
  struct thread *t = thread_current ();
	int i;

  // validness check for addr~addr+3
	for(i = 0; i < 4; i++){
  	// check whether addr is included in user memory

  	if(!is_user_vaddr((uintptr_t)addr + i))
    	return false;

  	// find the address of page table entry and check whether it is not NULL 
  	if(!find_s_pte((uintptr_t)addr + i))        // SOS Implementation project 3
    	return false;
	}

	return true;
}

bool check_writable(void *buffer){
  struct sPage_table_entry *s_pte;

	s_pte = find_s_pte((uintptr_t)buffer);
	if(s_pte == NULL)
		return false;

	return s_pte->writable;
}

void pop_arg_from_stack (void *esp, int *arg, int n){
  int i;

  // pass syscall number in user stack
	esp = (uintptr_t)esp + (uintptr_t)4;        

  
  for(i = 0; i < n; i++){
    // Check the validness of esp access
		if(!isValid_Vaddr(esp)){				
			free(arg);
			Exit(-1);
		}
    // get argument
    arg[i] = *(int *)esp;                         
    esp = (uintptr_t)esp + (uintptr_t)4; 
  }
  
  return;
}

/* Sys Calls */
void Halt (void){
  // shut down pintos
  shutdown_power_off();
}

void Exit (int status){
  struct thread *t = thread_current();

  ASSERT (t != NULL);

  // print exit status
  printf("%s: exit(%d)\n", t->name, status);

  // Store status at exit status
  t->exit_status = status;

  // call thread_exit() to terminate process
  thread_exit();
}

pid_t Exec(const char *cmd_line){
  pid_t pid;
  struct thread *t;

  ASSERT (isValid_Vaddr(cmd_line));
 
  pid = process_execute(cmd_line);

  // Parent has to wait until child process finish loading
  if(pid !=  TID_ERROR)
    sema_down(&thread_current()->child_load);

  ASSERT (t = get_child_process(pid));

  if(t->running_file == NULL)   // If process start fails, return -1
    pid = -1;
    
  return pid;
}

int Wait (pid_t pid){
  return process_wait(pid);       // wait until the process_wait finishes
}

bool Create (const char *file, unsigned initial_size){
  ASSERT (isValid_Vaddr(file));

	bool result;

  // pin page with user-provided pointer to physical memory 
  pin_buffer(file, strlen(file));             

  // Create file with the given name file while grapping file lock
	lock_acquire(&file_lock);
  result = filesys_create(file, initial_size);
	lock_release (&file_lock);

  // unpin page with user-provided pointer to physical memory 
  unpin_buffer(file, strlen(file));

	return result;
}

bool Remove (const char *file){
  ASSERT (isValid_Vaddr(file));

	bool result;

  // Remove file with the given name file
  pin_buffer(file, strlen(file));
	lock_acquire(&file_lock);
  result = filesys_remove(file);
	lock_release(&file_lock);
  unpin_buffer(file, strlen(file));

	return result;
}

int Open (const char *file_){

  ASSERT (isValid_Vaddr(file_));

  struct file *file;

	lock_acquire(&file_lock);
	file = filesys_open(file_);
	lock_release(&file_lock);

	if(file)
		return process_create_file(file);   // get new fd with the given name file
	else
		return -1;
}

int Filesize (int fd){
  struct file *file = process_get_file (fd);
	int result;

  if(file == NULL)
		return 0;

  // Get file size with the given fd
	lock_acquire(&file_lock);
  result = file_length(file);
	lock_release(&file_lock);

	return result;
}

int Read (int fd, void *buffer, unsigned size){
  struct file *file = process_get_file (fd);
  int result;

  ASSERT (isValid_Vaddr(buffer));

	if(!check_writable(buffer))
		Exit(-1);

  if(fd == STDIN_FILENO){           // Reading on Standard Input case
    for(result = 0; result < size; result++)
      ((uint8_t *)buffer)[result] = input_getc();
  }
  else if(file != NULL && fd > 1 && fd < thread_current()->fd){            // Reading on other input case	
    // pin page with user-provided pointer to physical memory 
    pin_buffer(buffer, size);

    // acquire lock to guarantee mutual exclusion to the file access
  	lock_acquire(&file_lock);
    result = file_read(file, buffer, size);
  	lock_release(&file_lock);

    // unpin page with user-provided pointer to physical memory 
    unpin_buffer(buffer, size);
  }
  else{                             // Exception case
    result = -1;
  }

  return result;
}

int Write (int fd, const void * buffer, unsigned size){
  struct file *file = process_get_file (fd);
  int result;

  ASSERT (buffer != NULL);
 
  if(fd == STDOUT_FILENO){            // Writing on Standard Output case
    putbuf(buffer, size);
    result = size;
  }
  else if(file != NULL && fd > 1 && fd < thread_current()->fd){              // Writing on other output case
    // pin page with user-provided pointer to physical memory 
    pin_buffer(buffer, size);

  	// acquire lock to guarantee mutual exclusion to the file access
  	lock_acquire(&file_lock);
    result = file_write(file, buffer, size);
  	lock_release(&file_lock);

    // unpin page with user-provided pointer to physical memory 
    unpin_buffer(buffer, size);
  }
  else{                               // Exception case
    result = -1;
  }

  return result;
}

void Seek (int fd, unsigned position){
  struct file *file = process_get_file (fd);

  if(file == NULL)
		return 0;

  // Change the position of the file with the given fd about position size
	lock_acquire(&file_lock);
  file_seek(file, position);
	lock_release(&file_lock);
}

unsigned Tell (int fd){
 struct file *file = process_get_file (fd);
 unsigned result;

  if(file == NULL)
		return 0;

  // Get file psotion with the given fd 
	lock_acquire(&file_lock);
  result = file_tell(file);
	lock_release(&file_lock);

	return result;
}

void Close (int fd){
  // Close the file with the given fd
  process_close_file(fd);
}

/* End Sys Calls */ 

int process_create_file (struct file *file){
  int fd = thread_current()->fd++;
  int **fd_table = thread_current()->fd_table;

  ASSERT (fd_table != NULL);

  // Create fd entry with the given file
  fd_table[fd] = file;

  return fd;
}

struct file *process_get_file (int fd){
  struct thread *t = thread_current();
  
  ASSERT (t != NULL);

  if(t->fd < fd)
    return NULL;

  // Get file pointer with the given fd
  return t->fd_table[fd];
}

void process_close_file (int fd){
  struct thread *t = thread_current();

  ASSERT (t != NULL);

  // close file with fd and initialize corresponding fd table
  if(t->fd >= fd){
		lock_acquire(&file_lock);
    file_close(t->fd_table[fd]);
		lock_release(&file_lock);
    t->fd_table[fd] = NULL;
  }
}

// SOS Project 3

// Memory Mapped Files
mapid_t Mmap(int fd, void *addr){
  struct thread *t = thread_current();
  struct file *file;
  struct file *new_file;
  mapid_t mapid;
  off_t read_bytes;
  struct sPage_table_entry *s_pte;
  uint8_t *upage;
  int i = 0;
  struct mmap_file *mm_file;

  ASSERT (t != NULL);

  file = process_get_file(fd);         // Get File from File Descriptor
	if(file == NULL)
		return -1;
  
  // synchronization for file system 
  lock_acquire(&file_lock);        
  read_bytes = file_length(file);     // Set read bytes to file size
  lock_release(&file_lock);

	if(read_bytes == 0 || (uintptr_t)addr % PGSIZE != 0 || (uintptr_t)addr == 0 || fd == 0 || fd == 1)
		return -1;	
	
  lock_acquire(&file_lock);        
  new_file = file_reopen(file);           // Reopen new independent file from file descriptor
	lock_release(&file_lock);

  mm_file = (struct mmap_file *)malloc(sizeof(struct mmap_file));     // Allocate page for mmap file
  if(mm_file == NULL){
  	lock_acquire(&file_lock);        
  	file_close(new_file);				          // Reopen new independent file from file descriptor
		lock_release(&file_lock);
    return -1;
	}

  mapid = allocate_mapid();           // Get mapid
  if(mapid == NULL){
  	lock_acquire(&file_lock);        
  	file_close(new_file);				          // Reopen new independent file from file descriptor
		lock_release(&file_lock);
		free(mm_file);
    return -1;
	}

  mm_file->mapid = mapid;       
  mm_file->file = new_file;
	list_init(&mm_file->s_pte_list);

  list_push_back(&t->mmap_table, &mm_file->elem);                     // Insert mmap file to mmap_table of the current thread

  upage = addr;
  while(read_bytes > 0){                  // Get enough sPage table entry to cover the read bytes of the file and store into the mmap table
    // Make and allocate sPage table entry for mmap file
    s_pte = (struct sPage_table_entry *)malloc(sizeof(struct sPage_table_entry));     
    if(s_pte == NULL || find_s_pte(upage)){
			deallocate_mmap_file(mm_file);
			if(s_pte != NULL)
				free(s_pte);
      return -1;
		}
    
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    s_pte->type = TYPE_FILE;
    s_pte->location = LOC_FILE;     // Current location is just in Virtual Space
    s_pte->page_number = PG_NUM(upage);
    s_pte->writable = true;
    s_pte->file = new_file;
    s_pte->fte = NULL;
    s_pte->offset = i * PGSIZE;
    s_pte->read_bytes = page_read_bytes;
    s_pte->zero_bytes = page_zero_bytes;

    hash_insert(&t->sPage_table, &s_pte->elem);
    list_push_back(&mm_file->s_pte_list, &s_pte->mmap_table_elem);

    /* Advance. */
    read_bytes -= page_read_bytes;
    upage += PGSIZE;
    i++;                 
  }
  
  return mapid;
}

// Memory Unmapped Files
void Munmap(mapid_t mapid){
  struct mmap_file *mm_file;
  struct sPage_table_entry *s_pte;
  struct thread *t = thread_current();
  struct list_elem *e;

  ASSERT (t != NULL);

	//printf("start Munmap()\n");
	if(list_empty(&t->mmap_table))
		return;

  // find correponding mmap instance in mmap table 
  for(e = list_begin(&t->mmap_table); e != list_end(&t->mmap_table); list_next(e)){
    mm_file = list_entry(e, struct mmap_file, elem);
    if(mm_file->mapid == mapid)
      break;
  }

  // if no corresponding mapid, return
  if(e == list_end(&t->mmap_table))
    return;
  
  deallocate_mmap_file(mm_file);
}

static mapid_t allocate_mapid (void){
  static mapid_t next_mapid = 1;
  mapid_t mapid;

  // get new mapid
  lock_acquire (&mapid_lock);
  mapid = next_mapid++;
  lock_release (&mapid_lock);

  return mapid;
}

// When memory mapped files are unmapped and the dirty bit is true, write back into File System
void mmap_write_back (struct sPage_table_entry *s_pte){
  ASSERT(s_pte != NULL);
  
  // Check dirty bit is true or not
  bool dirty;                              
  dirty = pagedir_is_dirty(s_pte->fte->thread->pagedir, (uintptr_t)s_pte->page_number << 12);

  // If dirty bit is true, write back into File System
  if(dirty){           
    if(!lock_held_by_current_thread(&file_lock)){                    
      file_write_at(s_pte->file, (uintptr_t)s_pte->fte->frame_number << 12, s_pte->read_bytes, s_pte->offset);
		}
    else{
      lock_acquire(&file_lock);
      file_write_at(s_pte->file, (uintptr_t)s_pte->fte->frame_number << 12, s_pte->read_bytes, s_pte->offset);
      lock_release(&file_lock);
    }
  }

  s_pte->location = LOC_FILE;             // Current sPage table entry is located in File System
}

/* End SOS Implementation */
