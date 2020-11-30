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
// End SOS Implementation

#define STDIN_FILENO 0
#define STDOUT_FILENO 1

static void syscall_handler (struct intr_frame *);

struct lock file_lock;      // SOS Implementation - lock for mut ex of read and write sys calls

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);    // SOS Implementation project2
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
            break;
    default:
            f->eax = result;
  }
}

bool isValid_Vaddr (void *addr){
  struct thread *t = thread_current ();
  uint32_t * ptr;
	int i;

	//printf("isValid_Vaddr after is user vaddr\n");
  // validness check for addr~addr+3
	for(i = 0; i < 4; i++){
  	// check whether addr is included in user memory

		//printf("isValid_Vaddr before is user vaddr\n");
  	if(!is_user_vaddr((uintptr_t)addr + i))
    	return false;


  	// find the address of page table entry and check whether it is not NULL 
  	if(!find_s_pte((uintptr_t)addr + i)){        // SOS Implementation project 3
			//printf("find_s_pte false\n");
    	return false;
		}

	}

	//printf("find_s_pte true\n");

	return true;
}

void pop_arg_from_stack (void *esp, int *arg, int n){
  int i;

	esp = (uintptr_t)esp + (uintptr_t)4;        // pass syscall number in user stack

  for(i = 0; i < n; i++){
		if(!isValid_Vaddr(esp)){				// Check the validness of esp access
			free(arg);
			Exit(-1);
		}
    arg[i] = *(int *)esp;                         // get argument
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

  // Create file with the given name file
  return filesys_create(file, initial_size);
}

bool Remove (const char *file){
  ASSERT (isValid_Vaddr(file));

  // Remove file with the given name file
  return filesys_remove(file);
}

int Open (const char *file_){

  ASSERT (isValid_Vaddr(file_));

  struct file *file = filesys_open(file_);

	if(file)
		return process_create_file(file);   // get new fd with the given name file
	else
		return -1;
}

int Filesize (int fd){
  struct file *file = process_get_file (fd);

  if(file == NULL)
		return 0;

  // Get file size with the given fd
  return file_length(file);
}

int Read (int fd, void *buffer, unsigned size){
  struct file *file = process_get_file (fd);
  int result;

  ASSERT (isValid_Vaddr(buffer));

  // acquire lock to guarantee mutual exclusion to the file access
  lock_acquire(&file_lock);

  if(fd == STDIN_FILENO){           // Reading on Standard Input case
    for(result = 0; result < size; result++)
      ((uint8_t *)buffer)[result] = input_getc();
  }
  else if(file != NULL && fd > 1 && fd < thread_current()->fd){            // Reading on other input case
    result = file_read(file, buffer, size);
  }
  else{                             // Exception case
    result = -1;
  }

  lock_release(&file_lock);

  return result;
}

int Write (int fd, const void * buffer, unsigned size){
  struct file *file = process_get_file (fd);
  int result;

  ASSERT (buffer != NULL);

  // acquire lock to guarantee mutual exclusion to the file access
  lock_acquire(&file_lock);
 
  if(fd == STDOUT_FILENO){            // Writing on Standard Output case
		//printf("stdout write!\n");
    putbuf(buffer, size);
    result = size;
  }
  else if(file != NULL && fd > 1 && fd < thread_current()->fd){              // Writing on other output case
    result = file_write(file, buffer, size);
  }
  else{                               // Exception case
    result = -1;
  }

  lock_release(&file_lock);

  return result;
}

void Seek (int fd, unsigned position){
  struct file *file = process_get_file (fd);

  if(file == NULL)
		return 0;

  // Change the position of the file with the given fd about position size
  file_seek(file, position);
}

unsigned Tell (int fd){
 struct file *file = process_get_file (fd);

  if(file == NULL)
		return 0;

  // Get file psotion with the given fd 
  return file_tell(file);
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
    file_close(t->fd_table[fd]);
    t->fd_table[fd] = NULL;
  }
}

/* End SOS Implementation */
