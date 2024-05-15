#include "userprog/syscall.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
// #include "threads/thread.c"
#include "userprog/process.h"
// #include "userprog/process.c"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include <string.h>
#include <stdlib.h>
#include "syscall.h"
#include "threads/synch.h"



struct open_file *get_file(int fd);
static void syscall_handler(struct intr_frame *);
struct lock fileSys_lock;

// checking validation of virtual memory
bool valid_user_space_adrress(void *val) {
  return val != NULL && is_user_vaddr(val) && pagedir_get_page(thread_current()->pagedir, val) != NULL;
}

void syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fileSys_lock);
}

void sys_exit(int status)
{
  char* name = thread_current()->name;
  char* save_ptr;
  char* executable = strtok_r (name, " ", &save_ptr);
  thread_current()->exit_status = status;
  printf("%s: exit(%d)\n", executable, status);
  thread_exit();
}
int sys_create(const char *file, unsigned initial_size)
{
  int i = 0;
  lock_acquire(&fileSys_lock);
  i = filesys_create(file, initial_size);
  lock_release(&fileSys_lock);
  return i;
}

int sys_remove(const char *file)
{
  int i = -1;
  lock_acquire(&fileSys_lock);
  i = filesys_remove(file);
  lock_release(&fileSys_lock);
  return i;
}

int sys_open(const char *file)
{
  static unsigned long cur_fd = 2;
  lock_acquire(&fileSys_lock);
  struct file *o_file = filesys_open(file);
  lock_release(&fileSys_lock);

  if (o_file != NULL) { 
    struct open_file *user_file = (struct open_file *)malloc(sizeof(struct open_file));
    int file_fd = cur_fd;
    user_file->fd = cur_fd;
    user_file->file = o_file;
  
    lock_acquire(&fileSys_lock);
    cur_fd++;
    lock_release(&fileSys_lock);
    struct list_elem *elem = &user_file->elem;
    list_push_back(&thread_current()->files_list, elem);
    return file_fd;
  }
  else return -1;
}

/* searching the list of open files associated with the current thread to find an open_file 
structure that matches  the provided file descriptor. If a match is found, 
it returns the pointer to the structure; otherwise, it returns NULL */
struct open_file *sys_getFile(int fd)
{
  struct list *files = &(thread_current()->files_list);
  for (struct list_elem *cur = list_begin(files); cur != list_end(files); cur = list_next(cur))
  {
    struct open_file *cur_file = list_entry(cur, struct open_file, elem);
    if ((cur_file->fd) == fd) return cur_file;
  }
  return NULL;
}

int sys_read(int fd, void *buffer, unsigned size)
{
  int i = size;
  if (fd == 0)
  {
    while (size--)
    {
      lock_acquire(&fileSys_lock);
      char ch = input_getc();
      lock_release(&fileSys_lock);
      buffer += ch;
    }
    return i;
  }

  struct open_file *user_file = sys_getFile(fd);
  if (user_file == NULL)
    return -1;
  else
  {
    struct file *file = user_file -> file;
    lock_acquire(&fileSys_lock);
    size = file_read(file, buffer, size);
    lock_release(&fileSys_lock);
    return size;
  }
}

int sys_write(int fd, const void *buffer, unsigned size)
{
  if (fd == 1)
  { 
    lock_acquire(&fileSys_lock);
    putbuf(buffer, size);    // write data from buffer into console
    lock_release(&fileSys_lock);
    return size;
  }

// else: write to a file
  struct open_file *file = sys_getFile(fd);
  if (file == NULL) // fail
    return -1;  
  else
  {
    int i = 0;
    lock_acquire(&fileSys_lock);
    i = file_write(file->file, buffer, size);
    lock_release(&fileSys_lock);
    return i;
  }
}
/*set the position of the file read/write pointer to a specified location within an open file.*/
void sys_seek(struct intr_frame *f)
{
  /* read the arguments starting from the address in f->esp , 
  while a return value, if it exists, has to be written to f->eax */
  // extract file descriptor and position 
  int fd = (int)(*((int *)f->esp + 1));
  unsigned position = (unsigned)(*((int *)f->esp + 2));
  struct open_file *file = sys_getFile(fd);
  if (file == NULL) f->eax = -1;
  else {
    lock_acquire(&fileSys_lock);
    file_seek(file->file, position);
    f->eax = position;
    lock_release(&fileSys_lock);
  }
}

/*get the current position of the file read/write pointer within an open file.*/
void sys_tell(struct intr_frame *f)
{
  int fd = (int)(*((int *)f->esp + 1));
  struct open_file *file = sys_getFile(fd);
  if (file == NULL) f->eax = -1;
  else {
    lock_acquire(&fileSys_lock);
    f->eax = file_tell(file->file);
    lock_release(&fileSys_lock);
  }
}

int sys_close(int fd)
{
  struct open_file *file = sys_getFile(fd);
  if (file == NULL) return -1;
  lock_acquire(&fileSys_lock);
  file_close(file->file);
  lock_release(&fileSys_lock);
  list_remove(&file->elem);
  return 1;
}

// passing the status to exit
void wrapperExit(struct intr_frame *f)
{
  int status = *((int *)f->esp + 1);
  if (!is_user_vaddr(status))   // not user valid address
  {
    f->eax = -1;
    sys_exit(-1);
  }
  f->eax = status;
  sys_exit(status);
}

/* checking validation in virtual memory, if valid pass it to sys_create() */
void wrapperCreate(struct intr_frame *f)
{
  char *file = (char *)*((int *)f->esp + 1);
  if (!valid_user_space_adrress(file)) sys_exit(-1);
  unsigned initial_size = (unsigned)*((int *)f->esp + 2);
  f->eax = sys_create(file, initial_size);
}

/* checking validation in virtual memory, if valid pass it to sys_remove() */
void wrapperRemove(struct intr_frame *f)
{
  char *file = (char *)(*((int *)f->esp + 1));
  if (!valid_user_space_adrress(file)) sys_exit(-1);
  f->eax = sys_remove(file);
}

/* checking validation in virtual memory, if valid pass it to sys_open() */
void wrapperOpen(struct intr_frame *f)
{
  char *file = (char *)(*((int *)f->esp + 1));
  if (!valid_user_space_adrress(file))
    sys_exit(-1);
  f->eax = sys_open(file);
}

/* checking validation in virtual memory, if valid pass it to sys_getFile() */
void wrapperFilesize(struct intr_frame *f)
{
  int fd = (int)(*((int *)f->esp + 1));
  struct open_file *file = sys_getFile(fd);
  if (file == NULL)
    f->eax = -1;
  else
  {
    lock_acquire(&fileSys_lock);
    f->eax = file_length(file->file); // setting file size
    lock_release(&fileSys_lock);
  }
}

/* checking validation in virtual memory, if valid pass it to sys_read() */
void wrapperRead(struct intr_frame *f)
{
  int fd = (int)(*((int *)f->esp + 1));
  char *buffer = (char *)(*((int *)f->esp + 2));
  if (fd == 1 || !valid_user_space_adrress(buffer))
  { // fail if fd is 1 means (stdout) or in valid in virtual memory
    sys_exit(-1);
  }
  unsigned size = *((unsigned *)f->esp + 3);
  f->eax = sys_read(fd, buffer, size);
}

/* checking validation in virtual memory, if valid pass it to sys_write() */
void wrapperWrite(struct intr_frame *f)
{
  int fd = *((int *)f->esp + 1);
  char *buffer = (char *)(*((int *)f->esp + 2));
  if (fd == 0 || !valid_user_space_adrress(buffer)) { // fail, if fd is 0 (stdin), or its virtual memory
    sys_exit(-1);
  }
  unsigned size = (unsigned)(*((int *)f->esp + 3));
  f->eax = sys_write(fd, buffer, size);
}

/* checking validation in virtual memory, if valid pass it to sys_close() */
void wrapperClose(struct intr_frame *f)
{
  int fd = (int)(*((int *)f->esp + 1));
  if (fd < 2) // fail, the fd is stdin or stdout
    sys_exit(-1);
  f->eax = sys_close(fd);
}

static void syscall_handler(struct intr_frame *f UNUSED)
{
  msg("\nokok\n");
  // if (!valid_stack_ptr(f)) sys_exit(-1);
  switch (*(int *)f->esp) {
  case SYS_CREATE: wrapperCreate(f);  break;
  case SYS_REMOVE: wrapperRemove(f);  break;
  case SYS_OPEN: wrapperOpen(f);  break;  
  case SYS_FILESIZE: wrapperFilesize(f);  break;
  case SYS_READ: wrapperRead(f);  break;
  case SYS_WRITE: wrapperWrite(f);  break;
  case SYS_SEEK: sys_seek(f);   break;
  case SYS_TELL: sys_tell(f);   break;
  case SYS_CLOSE: wrapperClose(f);  break;
  case SYS_WAIT:     
  f->eax = process_wait(f);
    break;
  default: sys_exit(-1);  break;
  }
  thread_exit();
}