/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <stdio.h>
#include <string.h>

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */

bool comparator(const struct list_elem *list_elem_1,
                const struct list_elem *list_elem_2, void *aux UNUSED);
bool compare_sema(const struct list_elem *list_elem_1,
                const struct list_elem *list_elem_2, void *aux UNUSED);

void remove_from_donations(struct thread *t, void *aux UNUSED);

void sema_init(struct semaphore *sema, unsigned value) {
  ASSERT(sema != NULL);
void remove_from_donations(struct thread *t, void *aux UNUSED);

void
sema_init (struct semaphore *sema, unsigned value) 
{
  ASSERT (sema != NULL);

  sema->value = value;
  list_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void sema_down(struct semaphore *sema) {
  enum intr_level old_level;

  ASSERT(sema != NULL);
  ASSERT(!intr_context());

  old_level = intr_disable();
  // while (sema->value == 0)
  while (sema->value <= 0) {
    list_insert_ordered(&sema->waiters, &thread_current()->elem, comparator,
                        NULL);
    thread_block();
  }

  sema->value--;
  intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore *sema) {
  enum intr_level old_level;
  bool success;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  if (sema->value > 0) {
    sema->value--;
    success = true;
  } else
    success = false;
  intr_set_level(old_level);

  return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void sema_up(struct semaphore *sema) {
  enum intr_level old_level;

  ASSERT(sema != NULL);

  old_level = intr_disable();

  struct thread *next = NULL;

  if (!list_empty(&sema->waiters)) {
    next = list_entry(list_pop_front(&sema->waiters), struct thread, elem);
    list_remove (&next->elem);
    thread_unblock(next);
  }

  sema->value++;
  intr_set_level(old_level);

  after_thread_unblock();
}

static void sema_test_helper(void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void) {
  struct semaphore sema[2];
  int i;

  printf("Testing semaphores...");
  sema_init(&sema[0], 0);
  sema_init(&sema[1], 0);
  thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) {
    sema_up(&sema[0]);
    sema_down(&sema[1]);
  }
  printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void sema_test_helper(void *sema_) {
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++) {
    sema_down(&sema[0]);
    sema_up(&sema[1]);
  }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init(struct lock *lock) {
  ASSERT(lock != NULL);

  lock->holder = NULL;
  lock->max_thread_priority = -1;
  sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */



void
lock_acquire (struct lock *lock)
{
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (!lock_held_by_current_thread (lock));
  enum intr_level old_level = intr_disable ();


  struct thread *current_thread = thread_current();

  struct lock *temp = lock;

  // Lock is free -> acquire it
  if( lock->holder != NULL) {

    current_thread->wait_on_lock = lock;

    // lock->max_thread_priority = current_thread->effective_priority > lock->max_thread_priority ? current_thread->effective_priority : lock->max_thread_priority;
    // printf("Max Priority of Lock: %d\n", lock->max_thread_priority);

    // Donate Priority to all holders -> nested 
        // printf("\n______________priority: %d, efficitive %d, tid: %d\n", thread_current()->priority, thread_current()->effective_priority, thread_current()->tid);

    // Add the thread to the donations_list of all parents
    while( temp != NULL && temp->max_thread_priority < current_thread->effective_priority  ) {
      // printf("Donating priority to %d from %d\n", temp->holder->effective_priority, current_thread->effective_priority);
      if( temp->holder != NULL && temp->max_thread_priority < current_thread->effective_priority ) {
        temp->max_thread_priority = current_thread->effective_priority;
        temp->holder->effective_priority = current_thread->effective_priority;
        update_priority(temp->holder);
        // after_thread_unblock();
      } else if(temp->holder == NULL && temp->max_thread_priority < current_thread->effective_priority) {
temp->max_thread_priority = current_thread->effective_priority;
      }
      temp = temp->holder->wait_on_lock;

    }

  }

  intr_set_level (old_level);

  sema_down (&lock->semaphore);
  old_level = intr_disable ();
  lock->holder = thread_current ();
    // printf("\npriority: %d, efficitive %d, tid: %d\n", thread_current()->priority, thread_current()->effective_priority, thread_current()->tid);

  list_insert_ordered (&thread_current ()->locks_list, &lock->elem, compare_locks, NULL);
  // thread_current()->wait_on_lock = NULL;


  if( lock->max_thread_priority > current_thread->effective_priority ) {
    current_thread->effective_priority = lock->max_thread_priority;
  }

  // update_priority(lock->holder);
  // after_thread_unblock();
    // printf("\npriority: %d, efficitive %d\n", thread_current()->priority, thread_current()->effective_priority);
intr_set_level (old_level);
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock *lock) {
  bool success;

  ASSERT(lock != NULL);
  ASSERT(!lock_held_by_current_thread(lock));

  success = sema_try_down(&lock->semaphore);
  if (success)
    lock->holder = thread_current();
  return success;
}

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void lock_release(struct lock *lock) {

  ASSERT(lock != NULL);
  ASSERT(lock_held_by_current_thread(lock));

  enum intr_level old_level = intr_disable ();

  if( !list_empty(&thread_current()->locks_list) ) {
  // printf("\n%d\n", thread_current()->effective_priority);
      list_remove (&lock->elem);
      update_priority(lock->holder);  
  }

  intr_set_level (old_level);

  lock->holder = NULL;
  sema_up(&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock *lock) {
  ASSERT(lock != NULL);

  return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem {
  struct list_elem elem;      /* List element. */
  struct semaphore semaphore; /* This semaphore. */

  int sema_priority;
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition *cond) {
  ASSERT(cond != NULL);

  list_init(&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait(struct condition *cond, struct lock *lock) {
  struct semaphore_elem waiter;

  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));


  waiter.sema_priority=thread_current()->effective_priority;

  sema_init(&waiter.semaphore, 0);
  // list_push_back (&cond->waiters, &waiter.elem);
  list_insert_ordered(&cond->waiters, &waiter.elem, compare_sema, NULL);


  lock_release(lock);
  sema_down(&waiter.semaphore);
  lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal(struct condition *cond, struct lock *lock UNUSED) {
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  if (!list_empty(&cond->waiters))
    sema_up(
        &list_entry(list_pop_front(&cond->waiters), struct semaphore_elem, elem)
             ->semaphore);
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition *cond, struct lock *lock) {
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);

  while (!list_empty(&cond->waiters))
    cond_signal(cond, lock);
}

bool comparator (const struct list_elem *list_elem_1, const struct list_elem *list_elem_2, void *aux UNUSED)
{
  return list_entry (list_elem_1, struct thread, elem)->effective_priority >= list_entry (list_elem_2, struct thread, elem)->effective_priority;
}

bool compare_locks (const struct list_elem *lock1, const struct list_elem *lock2, void * aux  UNUSED)
{
  return list_entry (lock1, struct lock, elem)->max_thread_priority >= list_entry (lock2, struct lock, elem)->max_thread_priority;
}