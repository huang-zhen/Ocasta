#ifndef __HMAP_H
#define __HMAP_H

#include <sys/queue.h>

#define LIST_ITERATOR(type) struct type *

#define LIST_ITERATOR_INIT(head, itr) do { (itr) = (head)->lh_first; } while (0)

#define LIST_ITERATOR_NEXT(itr, field) ((itr) = ((itr)->field).le_next)

#define HMAP_HEAD(name, lname, type)                                   \
struct name {                                                          \
  LIST_HEAD(lname, type) *mh_map;                                      \
  int mh_size;                                                         \
}

#define HMAP_ENTRY(type)                                               \
struct {                                                               \
  void *key;              /* key */                                    \
  struct type *le_next;   /* next element */                           \
  struct type **le_prev;  /* address of previous next element */       \
}

#define HMAP_INIT(head, lname, array, size)                            \
do {                                                                   \
  unsigned int me_i;                                                   \
  (head)->mh_map = (struct lname *)array;                              \
  if ((head)->mh_map) {                                                \
    (head)->mh_size = size;                                            \
    for (me_i = 0; me_i < (head)->mh_size; me_i++) {                   \
      LIST_INIT(&((head)->mh_map)[me_i]);                              \
    }                                                                  \
  }                                                                    \
} while (0)

#define HMAP_HASH(elm, field, ksize, hc)                               \
do {                                                                   \
  unsigned int me_i;                                                   \
  hc = 7;                                                              \
  for (me_i = 0; me_i < ksize; me_i++) {                               \
    hc = hc * 31 + ((char *)(elm)->field.key)[me_i];                   \
  }                                                                    \
} while (0)

#define HMAP_PUT(head, type, elm, pelm, field, ksize)                  \
do {                                                                   \
  unsigned int me_hc;                                                  \
  LIST_ITERATOR(type) me_itr;                                          \
  HMAP_HASH(elm, field, ksize, me_hc);                                 \
  me_hc %= (head)->mh_size;                                            \
  LIST_ITERATOR_INIT(&(head)->mh_map[me_hc], me_itr);                  \
  pelm = NULL;                                                         \
  while (me_itr) {                                                     \
    if (!memcmp(me_itr->field.key, (elm)->field.key, ksize)) {         \
      pelm = me_itr;                                                   \
      LIST_INSERT_AFTER(me_itr, elm, field);                           \
      LIST_REMOVE(me_itr, field);                                      \
      break;                                                           \
    }                                                                  \
    LIST_ITERATOR_NEXT(me_itr, field);                                 \
  }                                                                    \
  if (!pelm) {                                                         \
    LIST_INSERT_HEAD(&(head)->mh_map[me_hc], elm, field);              \
  }                                                                    \
} while (0)

#define HMAP_GET(head, type, elm, pelm, field, ksize)                  \
do {                                                                   \
  unsigned int me_hc;                                                  \
  LIST_ITERATOR(type) me_itr;                                          \
  HMAP_HASH(elm, field, ksize, me_hc);                                 \
  me_hc %= (head)->mh_size;                                            \
  LIST_ITERATOR_INIT(&(head)->mh_map[me_hc], me_itr);                  \
  pelm = NULL;                                                         \
  while (me_itr) {                                                     \
    if (!memcmp(me_itr->field.key, (elm)->field.key, ksize)) {         \
      pelm = me_itr;                                                   \
      LIST_REMOVE(me_itr, field);                                      \
      break;                                                           \
    }                                                                  \
    LIST_ITERATOR_NEXT(me_itr, field);                                 \
  }                                                                    \
} while (0)

#endif /* __HMAP_H */
