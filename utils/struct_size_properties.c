#include <stdio.h>
#include <stddef.h>

typedef char gchar;
typedef short gshort;
typedef long glong;
typedef int gint;
typedef gint gboolean;

typedef unsigned char guchar;
typedef unsigned short gushort;
typedef unsigned long gulong;
typedef unsigned int guint;

typedef float gfloat;
typedef double gdouble;

typedef void *gpointer;
typedef const void *gconstpointer;

typedef guint GumEventType;

// Reordering fields would reduce size by 8
struct _GumCallEvent
{
  GumEventType type;

  gpointer location;
  gpointer target;
  gint depth;
};

// Size: 32; align: 8
// type: 0 (4)
// location: 8 (8)
// target: 16 (8)
// depth: 24 (4)
void main()
{
  printf("Size: %d; align: %d\n", sizeof(struct _GumCallEvent), alignof(struct _GumCallEvent));
  printf("type: %d (%d)\n", offsetof(struct _GumCallEvent, type), sizeof(GumEventType));
  printf("location: %d (%d)\n", offsetof(struct _GumCallEvent, location), sizeof(gpointer));
  printf("target: %d (%d)\n", offsetof(struct _GumCallEvent, target), sizeof(gpointer));
  printf("depth: %d (%d)\n", offsetof(struct _GumCallEvent, depth), sizeof(gint));
}