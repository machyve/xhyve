#include <sys/cdefs.h>

#include <sys/types.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <xhyve/bhyvegc.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

struct bhyvegc {
	struct bhyvegc_image	*gc_image;
	int raw;
};

#pragma clang diagnostic pop

struct bhyvegc *
bhyvegc_init(uint16_t width, uint16_t height, void *fbaddr)
{
	struct bhyvegc *gc;
	struct bhyvegc_image *gc_image;

	gc = calloc(1, sizeof (struct bhyvegc));

	gc_image = calloc(1, sizeof(struct bhyvegc_image));
	gc_image->width = width;
	gc_image->height = height;
	if (fbaddr) {
		gc_image->data = fbaddr;
		gc->raw = 1;
	} else {
		gc_image->data = calloc(width * height, sizeof (uint32_t));
		gc->raw = 0;
	}

	gc->gc_image = gc_image;

	return (gc);
}

void
bhyvegc_set_fbaddr(struct bhyvegc *gc, void *fbaddr)
{
	gc->raw = 1;
	if (gc->gc_image->data && gc->gc_image->data != fbaddr)
		free(gc->gc_image->data);
	gc->gc_image->data = fbaddr;
}

void
bhyvegc_resize(struct bhyvegc *gc, uint16_t width, uint16_t height)
{
	struct bhyvegc_image *gc_image;

	gc_image = gc->gc_image;

	gc_image->width = width;
	gc_image->height = height;
	if (!gc->raw) {
		gc_image->data = realloc(gc_image->data, width * height * sizeof (uint32_t));
		if (gc_image->data != NULL)
			memset(gc_image->data, 0, width * height *
			    sizeof (uint32_t));
	}
}

struct bhyvegc_image *
bhyvegc_get_image(struct bhyvegc *gc)
{
	if (gc == NULL)
		return (NULL);

	return (gc->gc_image);
}
