/*
 * debug.cpp
 *
 *  Created on: 24 nov. 2014
 *      Author: oc
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "debug.h"
#include <cstdio>
#include <ctime>
#include <cerrno>
#include <cstring>
#include <pthread.h>
#include <sys/syscall.h>
#include <cstdlib>
#include <sys/types.h>
#include <unistd.h>
#include <cstdarg>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstddef>
#include <linux/limits.h>

#ifndef _CONSOLE_
static pthread_once_t syslog_is_initialized = PTHREAD_ONCE_INIT;
#endif /* _CONSOLE_ */

static __inline pid_t __gettid()
{
  const pid_t tid = (pid_t) syscall (SYS_gettid);
  return tid;
}
#define gettid __gettid

typedef struct allocated_ressources_
{
  FILE *memstream;
  char *buffer;
} allocated_ressources;

static void on_cancel(void *param)
{
  if (param)
    {
      allocated_ressources *rsc = (allocated_ressources *)param;
      if (rsc->memstream)
        {
          fclose(rsc->memstream);
          rsc->memstream = NULL;
        }
      if (rsc->buffer)
        {
          free(rsc->buffer);
          rsc->buffer = NULL;
        }
    }
}

void init_syslog()
{
	openlog(NULL,LOG_PID,LOG_LOCAL0);
}

void DebugPrint(int level,const char *format, ...)
{
  //int n = 0;
  va_list parameters;
  const int saved_errno = errno;
  va_start(parameters,format);

  struct timespec current_time_spec;
  struct tm current_time;
  if (clock_gettime(CLOCK_REALTIME,&current_time_spec) == 0)
    {
      if (gmtime_r(&current_time_spec.tv_sec,&current_time) == NULL)
        {
          memset(&current_time,0,sizeof(current_time));
        }
    }
  else
    {
      const int error = errno;
      current_time_spec.tv_nsec = 0;
      current_time_spec.tv_sec = 0;
      fprintf(stderr,"clock_gettime CLOCK_REALTIME error %d (%m)",error);
      time_t current;
      if (time(&current) != -1)
      {
		if (gmtime_r(&current,&current_time) == NULL)
		{
		  memset(&current_time,0,sizeof(current_time));
		  fprintf(stderr,"gmtime_r error");
		}
      }
      else
      {
    	  memset(&current_time,0,sizeof(current_time));
    	  fprintf(stderr,"time error");
      }
    }
  allocated_ressources ressources = {NULL,NULL};
  size_t size = 0;
  pthread_cleanup_push(on_cancel,&ressources);
  ressources.memstream = open_memstream(&ressources.buffer,&size);
  if (ressources.memstream)
    {
      /*struct tm now_tm;
      time_t now;
      (void) time(&now);
      ressources.memstream->_IO_write_ptr += strftime(ressources.memstream->_IO_write_ptr,ressources.memstream->_IO_write_end - ressources.memstream->_IO_write_ptr,"%h %e %T ",localtime_r(&now, &now_tm));*/

      const pid_t tid = gettid();

      fprintf(ressources.memstream,"{%.2u:%.2u:%.2u.%lu} [%d:%d] %s"
              ,current_time.tm_hour,current_time.tm_min,current_time.tm_sec,current_time_spec.tv_nsec
              ,(int) getpid (),(int) tid,format);
      fclose(ressources.memstream);
      ressources.memstream = NULL;
      errno = saved_errno; /* restore errno for %m format */
#ifdef _CONSOLE_
      vprintf(ressources.buffer,parameters);
#else
      pthread_once(&syslog_is_initialized,init_syslog);
      vsyslog(level,ressources.buffer,parameters);
#endif
      free(ressources.buffer);
      ressources.buffer = NULL;
    }
  else
    {
      const int error = errno;
      fprintf(stderr,"open_memstream error %d (%m)",error);
    }
  pthread_cleanup_pop(0);

  va_end(parameters);
}

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

void dumpMemory(const char *memoryName,const void *address, unsigned int size)
{
	const unsigned int nbBytesPerLines = 16;
	char hexa[(nbBytesPerLines+1) * 3];
	char ascii[(nbBytesPerLines+1)];
	register const unsigned char *cursor = (const unsigned char *)address;
	const unsigned char* const limit = cursor + size;

	DebugPrint(LOG_DEBUG," *** begin of memory dump of %s (size = %d bytes) ***" DEBUG_EOL,memoryName,size);
	while(cursor < limit) {
		register unsigned int i;
		register char *hexaCursor = hexa;
		register char *asciiCursor = ascii;
		const std::ptrdiff_t remaining = limit-cursor;
		const unsigned int lineSize = MIN(nbBytesPerLines,(unsigned int)remaining);

		for(i=0;i<lineSize;i++) {
			register const unsigned char value = *cursor;
			hexaCursor += sprintf(hexaCursor,"%.2X ",value);
			if ((value >= 0x20) && (value<= 0x7A)) {
				asciiCursor += sprintf(asciiCursor,"%c",value);
			} else {
				asciiCursor += sprintf(asciiCursor,".");
			}
			cursor++;
		}
		DebugPrint(LOG_DEBUG," %s\t%s",hexa,ascii);
	}
	DebugPrint(LOG_DEBUG," *** end of memory dump of %s (size = %d bytes) ***" DEBUG_EOL,memoryName,size);
}

static void on_cancel_during_write(void *param)
{
	if (param)
	{
		int fd = *(static_cast<int*>(param));
		close(fd);
	}
}

void dumpMemoryInFile(const char *memoryName,const void *address, unsigned int size)
{
	char filename[PATH_MAX];
	int fd = -1;
	sprintf(filename,"/tmp/%s",memoryName);
	fd = open(filename,O_WRONLY|O_TRUNC|O_CREAT,S_IRUSR|S_IWUSR);
	if (fd != -1)
	{
		pthread_cleanup_push(on_cancel_during_write,&fd);
		const ssize_t written = write(fd,address,(size_t)size);
		if (-1 == written)
		{
			const int error = errno;
			ERROR_MSG("write %s error %d (%m)",filename,error);
		}
		close(fd);
		pthread_cleanup_pop(0);
	}
	else
	{
		const int error = errno;
		ERROR_MSG("open %s error %d (%m)",filename,error);
	}
}


