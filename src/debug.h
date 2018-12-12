/*
 * debug.h
 *
 *  Created on: 24 nov. 2014
 *      Author: oc
 */

#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

#if (GCC_VERSION > 40000) /* GCC 4.0.0 */
#pragma once
#endif /* GCC 4.0.0 */

#ifndef _DEBUG_H_
#define _DEBUG_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#define ARRAY_SIZE(x)   (sizeof(x)/sizeof(x[0]))

#ifndef TO_STRING
#define STRING(x) #x
#define TO_STRING(x) STRING(x)
#endif /* STRING */

#define _T(x) x

#ifndef DEBUG_EOL
#define DEBUG_EOL _T("\r\n")
#endif //DEBUG_EOL

#ifndef DEBUG_LOG_HEADER
/*#define DEBUG_LOG_HEADER "####: "*/
#define DEBUG_LOG_HEADER ""
#endif /* DEBUG_LOG_HEADER */

#define CHECK_PARAMS(f,p)               __attribute__ ((format (printf, f, p)))

#if (GCC_VERSION > 40000) /* GCC 4.0.0 */
#define CHECK_PARAMS(f,p)	__attribute__ ((format (printf, f, p)))
#define CHECK_NON_NULL_PTR(n)	__attribute__ ((nonnull(n)))
/* define Branch prediction hints macros for GCC 4.0.0 and upper */
#ifndef likely
#define likely(x)   __builtin_expect(!!(x),1)
#endif /* likely */
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x),0)
#endif /* unlikely */
#else
#define CHECK_PARAMS(f,p)
#define CHECK_NON_NULL_PTR(n)
#define likely(x)   (x)
#define unlikely(x) (x)
#endif /* GCC 4.0.0 */

#if (GCC_VERSION >= 60300)
/* NOTHING YET ! */
#elif (GCC_VERSION > 42100) /* GCC 4.2.1 */
#pragma GCC diagnotic push
#pragma GCC diagnostic ignored "-Wno-variadic-macros" 
#else
#pragma GCC system_header /* oops ! just to disable the nasty warning "warning: anonymous variadic macros were introduced in C99" */
#endif /* 4.2.1 */

#if (GCC_VERSION > 40000) /* GCC 4.0.0 */
#define CHECK_NON_NULL_PTR(n)   __attribute__ ((nonnull(n)))
#else
#define CHECK_NON_NULL_PTR(n)
#endif /* (GCC_VERSION > 40000) */

#define TO_DO_PRAGMA(x)	_Pragma (#x)
#define TODO(x)	TO_DO_PRAGMA(message ("TODO: " #x))

#define SIMPLE_DEBUG_LOG_HEADER DEBUG_LOG_HEADER ":"
#define DEBUG_LOG_HEADER_POS    " [ %s ("  __FILE__ ":%d)]:"
#define CPP_SIMPLE_DEBUG_LOG_HEADER     DEBUG_LOG_HEADER ":"
#define CPP_DEBUG_LOG_HEADER_POS        " [ " << __FUNCTION__ << " (" << __FILE__ << ":" << __LINE__ << ")]:"


void DebugPrint(int level,const char *format, ...) CHECK_PARAMS(2,3) CHECK_NON_NULL_PTR(2);
void dumpMemory(const char *memoryName,const void *address, unsigned int size);
void dumpMemoryInFile(const char *memoryName,const void *address, unsigned int size);

#define EMERG_MSG(fmt,...)   DebugPrint(LOG_EMERG,"[Emergency]" DEBUG_LOG_HEADER_POS fmt DEBUG_EOL,__FUNCTION__,__LINE__, ##__VA_ARGS__)
#define ALERT_MSG(fmt,...)   DebugPrint(LOG_ALERT,"[Alert]" DEBUG_LOG_HEADER_POS fmt DEBUG_EOL,__FUNCTION__,__LINE__, ##__VA_ARGS__)
#define CRIT_MSG(fmt,...)    DebugPrint(LOG_CRIT,"[Critical]" DEBUG_LOG_HEADER_POS fmt DEBUG_EOL,__FUNCTION__,__LINE__, ##__VA_ARGS__)

#ifndef _RETAIL_

#define ERROR_MSG(fmt,...)   DebugPrint(LOG_ERR,"[Error]" DEBUG_LOG_HEADER_POS fmt DEBUG_EOL,__FUNCTION__,__LINE__, ##__VA_ARGS__)
#define WARNING_MSG(fmt,...) DebugPrint(LOG_WARNING,"[Warning]" DEBUG_LOG_HEADER_POS fmt DEBUG_EOL,__FUNCTION__,__LINE__, ##__VA_ARGS__)
#define NOTICE_MSG(fmt,...)  DebugPrint(LOG_NOTICE,"[Notice]" DEBUG_LOG_HEADER_POS fmt DEBUG_EOL,__FUNCTION__,__LINE__, ##__VA_ARGS__)

#if (defined(_DEBUG_) || defined(_DEBUG))

#define INFO_MSG(fmt,...)    DebugPrint(LOG_INFO,"[Info]" DEBUG_LOG_HEADER_POS fmt DEBUG_EOL,__FUNCTION__,__LINE__, ##__VA_ARGS__)
#define DEBUG_MSG(fmt,...)   DebugPrint(LOG_DEBUG,"[Debug]" DEBUG_LOG_HEADER_POS fmt DEBUG_EOL,__FUNCTION__,__LINE__, ##__VA_ARGS__)
#define TRACE_MSG(fmt,...)   DebugPrint(LOG_DEBUG,"[Trace]" DEBUG_LOG_HEADER_POS fmt DEBUG_EOL,__FUNCTION__,__LINE__, ##__VA_ARGS__)

#define DEBUG_MARK            DEBUG_MSG("(%d) in %s" DEBUG_EOL,__LINE__,__PRETTY_FUNCTION__)
#define DEBUG_VAR(x,f)        DEBUG_MSG("(%d) %s: " #x " = " f DEBUG_EOL,__LINE__,__PRETTY_FUNCTION__,x)
#define DEBUG_VAR_BOOL(Var)   DEBUG_MSG("(%d) %s: " #Var " = %s" DEBUG_EOL,__LINE__,__PRETTY_FUNCTION__,(Var?"True":"False"))
#define DEBUG_DUMP_MEMORY(Var,Size) dumpMemory(#Var,Var,Size)
#define DEBUG_DUMP_IN_FILE(Var,Size) dumpMemoryInFile(#Var,Var,Size)

#else //(defined(_DEBUG_) || defined(_DEBUG))

#define INFO_MSG(fmt,...)
#define DEBUG_MSG(fmt,...)
#define TRACE_MSG(fmt,...)
#define DEBUG_MARK
#define DEBUG_VAR(x,f)
#define DEBUG_VAR_BOOL(Var)
#define DEBUG_DUMP_MEMORY(Var,Size)
#define DEBUG_DUMP_IN_FILE(Var,Size)

#endif //(defined(_DEBUG_) || defined(_DEBUG))

#else //_RETAIL_

#define ERROR_MSG(fmt,...)
#define WARNING_MSG(fmt,...)
#define NOTICE_MSG(fmt,...)

#endif //_RETAIL_

#ifdef __cplusplus
}

#if (defined(_DEBUG_) || defined(_DEBUG))
#include <string>
class FunctionCallTrace
{
	std::string Name;
	std::string Filename;
	unsigned int LineNumber;
public:
	FunctionCallTrace(const char *name,const char *filename,const unsigned int line)
	:Name(name),Filename(filename),LineNumber(line)
	{
		DEBUG_MSG("+%s (%s:%u)",Name.c_str(),Filename.c_str(),LineNumber);
	}

	~FunctionCallTrace()
	{
		DEBUG_MSG("-%s (%s:%u)",Name.c_str(),Filename.c_str(),LineNumber);
	}
};

#define TRACE_CALL FunctionCallTrace functionCallTrace(__PRETTY_FUNCTION__,__FILE__,__LINE__)

#else /* (defined(_DEBUG_) || defined(_DEBUG)) */
#define TRACE_CALL
#endif /* (defined(_DEBUG_) || defined(_DEBUG)) */

#endif /* __cplusplus */

#endif /* _DEBUG_H_ */
