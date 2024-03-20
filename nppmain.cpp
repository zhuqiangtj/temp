/********************************************************************
** nppmain.c
**
** purpose: 
** 
** author:  yanghaifeng@schina.cn
** Copyright (C) 2011 SChina (www.schina.cn) 
**	
** 编译参数：
**      ENABLE_MSSQL
**      ENABLE_SSL
** 调试参数：
**  -q -t oracle 192.168.1.247 1521 1521
**  -q -t db2 127.0.0.1 50010 50000
**  -q -t dameng 127.0.0.1 5236 5336
**  -q -t mssql 192.168.1.67 1433 1433
**  -q -t mysql 192.168.1.50 9207 9207
**  -q -t mysql 192.168.1.67 5258 5258
*********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <stdint.h>
#include<errno.h>
#include "acpdump2.h"
#ifdef ENABLE_MYSQL
#include "dbfw_mysqlprivate.h"
#endif
#ifdef ENABLE_DB2
#include "db2_private.h"
#endif
#ifdef ENABLE_DM
#include "dameng_private.h"
#endif
#ifdef ENABLE_CACHEDB
#include "chdb_private.h"
#endif
#ifdef ENABLE_HIVE
#include "hive_private.h"
#include "npp_kerberos_help.h"
#endif
#ifdef ENABLE_IMPALA
#include "impala_private.h"
#endif
#ifdef ENABLE_HRPC
#include "hrpc_private.h"
#endif
#ifdef ENABLE_GAUSSDB_T
#include "gaussdb_oltp_private.h"
#endif
#ifdef ENABLE_ZK
#include "zookeeper_private.h"
#endif
#ifdef ENABLE_ES
#include "es_private.h"
#endif

#ifdef ENABLE_REDIS
#include "redis_private.h"
#endif
#include "dbfw_ac_server.h"
#include "dbfw_limits.h"
#include "npp_common.h"
#include "npp_dump.h"
#include "npp_log.h"

#include "smem_global.h"
#include "dbfw_smem.h"
#include "smem_log.h"

#include "npp_exception.h"
#include "npp_load_info.h"
#include "dbfw_mempool.h"
#include "dbfw_filter_internal.h"
#include "dbfwsga_acbuff.h"
#include "dbfwsga_global.h"
#include "dbfwsga_auditbuf.h"
#include "dbfwsga_runtime.h"
#include "dbfw_risk_engine.h"
#include "dbfw_vpatch.h"
#include "auditclient.h"
#include "protocol.h"
#include "npc_interface.h"
#include "encode.h"
#include "pcap.h"
#include "librslist.h"
#include "libbslhash.h"
#include "npp_runtime.h"
#include "compat_select.h"
#include "dspr_memqueue.h"
#include "dbfwsga_sqlfuzzy.h"
#include "dbfwsga_url.h"
#include "dbfwsga_objects.h"
#include "dbfwsga_sql_template.h"
#include "dbfwsga_tlog.h"
#include "dbfwsga_runtime.h"
#include "dbfwsga_capbuf.h"

#ifdef ENABLE_DBSCLOUD
#include "extac_public.h"
#include "dbfw_customization.h"
#endif
#ifdef NEW_TCP_REORDER
    /* 新的TCP Reorder方法 */
    #include "tcp_reorder.h"
#endif
#ifdef HAVE_SQL_MODIFY_ENGINE
#include "dbfw_sqlmodify.h"
#endif
#ifdef HAVE_CHERRY
#include "dbfw_tamper.h"
#endif
#ifdef NEW_TAMPER_FORPROXY
#include "dbfw_tamper.h"
#endif
#include <netinet/in.h>    // for sockaddr_in
#include <sys/types.h>    // for socket
#include <sys/socket.h>    // for socket    
#include <netinet/in.h> 
#include <netinet/tcp.h>
#include "dbfw_fixarray_interface.h"
#include "npp_global.h"
#include "filter.h"
#include "action.h"
#include "fixarray_dbaccess.h"
#include "dbfw_db_dialect.h"
#include "dbfw_acbuff_interface.h"


#ifdef HAVE_LUA
#include "SessionForLua.h"  
#include "StatementForLua.h"
#endif
#include "dbfw_hbase.h" // for shutdown protobuf
#include "teradata_private.h"
#include "hana_private.h"
#include "npp_decryption.h"

#ifdef HAVE_SQL_MODIFY_ENGINE
	#ifdef HAVE_SQL_SPY
		#include "dbfw_sql_parser.h"
		#include "dbfw_sql_parser_mssql.h"
		#include "dbfw_sql_parser_mysql.h"
		#include "dbfw_sql_parser_db2.h"
		#include "dbfw_sql_parser_dm.h"
		#include "dbfw_sql_parser_postgre.h"
		#include "dbfw_sql_parser_informix.h"
		#include "dbfw_sql_parser_cache.h"
		#include "dbfw_sql_parser_oscar.h"
	#endif
#endif

#ifdef ENABLE_TELNET 
#include "mysql.h"
#include "mysqld_error.h"
MYSQL *g_telnet_mysql = NULL;
#endif

#include "npp_passwd_bridge.h"
#include "dspr_hashmap.h"
#include "dbfw_mask.h"


/* 定义无连接会话的连接方式信息(is_sos) */
#define DBFW_SESSION_CONNTYPE_UNKNOWN   0
#define DBFW_SESSION_CONNTYPE_JDBC308   1       /* JDBC TNSV308，9i和10g使用，默认值 */
#define DBFW_SESSION_CONNTYPE_JDBC310   2       /* JDBC TNSV310，JDBC Thin 11g */
#define DBFW_SESSION_CONNTYPE_JDBC315   3       /* JDBC TNSV315，12C-12.1.0.1 */
#define DBFW_SESSION_CONNTYPE_OCI9I     4       /* OCI9i客户端连接 */
#define DBFW_SESSION_CONNTYPE_OCI101    5       /* OCI 10.1客户端连接 */
#define DBFW_SESSION_CONNTYPE_OCI102    6       /* OCI 10.2客户端连接 */
#define DBFW_SESSION_CONNTYPE_OCI110    7       /* OCI 11.X客户端连接 */
/* 定义无连接会话的客户端操作系统信息(is_pci) */
#define DBFW_SESSION_OS_UNKNOWN   0
#define DBFW_SESSION_OS_WIN32     1       /* Win32 */
#define DBFW_SESSION_OS_WIN64     2       /* Win64 */
#define DBFW_SESSION_OS_LINUX32   3       /* Linux32 */
#define DBFW_SESSION_OS_LINUX64   4       /* Linux64 */
#define DBFW_SESSION_OS_AIX32     5       /* AIX32 */
#define DBFW_SESSION_OS_AIX64     6       /* AIX64 */
#define DBFW_SESSION_OS_SLA32     7       /* Solaris32 */
#define DBFW_SESSION_OS_SLA64     8       /* Solaris64 */
#define DBFW_SESSION_OS_HPUX      9       /* HPUnix64 */
#define DBFW_MAGIC_NOMESSAGE      "无信息"

#define DBFW_TCPDATA_MINSIZE      3     /* TCP数据的最小尺寸，用于判断是否是Keep Alive数据 */

#define HALF_OF_UINT_MAX        0x7FFFFF

#define MAX_FRAME_SIZE_FORNPC	10*1024		/* 系统handlenpc能够处理的最大frame尺寸，超出该尺寸则阶段 */

#define STMT_COUNT_LOG_FORSTMTTABLE		500	/* 当stmp_table_hash中的stmt个数超过此数量时记录日志 */

#define TIMEOUT_FIN_FOR_CHERRY	1000000		/* FIN包之后的ACK包的超时时间，1秒 */

#define TIMEOUT_SUSPEND_SEC		3600		/* NPP进程挂起的超时时间，超过该时间则自动退出 */

#ifdef ENABLE_SSL
    #include <openssl/ssl.h>    // link with libssl.a libcrypto.a -lgdi32
	#include <openssl/err.h> 
#else                           // on linux: gcc -o stcppipe stcppipe.c -lssl -lcrypto -lpthread
    #define SSL     char
    #define SSL_read(A,B,C)     0
    #define SSL_write(A,B,C)    0
#endif

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/net.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>

#define ONESEC          1
#define set_priority    nice(-10)

#define INTERLOCK_VAR(X)    static int X = 0
#define INTERLOCK_GET(X)    X
#define INTERLOCK_SET(X,Y)  X = Y
#define INTERLOCK_DEC(X)    X--
#define INTERLOCK_INC(X)    X++

/* add by yanghaifeng@schina.cn */

#include "oranetprivate.h"
#include "oranet8_ack.h"
#include "libtis.h"

#include "dbfw_tlog.h"

#if defined ENABLE_DBSCLOUD
#include "sga_public.h"
#include "extac_public.h"
#endif
#ifdef ENABLE_SSL_AUDIT
#include "ssl_package_proc.h"
#endif
#ifdef SOURCECODE
#undef SOURCECODE
#endif
#define SOURCECODE 1
#define thread_id   pthread_t

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;




#define XORBYTE         0xff







INTERLOCK_VAR(cur_connections);
struct  sockaddr_in lpeer,
                    dpeer,
                    rpeer,
                    *dhost  = NULL;
in_addr_t   *iplist         = NULL,
            *rhost          = NULL,
            *lifaces        = NULL,
            Lhost           = INADDR_ANY;
int         quiet           = 0,
            l_xor             = 0,
            frontend_ssl_state           = 0,
			backend_ssl_state        =0,
            dump_stdout     = 0,
            ssl_method_type = 23,
            max_connections = 0;
unsigned char          *dump           = NULL,
            *cleardump = NULL,
            *subst1         = NULL,
            *subst2         = NULL,
            *ssl_cert_file  = NULL,
            *ssl_cert_pass  = NULL,
            *db_type        = NULL;


/*
    global variable
*/
//void*   __DBFW_SGA_ADDR;                /* sga start address */
#define WORKTIME_DEFALUT        3600*24     /* 默认发呆时长，秒 */
u_int   __PROCESS_ID = 0;                   /* process/thread id*/
Dbfw_Sga_Fixarray_Buff __SGA_FIXARRAY;
Dbfw_Sga_SessBuff*    __SGA_SESSBUF;  /* sga's session buffer */
Dbfw_Sga_SQLTBuff      __SGA_SQLTBUF;  /* sga's session buffer */
Dbfw_Sga_TlogBuff*       __SGA_TLOGBUF;  /* sga's tlog buffer */
Dbfw_Sga_ACBuff         __SGA_ACBUF;    /* sga's ac buffer */
Dbfw_Sga_RTBuff_Buff     __SGA_RTBUF;    /* sga's ac buffer */
Dbfw_Sga_CapBuff			__SGA_CAPBUF;
AC_XSec_Databse*        __SGA_AC_XSEC_DATABASE; /* sga's ac buffer's xsec database */
AC_Databse_Address*     __SGA_AC_DATABASE_ADDRESS;  /* sga's ac buffer's AC_Databse_Address */
//void*                   __SGA_CAPBUF;
Dbfw_Sga_SqlFuzzyBuf	__SGA_SQLFUZZYBUF;

u_int                   __DB_ADDRESS;       /* IP Address of DB Server */
u_int                   __DB_PORT;          /* IP Port of DB Server */
u_int                   __DB_SLOT_IDX;
u_char                  __DB_ISFIND;        /* 是否发现数据库实例配置的标记 0-否 1-是 */
//#ifndef WIN32
OraNet8_Session *       __ORA_SESSION = NULL;  /* process's session */
char                    __DBFW_INSTANCE_NAME[64+1];  /* DBFW系统的实例名，最长8字节 */
//#endif
Npp_All_Config*         __NPP_ALL_CONFIG;       /* 全部的NPP配置参数 */
u_char                  __NPP_PROCESS_TYPE;     /* NPP_PROCESS_TYPE_NETWORK/NPP_PROCESS_TYPE_DA/NPP_PROCESS_TYPE_NPC */
/* VPatch参数 */
VPatch_InputInfo*       __VPATCH_INPUT_INFO = NULL;

/* 内存池 */
Dbfw_Mem_SlotOfChunk    *__SLOT_OF_CHUNKS = NULL;
Dbfw_Mempool            *__MEM_POOL = NULL;
Dbfw_Mempool_StackWalk  *__MEM_STACKWALK = NULL;
u_char                  __MEMPOOL_INIT = 0;     /* mempool初始化标记 0-否 1-是 */
int		__SOCK_TYPE = AF_INET;	/*sock 类型*/
/* 为应对tcpreplay的性能测试场景，
 *  解决该工具loop之后sequence不增长问题，增加开关
 *  ，解析重传包，开启方式为 touch /dev/shm/npp_tcpreplay */
bool    __NPP_TCPREPLAY_SWITCH = false;

#ifdef HAVE_LUA
lua_State *L;
Dbfw_SessCommon	*__SessionData_Ptr;
Dbfw_SqlCommon *__StatementData_ptr;
#endif

#ifdef ENABLE_CLUSTER
int global_hostid;
int global_regionid;
#endif
//char    *__CORE_DATA;
//int     __CORE_DATA_SIZE = 0;
//u_int64                 __LAST_TLOG_FLUSH_TIME = 0;       /* 最后一次tlogbuf刷新的时间 */
//u_int                   __HELP_STMTSECQUENCE = 0;   /* 会话级的sql语句secquence信息 */
static const unsigned char SSL_CERT_X509[] =   
"\x30\x82\x03\x07\x30\x82\x02\x70\xa0\x03\x02\x01\x02\x02\x09\x00"
"\x85\x3a\x6e\x0a\xa4\x3c\x6b\xec\x30\x0d\x06\x09\x2a\x86\x48\x86"
"\xf7\x0d\x01\x01\x05\x05\x00\x30\x61\x31\x0b\x30\x09\x06\x03\x55"
"\x04\x06\x13\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x14"
"\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x07\x14\x02\x22\x22"
"\x31\x0b\x30\x09\x06\x03\x55\x04\x0a\x14\x02\x22\x22\x31\x0b\x30"
"\x09\x06\x03\x55\x04\x0b\x14\x02\x22\x22\x31\x0b\x30\x09\x06\x03"
"\x55\x04\x03\x14\x02\x22\x22\x31\x11\x30\x0f\x06\x09\x2a\x86\x48"
"\x86\xf7\x0d\x01\x09\x01\x16\x02\x22\x22\x30\x1e\x17\x0d\x30\x39"
"\x30\x31\x30\x34\x30\x33\x31\x34\x33\x33\x5a\x17\x0d\x31\x30\x30"
"\x31\x30\x34\x30\x33\x31\x34\x33\x33\x5a\x30\x61\x31\x0b\x30\x09"
"\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55"
"\x04\x08\x14\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x07\x14"
"\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x0a\x14\x02\x22\x22"
"\x31\x0b\x30\x09\x06\x03\x55\x04\x0b\x14\x02\x22\x22\x31\x0b\x30"
"\x09\x06\x03\x55\x04\x03\x14\x02\x22\x22\x31\x11\x30\x0f\x06\x09"
"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x02\x22\x22\x30\x81\x9f"
"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03"
"\x81\x8d\x00\x30\x81\x89\x02\x81\x81\x00\xc5\xe3\x3f\x2d\x8f\x98"
"\xc2\x2a\xef\x71\xea\x40\x21\x54\x3f\x08\x62\x9c\x7b\x39\x22\xfd"
"\xda\x80\x1f\x21\x3e\x8d\x68\xcf\x8e\x6b\x70\x98\x95\x2c\x1e\x4e"
"\x79\x39\x45\xf5\xa3\xd9\x20\x54\x85\x79\x36\xf5\x08\xbe\xa0\xa6"
"\x03\x80\x60\x21\xd6\xbc\xde\xf8\xed\xe8\x73\x02\x96\x84\xcb\xb4"
"\xff\x72\x89\xf4\x56\x41\xf6\x28\xf6\x6b\x9f\x0c\x1d\xe0\x9b\x21"
"\xcb\x86\x08\xdf\x6b\xc1\x8a\xd6\xa3\x52\x2f\xfa\xd8\x5a\x2c\x86"
"\x52\x0d\x75\x2d\xf6\x17\x11\xa7\x17\xad\xc2\x3b\xd8\x0f\xcf\xb7"
"\x2b\x2c\x8a\xc4\xcd\x2d\x94\xe4\x15\x75\x02\x03\x01\x00\x01\xa3"
"\x81\xc6\x30\x81\xc3\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14"
"\x00\x6b\x12\xa2\xb9\x10\x90\xe4\xe5\xe8\xff\xec\x5c\x24\x44\xee"
"\xed\xc1\x66\xb7\x30\x81\x93\x06\x03\x55\x1d\x23\x04\x81\x8b\x30"
"\x81\x88\x80\x14\x00\x6b\x12\xa2\xb9\x10\x90\xe4\xe5\xe8\xff\xec"
"\x5c\x24\x44\xee\xed\xc1\x66\xb7\xa1\x65\xa4\x63\x30\x61\x31\x0b"
"\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0b\x30\x09\x06"
"\x03\x55\x04\x08\x14\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04"
"\x07\x14\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x0a\x14\x02"
"\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x0b\x14\x02\x22\x22\x31"
"\x0b\x30\x09\x06\x03\x55\x04\x03\x14\x02\x22\x22\x31\x11\x30\x0f"
"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x02\x22\x22\x82"
"\x09\x00\x85\x3a\x6e\x0a\xa4\x3c\x6b\xec\x30\x0c\x06\x03\x55\x1d"
"\x13\x04\x05\x30\x03\x01\x01\xff\x30\x0d\x06\x09\x2a\x86\x48\x86"
"\xf7\x0d\x01\x01\x05\x05\x00\x03\x81\x81\x00\x33\xb1\xd0\x31\x04"
"\x17\x67\xca\x54\x72\xbc\xb7\x73\x5a\x8f\x1b\x23\x25\x7d\xcb\x23"
"\xae\x1b\x9b\xd2\x92\x80\x09\x5d\x20\x24\xd2\x73\x6f\xe7\x5a\xaf"
"\x9e\xd0\xdd\x50\x61\x96\xbf\x7c\x2d\xa1\x0a\xc4\x88\xf7\xe0\xc6"
"\xc3\x04\x35\x6f\xac\xd5\xd1\xfd\x55\xab\x6c\x99\xc7\x66\x72\xb8"
"\x70\x22\xcb\xd3\x8c\xa7\x18\x17\x2e\x25\x2f\x33\x5c\x57\x82\x67"
"\x0e\x29\xeb\x81\x74\xd3\xa3\x54\xfa\x08\xba\x87\x50\x18\xab\xc5"
"\x15\x69\xce\x4a\x73\x3b\xee\x12\x4d\x1c\x63\x11\x9b\xdf\x4d\xa1"
"\x38\x0d\xb6\x1d\xfb\xd6\xb8\x5b\xc2\x10\xd9";

static const unsigned char SSL_CERT_RSA[] =    
"\x30\x82\x02\x5b\x02\x01\x00\x02\x81\x81\x00\xc5\xe3\x3f\x2d\x8f"
"\x98\xc2\x2a\xef\x71\xea\x40\x21\x54\x3f\x08\x62\x9c\x7b\x39\x22"
"\xfd\xda\x80\x1f\x21\x3e\x8d\x68\xcf\x8e\x6b\x70\x98\x95\x2c\x1e"
"\x4e\x79\x39\x45\xf5\xa3\xd9\x20\x54\x85\x79\x36\xf5\x08\xbe\xa0"
"\xa6\x03\x80\x60\x21\xd6\xbc\xde\xf8\xed\xe8\x73\x02\x96\x84\xcb"
"\xb4\xff\x72\x89\xf4\x56\x41\xf6\x28\xf6\x6b\x9f\x0c\x1d\xe0\x9b"
"\x21\xcb\x86\x08\xdf\x6b\xc1\x8a\xd6\xa3\x52\x2f\xfa\xd8\x5a\x2c"
"\x86\x52\x0d\x75\x2d\xf6\x17\x11\xa7\x17\xad\xc2\x3b\xd8\x0f\xcf"
"\xb7\x2b\x2c\x8a\xc4\xcd\x2d\x94\xe4\x15\x75\x02\x03\x01\x00\x01"
"\x02\x81\x80\x59\x45\x5c\x11\xf4\xae\xc8\x21\x50\x65\xc6\x74\x69"
"\xd4\xb4\x9e\xd6\xc5\x9a\xfd\x3a\xa0\xe4\x7a\x5a\x10\xc8\x44\x48"
"\xdd\x21\x75\xac\x94\xd8\xee\xcf\x39\x3d\x8c\xad\xd7\xd3\xb3\xb6"
"\xd7\x0a\x63\x95\x7c\x53\x16\x94\x28\x70\x79\xf0\x64\x33\x98\x7e"
"\xca\x33\xa0\x97\x38\x01\xe9\x06\x9b\x5c\x15\x3d\x89\xa3\x40\x2a"
"\x54\xb1\x79\x15\xf1\x7c\xfd\x18\xca\xdf\x53\x42\x6c\x8a\x0b\xc1"
"\x18\x70\xea\x7e\x00\x64\x07\x84\x37\xf2\x1b\xf5\x2a\x22\xe9\xd6"
"\xfa\x03\xc6\x7f\xaa\xc8\xa2\xa3\x67\x2a\xd3\xdd\xae\x36\x47\xc1"
"\x4f\x13\xe1\x02\x41\x00\xec\x61\x11\xbf\xcd\x87\x03\xa6\x87\xc9"
"\x2f\x1d\x80\xc1\x73\x5f\x19\xe7\x7c\xb9\x67\x7e\x49\x58\xbf\xab"
"\xd8\x37\x29\x22\x69\x79\xa4\x06\xcd\xac\x5f\x9e\xba\x12\x77\xf8"
"\x3e\xd2\x6a\x06\xb5\x90\xe4\xfa\x23\x86\xff\x41\x1b\x10\xbe\xe4"
"\x9d\x29\x75\x7c\xe6\x49\x02\x41\x00\xd6\x50\x40\xfc\xc9\x49\xad"
"\x69\x55\xc7\xa3\x5d\x51\x05\x5b\x41\x2b\xd2\x5a\x74\xf8\x15\x49"
"\x06\xf0\x1a\x6f\x7d\xb6\x65\x17\xa0\x64\xff\x7a\xd6\x99\x54\x0d"
"\x53\x95\x9f\x6c\x43\xde\x27\x1b\xe9\x24\x13\x43\xd5\xda\x22\x85"
"\x1d\xa7\x55\xa5\x4d\x0f\x5e\x45\xcd\x02\x40\x51\x92\x4d\xe5\xba"
"\xaf\x54\xfb\x2a\xf0\xaa\x69\xab\xfd\x16\x2b\x43\x6d\x37\x05\x64"
"\x49\x98\x56\x20\x0e\xd5\x56\x73\xc3\x84\x52\x8d\xe0\x2b\x29\xc8"
"\xf5\xa5\x90\xaa\x05\xe8\xe8\x03\xde\xbc\xd9\x7b\xab\x36\x87\x67"
"\x9e\xb8\x10\x57\x4f\xdd\x4c\x69\x56\xe8\xc1\x02\x40\x27\x02\x5a"
"\xa1\xe8\x9d\xa1\x93\xef\xca\x33\xe1\x33\x73\x2f\x26\x10\xac\xec"
"\x4c\x28\x2f\xef\xa7\xf4\xa2\x4b\x32\xed\xb5\x3e\xf4\xb2\x0d\x92"
"\xb5\x67\x19\x56\x87\xa5\x4f\x6c\x6c\x7a\x0e\x52\x55\x40\x7c\xc5"
"\x37\x32\xca\x5f\xc2\x83\x07\xe2\xdb\xc0\xf5\x5e\xed\x02\x40\x1b"
"\x88\xf3\x29\x8d\x6b\xdb\x39\x4c\xa6\x96\x6a\xd7\x6b\x35\x85\xde"
"\x1c\x2c\x3f\x0c\x8d\xff\xf5\xc1\xeb\x25\x3c\x56\x63\xaa\x03\xe3"
"\x10\x24\x87\x98\xd4\x73\x62\x4a\x51\x3b\x01\x9a\xda\x73\xf2\xcd"
"\xd6\xbb\xe3\x3e\x37\xb3\x19\xd9\x82\x91\x07\xdf\xd0\xa9\x80";



void handle_connections(int sock, int sd_one, int *sd_array, int ha, char *client_mac_str,char *oracle_server_mac_str,char *oracle_server_ip_str, u_short init_session);
void handle_connection_proxy(Npp_ProcessParam p_processParam);
void handle_threeway_proxy(Npp_ProcessParam p_processParam);
void handle_npc(Npp_ProcessParam p_processParam);

void xor_data(unsigned char *data, int size);
int array_connect(int sd, in_addr_all *ip, sockaddr_in_all *ipport, sockaddr_in_all *peer, int idx);
sockaddr_in_all *create_peer_array(unsigned char *list, u16 default_port);
void get_sock_ip_port(int sd, u16 *port, in_addr_all *ip);
void get_peer_ip_port(int sd, u16 *port, in_addr_all *ip);
void resolv(char *host, in_addr_all *host_ip);

void std_err(void);
void usage(char * myname);
int mysend(SSL *ssl_sd, int sd, unsigned char *data, int datasz);
int myrecv(SSL *ssl_sd, int sd, unsigned char *data, int datasz);

int NPP_ConnectFilter(OraNet8_Session * ora_session,Npp_RewriteNetPacket*rewrite_packet);

/* 会话找回 */
int Dbfw_SessInfoFindFromSga(OraNet8_Session * ora_session)
{
	int ret = 0;
	int nRet = 0;
    /* 从SGA区获取会话的信息 */
#ifdef HAVE_SESSION_AUTO_REPLACE
    u_int64 current_timestamp;
    if(ora_session->help_last_req_time > ora_session->help_last_resp_time)
        current_timestamp = ora_session->help_last_req_time;
    else
        current_timestamp = ora_session->help_last_resp_time;
    /* 处理MSSQL数据库的udump操作获得的数据库用户名(首先会用于泰安中心医院) */
    if((__SGA_AC_XSEC_DATABASE && __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MSSQL))
    {
        {

            if(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->username[0]==0x00 || 
               strcmp((char*)((SessBuf_SessionData_Ora *)(ora_session->sessdata))->username,"未知用户")==0 ||
               ora_session->unconn_savesga_flag_mssql==0x01/* 已经保存过MSSQL数据库的udump用户名了 */
              )
            {
                /* 用户名为空或“未知用户”或者已经保存过,什么也不做 */
            }
            else
            {
                if((char*)((SessBuf_SessionData_Ora *)(ora_session->sessdata))->username[0]!=0x00 && ora_session->sessCommon.error_code != 18456)
                {
                    /* 
                        username与realusername_formssql_bak已经相同了,并且肯定不是“未知用户”，这样表示username中的数据已经是准确的了，不存在写了一半的情况
                        下面开始强制记录用户名信息到SGA的rt缓冲区
                    */
                    ora_session->unconn_savesga_flag = 0;   /* 清理之前的写标记 */
                    ora_session->unconn_savesga_flag_mssql=0x01;
                    ret = Unconn_CompareAndAddIdenConnectInfo(ora_session,(void*)__SGA_RTBUF.data.ora_unconnect_protocol_data);
                    if(ret==1)
                    {
                        /* 添加了新记录 */
                    }
                }
                else
                {
                }
            }
        }
    }

    /* fix bug 2109 : 去掉|| __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MSSQL,否则会造成所有的MSSQL数据库都会执行一次自动填充 */
    if(ora_session->unconn_have_conninfo_fromsga==0 && 
       (
        (ora_session->help_session_state == DBFW_SESSION_STATE_NOCONNECT) ||
        (strlen((char*)((SessBuf_SessionData_Ora *)(ora_session->sessdata))->username)==0 || strcmp((char*)((SessBuf_SessionData_Ora *)(ora_session->sessdata))->username,"未知用户")==0)
       )
      )
    {
        /* 是无连接会话,并且之前没有从SGA区获取到正确的用户登录信息 */
        if(ora_session->unconn_last_timestamp_conninfo_fromsga==0 || 
           (ora_session->unconn_last_timestamp_conninfo_fromsga+1000000)<current_timestamp)
        {
            /* 当前时间与上一次获取会话信息的时间间隔超过了1秒 */
            ret = Unconn_GetNextIdenConnectInfoFromSGA(ora_session,(void*)__SGA_RTBUF.data.ora_unconnect_protocol_data);
            if(ret>0)
            {
//                /* 找到了记录 */
                ora_session->unconn_have_conninfo_fromsga = 1;

            }
            else if(ret<0)
            {
                /* 找到了信息，但由于有多个登录信息，不可用了;这种情况下不应该重复的进行查找了 */
                ora_session->unconn_have_conninfo_fromsga = 1;
            }
            else
            {
                ora_session->unconn_have_conninfo_fromsga = 0;
            }
            ora_session->unconn_last_timestamp_conninfo_fromsga = current_timestamp;
        }
    }
#endif

	if(ora_session->unconn_have_conninfo_fromsga == 1 && ret >0)
		nRet = 1;
	return nRet;
}

/*
    向RTbuf区设置发送包队列数据
*/
void Dbfw_SetSendQueueToRtbuf(int data_type)
{
    // guoxw 20160715
    char errbuf[256] = {0};
    Tis_Manager *tis = NULL;

	tis = __SGA_CAPBUF.tis;
	if(tis == NULL)
	{
		OraNet_DumpSql("Dbfw_SetSendQueueToRtbuf, get tis error:%s\n", errbuf);
		return;
	}
	else
	{
		if(Tis_Content_Type(tis) == 0)
			return;
	}

	Dspr_MemQueue_Err queue_err ;
	memset(&queue_err, 0, sizeof(Dspr_MemQueue_Err));
#ifdef HAVE_CHERRY
    int ret = 0;
    if(__NPP_ALL_CONFIG->start_for_transparent==0)
    {
        /* 不是按照DPDK全透明网桥方式启动的NPC，则直接返回 */
        return;
    }
    if(data_type==DBFW_TAMPER_TYPE_TIMEOUT)
    {
        /* 超时，无论是否有当前的数据包，都设置 */
        __NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_TAMPER_TYPE_TIMEOUT;
        __NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
#ifdef DEBUG_CHERRY
        printf("[CHERRY] Dbfw_SetSendQueueToRtbuf DBFW_TAMPER_TYPE_TIMEOUT\n");
#endif
        ret = dspr_memqueue_put(__NPP_ALL_CONFIG->memqueue,(Dspr_MemQueue_Node*)&__NPP_ALL_CONFIG->nfw_memqueue_node, &queue_err); 
        if((queue_err.err_no&DSPR_MQ_FULL_1) || (queue_err.err_no&DSPR_MQ_FULL_2))
		{
			Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" memqueue put generate ERR ,_iSend:%llud, irecv:%llud , errno:%d", queue_err.iSend, queue_err.iRecv, queue_err.err_no);
		}
    }
    else if(data_type==DBFW_TAMPER_TYPE_CRASH)
    {
        /* core或关闭，无论是否有当前的数据包，都设置 */
        __NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_TAMPER_TYPE_CRASH;
        __NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
#ifdef DEBUG_CHERRY
        printf("[CHERRY] Dbfw_SetSendQueueToRtbuf DBFW_TAMPER_TYPE_CRASH\n");
#endif
        ret = dspr_memqueue_put(__NPP_ALL_CONFIG->memqueue,(Dspr_MemQueue_Node*)&__NPP_ALL_CONFIG->nfw_memqueue_node, &queue_err);
		if((queue_err.err_no&DSPR_MQ_FULL_1) || (queue_err.err_no&DSPR_MQ_FULL_2))
		{
			Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" memqueue put generate ERR ,_iSend:%llud, irecv:%llud , errno:%d", queue_err.iSend, queue_err.iRecv, queue_err.err_no);
		}

    }
    else if(data_type==DBFW_TAMPER_TYPE_EXIT)
    {
        /* core或关闭，无论是否有当前的数据包，都设置 */
        __NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_TAMPER_TYPE_EXIT;
        __NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
#ifdef DEBUG_CHERRY
        printf("[CHERRY] Dbfw_SetSendQueueToRtbuf DBFW_TAMPER_TYPE_EXIT\n");
#endif
        ret = dspr_memqueue_put(__NPP_ALL_CONFIG->memqueue,(Dspr_MemQueue_Node*)&__NPP_ALL_CONFIG->nfw_memqueue_node, &queue_err);     
		if((queue_err.err_no&DSPR_MQ_FULL_1) || (queue_err.err_no&DSPR_MQ_FULL_2))
		{
			Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" memqueue put generate ERR ,_iSend:%llud, irecv:%llud , errno:%d", queue_err.iSend, queue_err.iRecv, queue_err.err_no);
		}

	}
    else if(data_type==DBFW_TAMPER_TYPE_SWITCHOFF)
    {
        /* 阻断，无论是否有当前的数据包，都设置 */
        __NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_TAMPER_TYPE_SWITCHOFF;
        __NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
#ifdef DEBUG_CHERRY
        printf("[CHERRY] Dbfw_SetSendQueueToRtbuf DBFW_TAMPER_TYPE_SWITCHOFF\n");
#endif
        ret = dspr_memqueue_put(__NPP_ALL_CONFIG->memqueue,(Dspr_MemQueue_Node*)&__NPP_ALL_CONFIG->nfw_memqueue_node, &queue_err);     
		if((queue_err.err_no&DSPR_MQ_FULL_1) || (queue_err.err_no&DSPR_MQ_FULL_2))
		{
			Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" memqueue put generate ERR ,_iSend:%llud, irecv:%llud , errno:%d", queue_err.iSend, queue_err.iRecv, queue_err.err_no);
		}
	}
    else if(data_type==DBFW_TAMPER_TYPE_TAMPER)
    {
        /* 篡改，必须有数据包 */
        if(__NPP_ALL_CONFIG->nfw_memqueue_node.value>0)
        {
            __NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_TAMPER_TYPE_TAMPER;
            __NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
#ifdef DEBUG_CHERRY
            printf("[CHERRY] Dbfw_SetSendQueueToRtbuf DBFW_TAMPER_TYPE_TAMPER\n");
#endif
            ret = dspr_memqueue_put(__NPP_ALL_CONFIG->memqueue,(Dspr_MemQueue_Node*)&__NPP_ALL_CONFIG->nfw_memqueue_node, &queue_err); 
			if((queue_err.err_no&DSPR_MQ_FULL_1) || (queue_err.err_no&DSPR_MQ_FULL_2))
			{
				Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" memqueue put generate ERR ,_iSend:%llud, irecv:%llud , errno:%d", queue_err.iSend, queue_err.iRecv, queue_err.err_no);
			}
		}    
    }
    else if(data_type==(DBFW_TAMPER_TYPE_TAMPER|DBFW_TAMPER_TYPE_SWITCHOFF))
    {
        /* 篡改+reset，必须有数据包 */
        if(__NPP_ALL_CONFIG->nfw_memqueue_node.value>0)
        {
            __NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_TAMPER_TYPE_TAMPER_OFF;
            __NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
#ifdef DEBUG_CHERRY
            printf("[CHERRY] Dbfw_SetSendQueueToRtbuf TAMPER+RESET\n");
#endif
            ret = dspr_memqueue_put(__NPP_ALL_CONFIG->memqueue,(Dspr_MemQueue_Node*)&__NPP_ALL_CONFIG->nfw_memqueue_node, &queue_err); 
			if((queue_err.err_no&DSPR_MQ_FULL_1) || (queue_err.err_no&DSPR_MQ_FULL_2))
			{
				Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" memqueue put generate ERR ,_iSend:%llud, irecv:%llud , errno:%d", queue_err.iSend, queue_err.iRecv, queue_err.err_no);
			}
		}    
    }
    else if(data_type==DBFW_TAMPER_TYPE_DISCARD)
    {
    	if(__NPP_ALL_CONFIG->nfw_memqueue_node.value>0)
	    {
	    	__NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_TAMPER_TYPE_DISCARD;
	    	__NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
			ret = dspr_memqueue_put(__NPP_ALL_CONFIG->memqueue,(Dspr_MemQueue_Node*)&__NPP_ALL_CONFIG->nfw_memqueue_node, &queue_err);
			if((queue_err.err_no&DSPR_MQ_FULL_1) || (queue_err.err_no&DSPR_MQ_FULL_2))
			{
				Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" memqueue put generate ERR ,_iSend:%llud, irecv:%llud , errno:%d", queue_err.iSend, queue_err.iRecv, queue_err.err_no);
			}

		}
    }
    else if(data_type==0x40)
    {
        /* 篡改+rollback+reset */
        if(__NPP_ALL_CONFIG->nfw_memqueue_node.value>0)
        {
            __NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_TAMPER_TYPE_ROLLBACK_OFF;
            __NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
#ifdef DEBUG_CHERRY
            printf("[CHERRY] Dbfw_SetSendQueueToRtbuf TAMPER+ROLLBACK+RESET\n");
#endif
            ret = dspr_memqueue_put(__NPP_ALL_CONFIG->memqueue,(Dspr_MemQueue_Node*)&__NPP_ALL_CONFIG->nfw_memqueue_node, &queue_err); 
			if((queue_err.err_no&DSPR_MQ_FULL_1) || (queue_err.err_no&DSPR_MQ_FULL_2))
			{
				Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" memqueue put generate ERR ,_iSend:%llud, irecv:%llud , errno:%d", queue_err.iSend, queue_err.iRecv, queue_err.err_no);
			}
		}
    }
    else if(data_type==DBFW_TAMPER_TYPE_NORMAL)
    {
        /* 正常放行包 */
        if(__NPP_ALL_CONFIG->nfw_memqueue_node.value>0)
        {
            /* 有需要DPDK的NFW发送的通讯包 */
            __NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_TAMPER_TYPE_NORMAL;
            __NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
            ret = dspr_memqueue_put(__NPP_ALL_CONFIG->memqueue,(Dspr_MemQueue_Node*)&__NPP_ALL_CONFIG->nfw_memqueue_node, &queue_err);
			if((queue_err.err_no&DSPR_MQ_FULL_1) || (queue_err.err_no&DSPR_MQ_FULL_2))
			{
				Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" memqueue put generate ERR ,_iSend:%llud, irecv:%llud , errno:%d", queue_err.iSend, queue_err.iRecv, queue_err.err_no);
			}
		}
    }    
    /* 重置nfw_memqueue_node的值 */
    __NPP_ALL_CONFIG->nfw_memqueue_node.value = 0;
    __NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_TAMPER_TYPE_NORMAL;
    __NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
    /* 重置会话的篡改数据指针 */
    if(__ORA_SESSION)
    {
        __ORA_SESSION->tamper_data_addr = NULL;
        __ORA_SESSION->tamper_data_size = 0;
        __ORA_SESSION->tamper_pack_type = 0;
    }
#endif    
}

/*
    立即执行阻断处理
    目前只用于仅支持阻断，不支持拦截的数据库类型
*/
void Dbfw_Switchoff_Immediately_ForHandleNpc(void)
{
#ifdef HAVE_CHERRY
    /* MSSQL目前只支持阻断，并且无法抛出异常 */
    {
        /* 
            TODO : 阻断 
            1:篡改当前包为拦截包，发送该包
            2:等待04包返回，并篡改返回的报错信息,并发送
            3:发送reset包
        */
#ifdef DEBUG_CHERRY
        printf("[CHERRY] Dbfw_Switchoff_Immediately_ForHandleNpc\n");
#endif
        //OraNet_DumpSql("OraTnsPackageParse result is switchoff\n");
        {
            /* 不可篡改，只能发送阻断包 */
            Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
#ifdef DUMP_MEMORY_LEAK
            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
#else
            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
#endif
            //continue;
        }
    }
#endif
}



void NPP_SetSessionForHandlePcap(OraNet8_Session *ora_session)
{
    int i = 0;
    int length = 0;
    u_int64 start_cli_address[2];  /* 来自__SGA_AC_XSEC_DATABASE->database_unconnect[i].start_cli_address的计算结果 */
    u_int64 end_cli_address[2];    /* 来自__SGA_AC_XSEC_DATABASE->database_unconnect[i].end_cli_address的计算结果 */
    u_int64 unconn_ipkey = 0;
    u_char connect_type = 0;    /* 
                                    is_sox字段的值，表示连接方式，值1～9 
                                    0-表示未使用(未知) 
                                    1-JDBC308(9i和10g使用默认值) 
                                    2-JDBC310(JDBC Thin 11g) 
                                    3-JDBC315(12C-12.1.0.1) 
                                    4-OCI(9i) 
                                    5-OCI(10.1) 
                                    6-OCI(10.2) 
                                    7-OCI(11.X)
                                */
    u_char client_type = 0;     /*
                                    is_pci字段的值，表示客户端操作系统，值 1～9
                                    0表示未使用(未知) 
                                    1-Windows32 
                                    2-Windows64 
                                    3-Linux 32 
                                    4-Linux64(默认值) 
                                    5-AIX32 
                                    6-Aix64 
                                    7-Solaris32 
                                    8-Solaris64 
                                    9-HPUnix 64
                                */
    u_char server_type = 0;     /*
                                    is_glba字段的值，表示服务器的操作系统，值 1～9
                                    0表示未使用(未知) 
                                    1-Windows32 
                                    2-Windows64 
                                    3-Linux32 
                                    4-Linux64(默认值) 
                                    5-AIX32 
                                    6-Aix64 
                                    7-Solaris32 
                                    8-Solaris64 
                                    9-HPUnix 64
                                */
	/* 刘思成添加Mysql和SHENTONG */
    if(__SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_ORACLE &&
       __SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_DM &&
	   __SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_MYSQL &&
	   __SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_SHENTONG &&
	   __SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_DB2  &&
	   __SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_KINGBASE  &&
	   __SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_POSTGREE &&
       __SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_OSCAR &&
	   __SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_IFX &&
	   __SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_CACHEDB &&
	   __SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_GBASE8T &&
		__SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_TERADATA &&
		__SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_HIVE &&
		__SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_IMPALA &&
		__SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_HRPC &&
		__SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_SENTRY &&
		__SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_REDIS &&
	   __SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_HANA &&
	   __SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_ES &&
		__SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_WEBHTTP &&
		__SGA_AC_XSEC_DATABASE->dialect!=DBFW_DBTYPE_SYBASEIQ
       )
    {
        /* 非Oracle/DM/mysql/Gbase数据库，不需要配置以下信息 */
        return;
    }
    /*
        先获取默认的无连接的会话的配置信息,也许该默认配置是“无效的”，但肯定会有默认信息
        前提条件：配置的服务器的版本和操作系统是正确的       
    */
    //ora_session->help_session_state = DBFW_SESSION_STATE_NOCONNECT;   /* 不能在这里设置 */
    /* 内部测试 */
//     __SGA_AC_XSEC_DATABASE->is_sox  = DBFW_SESSION_CONNTYPE_OCI102;
//     __SGA_AC_XSEC_DATABASE->is_pci  = DBFW_SESSION_OS_WIN32;
//     __SGA_AC_XSEC_DATABASE->is_glba  = DBFW_SESSION_OS_LINUX64;
    OraNet_DumpSql("is_sos       = %d\n",__SGA_AC_XSEC_DATABASE->is_sox);
    OraNet_DumpSql("is_pci       = %d\n",__SGA_AC_XSEC_DATABASE->is_pci);
    OraNet_DumpSql("is_glba      = %d\n",__SGA_AC_XSEC_DATABASE->is_glba);
    if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_ORACLE)
    {
        /* Oracle数据库 */
        connect_type    = __SGA_AC_XSEC_DATABASE->is_sox;
        client_type     = __SGA_AC_XSEC_DATABASE->is_pci;
        server_type     = __SGA_AC_XSEC_DATABASE->is_glba;   
        
#ifdef HAVE_CHERRY   // 20151118 guoxw HA sync
    	if(ora_session->syncd_session)
    	{
    		ora_session->unconn_iden_result = UNCONN_IDEN_RESULT_OVER;
    		
    		/* 修改此处是解决oranetparse.cpp文件OraTnsPackageParse()中判断
    		 * ora_session->help_session_state == DBFW_SESSION_STATE_NORMAL && ora_session->have_0106_for_oracle==0后
    		 * 将ora_session->help_session_state置为DBFW_SESSION_STATE_NOCONNECT
    		 * 从而Unconn_GetNextIdenConnectInfoFromSGA中将一系列值使用内存中第一个session的信息填充
    		 */
    		ora_session->have_0106_for_oracle = 1;
    		
    		ora_session->help_session_state = DBFW_SESSION_STATE_NORMAL;
    		ora_session->help_connect_state = 0x01;
    		
    		return;   // 同步的会话，直接返回
    	}    
#endif    
             
        /* 先设置缺省配置:JDBC308+Linux64 */
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version = ORA_TNS_VER_313;
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.compatiable_version = ORA_TNS_VER_300;
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.sdu_size = 2048;
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tdu_size = 0x7fff;
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.conn_data_len = 0;
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.offset_of_conndata = 0;
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.max_receivable_conn_data = 0;

        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.tns_version = ORA_TNS_VER_314;
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.sdu_size = 2048;
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.tdu_size = 0x7fff;
        ora_session->help_db_charset_utf8 = 0;  /* 未知 */

        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori = OS_WIN;
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os = OS_WIN;
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_bit = 0x32;

        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_ori = OS_LINUX;
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_LINUX;
        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_bit = 0x64;

        //memset(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->username,0x00,sizeof(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->username));
        //z_strcpy((char*)((SessBuf_SessionData_Ora *)(ora_session->sessdata))->username,(char*)DBFW_MAGIC_NOMESSAGE, __FILE__, __LINE__, Smem_LogError_Format);
        memset(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->auth_instance_name,0x00,sizeof(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->auth_instance_name));
        //s_strcpy((char*)((SessBuf_SessionData_Ora *)(ora_session->sessdata))->auth_instance_name,(char*)DBFW_MAGIC_NOMESSAGE, SGA_TYPE_SESSBUF, __FILE__, __LINE__, Smem_LogError_Format);
        /* 首先进行Oracle无连接协议智能识别结果找回,即使用户设置了无连接会话的信息，也要先从识别结果中查找 */
        ora_session->unconn_iden_result = UNCONN_IDEN_RESULT_NOTOVER;
        /* 根据ora_session记录的客户端IP，获取配置的与该IP应用相关的配置信息 */
        for(i=0;i<DBFW_MAX_DATABASE_UNCONNECT;i++)
        {
            if(__SGA_AC_XSEC_DATABASE->database_unconnect[i].state == 1)
            {
                /* 
                    是有效数据:
                    检查ora_session的客户端IP是否符合记录的IP范围
                */
                if(strchr((char *)(__SGA_AC_XSEC_DATABASE->database_unconnect[i].start_cli_address),'.') != NULL)
                {
                	start_cli_address[0] = DBFW_HTON32(str2ip(__SGA_AC_XSEC_DATABASE->database_unconnect[i].start_cli_address));
                	start_cli_address[1] = 0; 
                }else{
					Dbfw_common_ipv6_string_2_array((char *)__SGA_AC_XSEC_DATABASE->database_unconnect[i].start_cli_address, (u_char *)&start_cli_address);
				}
				if(strchr((char *)(__SGA_AC_XSEC_DATABASE->database_unconnect[i].end_cli_address),'.') != NULL)
				{
                	end_cli_address[0] = DBFW_HTON32(str2ip(__SGA_AC_XSEC_DATABASE->database_unconnect[i].end_cli_address));
                	end_cli_address[1] = 0;
				}
				else{
					Dbfw_common_ipv6_string_2_array((char *)__SGA_AC_XSEC_DATABASE->database_unconnect[i].end_cli_address, (u_char *)&end_cli_address);
				}
                if((((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip[0]>start_cli_address[0] ||
					(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip[0]==start_cli_address[0] &&
					((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip[1]>=start_cli_address[1])) &&
                   (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip[0]<end_cli_address[0] ||
                   (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip[0]==end_cli_address[0] &&
                   ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip[1]<=end_cli_address[1]))
                  )
                {
                    /* 符合条件 */
                    connect_type    = __SGA_AC_XSEC_DATABASE->database_unconnect[i].cli_api;
                    client_type     = __SGA_AC_XSEC_DATABASE->database_unconnect[i].cli_os;
                    server_type     = __SGA_AC_XSEC_DATABASE->database_unconnect[i].db_os;
                    /* 设置为已识别完成(使用用户配置的协议类型) */
                    /* 只有Oracle数据库需要进行协议识别 */
                    ora_session->unconn_iden_result = UNCONN_IDEN_RESULT_OVER;
                    /* 找到第一个后，不再向后继续查找了 */
                    break;
                }
            }
        }
        /* 根据__SGA_AC_XSEC_DATABASE->is_sox */
        //switch (__SGA_AC_XSEC_DATABASE->is_sox)
        switch (connect_type)
        {
            case DBFW_SESSION_CONNTYPE_UNKNOWN:
            case DBFW_SESSION_CONNTYPE_JDBC308:
				((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version = ORA_TNS_VER_308;
				((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.tns_version = ORA_TNS_VER_308;
                /* 未知，按照默认处理 */
    	        break;
            case DBFW_SESSION_CONNTYPE_JDBC310:
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version = ORA_TNS_VER_310;
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.tns_version = ORA_TNS_VER_310;
                break;
            case DBFW_SESSION_CONNTYPE_JDBC315: /* 12C */
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version = ORA_TNS_VER_315;
                /* 先不设置服务器的TNS版本 */
                break;
            case DBFW_SESSION_CONNTYPE_OCI9I:
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version = ORA_TNS_VER_312;
                /* 服务器也应该是该版本 */
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.tns_version = ORA_TNS_VER_312;
                break;
            case DBFW_SESSION_CONNTYPE_OCI101:  /* 也是312版本 */
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version = ORA_TNS_VER_312;
                /* 服务器也应该是该版本 */
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.tns_version = ORA_TNS_VER_312;
                break;
            case DBFW_SESSION_CONNTYPE_OCI102:  /* 10gR2 */
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version = ORA_TNS_VER_313;
                /* 先不设置服务器的TNS版本 */
                break;
            case DBFW_SESSION_CONNTYPE_OCI110:  /* 11g */
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version = ORA_TNS_VER_314;
                /* 先不设置服务器的TNS版本 */
                break;
            default:
                break;
        }
        /* 根据设置的Oracle版本确定服务器的TNS版本 */
        if(__SGA_AC_XSEC_DATABASE->db_version<10020000)
        {
            /* 10.2以下版本，使用9i的通讯协议 */
            ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.tns_version = ORA_TNS_VER_312;
        }
        else if(__SGA_AC_XSEC_DATABASE->db_version<11000000)
        {
            /* 10.2版本 */
            if(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version < ORA_TNS_VER_313)
            {
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.tns_version = ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version;
            }
            else
            {
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.tns_version = ORA_TNS_VER_313;
            }
        }
        else if(__SGA_AC_XSEC_DATABASE->db_version<12000000)
        {
            /* 11.X版本 */
            if(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version < ORA_TNS_VER_314)
            {
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.tns_version = ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version;
            }
            else
            {
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.tns_version = ORA_TNS_VER_314;
            }
        }
        /* 客户端操作系统信息is_pci字段 */
        //if(__SGA_AC_XSEC_DATABASE->is_sox>=DBFW_SESSION_CONNTYPE_OCI9I)
        if(connect_type >= DBFW_SESSION_CONNTYPE_OCI9I)
        {
            /* 非JDBC，需要根据配置的操作系统确定 */
            //switch (__SGA_AC_XSEC_DATABASE->is_pci)
            switch (client_type)
            {
                case DBFW_SESSION_OS_WIN32:
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_bit = 0x32;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os = OS_WIN;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori = OS_WIN;
                    break;
                case DBFW_SESSION_OS_WIN64:
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_bit = 0x64;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os = OS_LINUX;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori = OS_WIN;
                    break;
                case DBFW_SESSION_OS_LINUX32:
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_bit = 0x32;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os = OS_WIN;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori = OS_LINUX;
                    break;
                case DBFW_SESSION_OS_LINUX64:
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori = OS_LINUX;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os = OS_LINUX;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_bit = 0x64;
                    break;
                case DBFW_SESSION_OS_AIX32:
                case DBFW_SESSION_OS_AIX64:
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os = OS_AIX;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori = OS_AIX;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_bit = 0x64;
                    break;
                case DBFW_SESSION_OS_SLA32:
                case DBFW_SESSION_OS_SLA64:
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os = OS_AIX;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori = OS_AIX;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_bit = 0x64;
                    break;
                case DBFW_SESSION_OS_HPUX:
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os = OS_AIX;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori = OS_AIX;
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_bit = 0x64;
                    break;
                default:
                    break;
            }
        }
        /* 服务器操作系统信息is_glba字段 */
        //switch (__SGA_AC_XSEC_DATABASE->is_glba)
        switch (server_type)
        {
            case DBFW_SESSION_OS_WIN32:
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_ori = OS_WIN;
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_bit = 0x32;
                /* 当客户端为AIX64的时候，相当于Server是AIX64的情况 */
                if(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os==OS_AIX && ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori==OS_AIX)
                {
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_AIX;
                }
                else
                {
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_WIN;
                }
    	        break;
            case DBFW_SESSION_OS_WIN64:
                /* 当客户端为AIX64的时候，相当于Server是AIX64的情况 */
                if(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os==OS_AIX && ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori==OS_AIX)
                {
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_AIX;
                }
                else
                {
                    /* 否则按照Linux64处理 */
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_LINUX;
                }
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_bit = 0x64;
                break;
            case DBFW_SESSION_OS_LINUX32:
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_bit = 0x32;
                /* 当客户端为AIX64的时候，相当于Server是AIX64的情况 */
                if(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os==OS_AIX && ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori==OS_AIX)
                {
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_AIX;
                }
                else
                {
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_WIN;
                }         
                /* 
                    2014-01-10 秦皇岛社保发现使用了Linux32的协议，为“Linuxi386/Linux-2.0.34-8.1.0” 
                    冒险：遇到Linux32，设置协议为WIN32，包括client_os_ori
                */
                //if(__SGA_AC_XSEC_DATABASE->is_pci==DBFW_SESSION_OS_LINUX32)
                if(client_type == DBFW_SESSION_OS_LINUX32)
                {
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_bit = 0x32;
                    if(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os==OS_AIX && ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori==OS_AIX)
                    {
                        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_AIX;
                        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_ori = OS_WIN;
                    }
                    else
                    {
                        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_WIN;
                        ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_ori = OS_WIN;
                    } 
                }            
                break;
            case DBFW_SESSION_OS_LINUX64:
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_ori = OS_LINUX;
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_bit = 0x64;
                /* 当客户端为AIX64的时候，相当于Server是AIX64的情况 */
                if(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os==OS_AIX && ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori==OS_AIX)
                {
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_AIX;
                }
                else
                {
                    ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_LINUX;
                }            
                break;
            case DBFW_SESSION_OS_AIX32:
            case DBFW_SESSION_OS_AIX64:
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_ori = OS_AIX;
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_AIX;
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_bit = 0x64;
                break;
            case DBFW_SESSION_OS_SLA32:
            case DBFW_SESSION_OS_SLA64:
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_AIX;
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_ori = OS_AIX;
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_bit = 0x64;
                break;
            case DBFW_SESSION_OS_HPUX:
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_ori = OS_AIX;
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os = OS_AIX;
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_bit = 0x64;
                break;
            default:
                break;
        }
        /* 2014-06-24 增加通讯协议为JDBC的调整 */
        //switch (__SGA_AC_XSEC_DATABASE->is_sox)
        switch (connect_type)
        {
            case DBFW_SESSION_CONNTYPE_JDBC308:
            case DBFW_SESSION_CONNTYPE_JDBC310:
            case DBFW_SESSION_CONNTYPE_JDBC315: /* 12C */
                /* 是Java通讯协议 */
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os = OS_JAVA_TTC;
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori = OS_JAVA_TTC;
                ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_bit = 0x64;
                break;
            default:
                break;
        }
        /*
            下面根据ora_session的客户端IP来从
        */
        /* DUMP默认配置结果信息 */
        OraNet_DumpSql("tns_version(client) = %04x\n",((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_connect_header.tns_version);
        OraNet_DumpSql("client_os_ori       = %02x\n",((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_ori);
        OraNet_DumpSql("client_os           = %02x\n",((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os);
        OraNet_DumpSql("client_os_bit       = %02x\n",((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_os_bit);
        OraNet_DumpSql("tns_version(server) = %04x\n",((SessBuf_SessionData_Ora *)(ora_session->sessdata))->tns_accept_header.tns_version);
        OraNet_DumpSql("server_os_ori       = %02x\n",((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_ori);
        OraNet_DumpSql("server_os           = %02x\n",((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os);
        OraNet_DumpSql("server_os_bit       = %02x\n",((SessBuf_SessionData_Ora *)(ora_session->sessdata))->server_os_bit);
    }
    else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_DM)
    {
#ifdef ENABLE_DM

#ifdef HAVE_CHERRY   // 20151124 guoxw HA sync
    	if(ora_session->syncd_session)
    	{
    		ora_session->unconn_iden_result = UNCONN_IDEN_RESULT_OVER;
    		ora_session->help_session_state = DBFW_SESSION_STATE_NORMAL;
    		ora_session->help_connect_state = 0x01;
    	}    
#endif		
        /* 达梦数据库:只需要关注字符集信息 */
        /* DUMP默认配置结果信息 */
        OraNet_DumpSql("dm_server_charset   = %02x\n",__SGA_AC_XSEC_DATABASE->is_dpa);
#endif
    }
	/* 刘思成开始添加 */
	/* 无连接默认添加的是Mysql非压缩协议下的登录信息 */
	else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL || __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG)
	{
#ifdef ENABLE_MYSQL

#ifdef HAVE_CHERRY   // 20151124 guoxw HA sync
    	if(ora_session->syncd_session)
    	{
    		ora_session->unconn_iden_result = UNCONN_IDEN_RESULT_OVER;
    	
    		ora_session->help_session_state = DBFW_SESSION_STATE_NORMAL;
    		ora_session->help_connect_state = 0x01;
    	}    
#endif
    
		/* 设置4字节高低位 */
		ora_session->mysql_capability_flag_1_client.client_long_password=0x01;
		ora_session->mysql_capability_flag_1_client.client_found_rows=0x00;
		ora_session->mysql_capability_flag_1_client.client_long_flag=0x01;
		ora_session->mysql_capability_flag_1_client.client_connect_with_db=0x00;
		ora_session->mysql_capability_flag_1_client.client_no_schema=0x00;
		ora_session->mysql_capability_flag_1_client.client_compress=0x00;
		ora_session->mysql_capability_flag_1_client.client_odbc=0x00;
		ora_session->mysql_capability_flag_1_client.client_local_files=0x01;
		ora_session->mysql_capability_flag_1_client.client_ignore_space=0x00;
		ora_session->mysql_capability_flag_1_client.client_protocol_41=0x01;
		ora_session->mysql_capability_flag_1_client.client_interactive=0x01;
		ora_session->mysql_capability_flag_1_client.client_ssl=0x00;
		ora_session->mysql_capability_flag_1_client.client_ignore_sigpipe=0x00;
		ora_session->mysql_capability_flag_1_client.client_transactions=0x01;
		ora_session->mysql_capability_flag_1_client.client_reserved=0x00;
		ora_session->mysql_capability_flag_1_client.client_secure_connection=0x01;
		////////////////////////////////////////////////////////////////////////////////
		ora_session->mysql_capability_flag_1_server.client_long_password=0x01;
		ora_session->mysql_capability_flag_1_server.client_found_rows=0x01;      
		ora_session->mysql_capability_flag_1_server.client_long_flag=0x01;
		ora_session->mysql_capability_flag_1_server.client_connect_with_db=0x01;
		ora_session->mysql_capability_flag_1_server.client_no_schema=0x01;
		ora_session->mysql_capability_flag_1_server.client_compress=0x01;
		ora_session->mysql_capability_flag_1_server.client_odbc=0x01;
		ora_session->mysql_capability_flag_1_server.client_local_files=0x01;
		ora_session->mysql_capability_flag_1_server.client_ignore_space=0x01;
		ora_session->mysql_capability_flag_1_server.client_protocol_41=0x01;
		ora_session->mysql_capability_flag_1_server.client_interactive=0x01;
		ora_session->mysql_capability_flag_1_server.client_ssl=0x00;
		ora_session->mysql_capability_flag_1_server.client_ignore_sigpipe=0x01;
		ora_session->mysql_capability_flag_1_server.client_transactions=0x01;
		ora_session->mysql_capability_flag_1_server.client_reserved=0x01;
		ora_session->mysql_capability_flag_1_server.client_secure_connection=0x01;
        /* 完成登录信息 */
		ora_session->mysql_help_ishandshaked=0x01;
		ora_session->mysql_help_islogined=0x01; 
		ora_session->mysql_help_login_result=0x01;
		ora_session->finish_choose = 0xFF;	/*强制判定是否压缩协议*/
		ora_session->mysql_start_for_unconnect = 1;
		/* 从前台获取字符集：__SGA_AC_XSEC_DATABASE->is_dpa是前台设置的字符集 */
		/* 
		修复mysql内存泄露的问题，原因是在此处申请的 mysql_handshakeresponse41 没有指定mysql_handshake_response_version的版本为
		DBFW_MYSQL_PROTOCOL_HANDSHAKERESPONSE41  造成在close session时 没有正确释放
		*/
		
		/* 释放并重置mysql_handshake_response */
		if(ora_session->mysql_handshake_response!=NULL)
		{
			if(ora_session->mysql_handshake_response_version==DBFW_MYSQL_PROTOCOL_HANDSHAKERESPONSE41)
			{
				Free_MySQL_HandshakeResponse41((DBFW_MySQL_HandshakeResponse41*)ora_session->mysql_handshake_response);
				ZFree(ora_session->mysql_handshake_response);
			}
			else if(ora_session->mysql_handshake_response_version==DBFW_MYSQL_PROTOCOL_HANDSHAKERESPONSE320)
			{
				Free_MySQL_HandshakeResponse320((DBFW_MySQL_HandshakeResponse320*)ora_session->mysql_handshake_response);
				ZFree(ora_session->mysql_handshake_response);
			}
		}	
		DBFW_MySQL_HandshakeResponse41 *mysql_handshakeresponse41 = NULL;
		mysql_handshakeresponse41 = (DBFW_MySQL_HandshakeResponse41*)ZMalloc(sizeof(DBFW_MySQL_HandshakeResponse41));
		Init_MySQL_HandshakeResponse41(mysql_handshakeresponse41);
		ora_session->mysql_handshake_response = (void*)mysql_handshakeresponse41;
		ora_session->mysql_handshake_response_version = DBFW_MYSQL_PROTOCOL_HANDSHAKERESPONSE41;
		((DBFW_MySQL_HandshakeResponse41*)ora_session->mysql_handshake_response)->client_character_set = __SGA_AC_XSEC_DATABASE->is_dpa;
#endif	
	}
	else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_DB2)
	{
#ifdef ENABLE_DB2

#ifdef HAVE_CHERRY   // 20151124 guoxw HA sync
    	if(ora_session->syncd_session)
    	{
    		ora_session->unconn_iden_result = UNCONN_IDEN_RESULT_OVER;
    	
    		ora_session->help_session_state = DBFW_SESSION_STATE_NORMAL;
    		ora_session->help_connect_state = 0x01;
    	}    
#endif
    
		if(__SGA_AC_XSEC_DATABASE->is_dpa == 4)
			ora_session->db2_ccsid_client.ccsidsbc = DB2_CHARSET_PAGECODE_UTF8;
		else if(__SGA_AC_XSEC_DATABASE->is_dpa == 0)
			ora_session->db2_ccsid_client.ccsidsbc = DB2_CHARSET_PAGECODE_GBK;
		else
			ora_session->db2_ccsid_client.ccsidsbc = DB2_CHARSET_PAGECODE_GBK;
#endif
	}
	else if (__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_POSTGREE || __SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_KINGBASE)
	{	
#ifdef ENABLE_PGSQL	

#ifdef HAVE_CHERRY   // 20151124 guoxw HA sync
    	if(ora_session->syncd_session)
    	{
    		ora_session->unconn_iden_result = UNCONN_IDEN_RESULT_OVER;
    	
    		ora_session->help_session_state = DBFW_SESSION_STATE_NORMAL;
    		ora_session->help_connect_state = 0x01;
    	}    
#endif
    
	ora_session->help_last_ack_errorno = 0;
	/**
	 *缺省schemaname public 赋值
	 */

	ora_session->pg_help_proto_majorver = 3;
	ora_session->pg_help_proto_minver = 3; 
#ifdef ENABLE_KINGBASE
	ora_session->kb_protocol_version = KB_PROTOCOL(ora_session->pg_help_proto_majorver,ora_session->pg_help_proto_minver);
#endif 

#endif 

	}
	else if (__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_IFX || __SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_GBASE8T)
	{
#ifdef ENABLE_IIF	

	#ifdef HAVE_CHERRY   // 20151124 guoxw HA sync
    	if(ora_session->syncd_session)
    	{
    		ora_session->unconn_iden_result = UNCONN_IDEN_RESULT_OVER;
    	
    		ora_session->help_session_state = DBFW_SESSION_STATE_NORMAL;
    		ora_session->help_connect_state = 0x01;
    	}    
    #endif
    

	ora_session->help_last_ack_errorno = 0;
	/**
	 *缺省schemaname informix 赋值
	 */

#endif 
	}

	/* 刘思成添加结束 */
}

/*
    判断通讯包的方向
    未知： 3
*/
u_int NPP_GetPcapDirect(Dbfw_EthernetParseResult parseresult,OraTNS_TCPInfo *tcp_info)
{
    u_int direction = 0;
	u_int64 ip_srcaddr[2];
	u_int64 ip_destaddr[2];
	
	if(parseresult.ethernet.type == 0x86dd)
	{
		z_memcpy(ip_srcaddr,parseresult.ipv6_header.ip_srcaddr,sizeof(ip_srcaddr), __FILE__, __LINE__, Smem_LogError_Format);
		z_memcpy(ip_destaddr,parseresult.ipv6_header.ip_destaddr,sizeof(ip_srcaddr), __FILE__, __LINE__, Smem_LogError_Format);
	}else{
		ip_srcaddr[0] = parseresult.ipv4_header.ip_srcaddr;
		ip_srcaddr[1] = 0;
		ip_destaddr[0] = parseresult.ipv4_header.ip_destaddr;
		ip_destaddr[1] = 0;
	}
    if(ip_srcaddr[0]==tcp_info->client_ip[0] && ip_srcaddr[1]==tcp_info->client_ip[1] &&
        parseresult.tcp_header.source_port==(u_short)tcp_info->client_port
        )
    {
        /* 客户端IP和端口匹配上了 */
        if(ip_destaddr[0]==tcp_info->oracle_server_ip[0] && ip_destaddr[1]==tcp_info->oracle_server_ip[1] &&
            parseresult.tcp_header.dest_port==(u_short)tcp_info->oracle_server_port
            )
        {
            /* 服务器的IP和端口也匹配上了 */                        
            direction = USER2ORA;
        }
        else
        {
            /* 匹配错误 */
            direction = 3;
        }
    }
    else if(ip_srcaddr[0]==tcp_info->oracle_server_ip[0] && ip_srcaddr[1]==tcp_info->oracle_server_ip[1] &&
        parseresult.tcp_header.source_port==(u_short)tcp_info->oracle_server_port
        )
    {
        /* 服务器的IP和端口匹配上了 */
        if(ip_destaddr[0]==tcp_info->client_ip[0] && ip_destaddr[1]==tcp_info->client_ip[1] && 
            parseresult.tcp_header.dest_port==(u_short)tcp_info->client_port
            )
        {
            /* 客户端IP和端口匹配上了 */
            direction = ORA2USER;
        }
        else
        {
            /* 匹配错误 */
            direction = 3;
        }
    }
    else
    {
        /* 匹配错误 */
        direction = 3;
    }
    return direction;
}








/* 这个主入口程序是在Linux下的真正的NPP主入口函数 */
int main(int argc, char *argv[])
{


    Npp_ProcessParam processParam;    
    u_int i = 0;
    u_int j = 0;
    u_int k = 0;
    int ret = 0;
    int paramSize = 0;
    u_short capbufid = 0;
    
    u_short init_session = 0;   /* 20151111 guoxw */
 
    char tmp_param[64];
    
    /* guoxw 20160615 nfw中创建npp时屏蔽了信号，在这里解除屏蔽，这些这些信号unblock */
    Npp_SetSignalMask();
    pid_t pid;
    int fd_oom = 0;
    const void* oom_adj = "8";
    const void* oom_score_adj = "8";
    ssize_t w_len = 0;
    char oom_path[512] = {0};

    pid = getpid();
    bzero(oom_path, 512);
    sprintf(oom_path, "/proc/%d/oom_adj",pid);
    if( access(oom_path, W_OK) == -1 )
    {
        printf("cannot find oom_path = %s \n", oom_path);
        exit(0);
    }else
    {
        fd_oom = open(oom_path, O_TRUNC|O_WRONLY);
        if ( fd_oom == -1 )
        {
            printf("cannot open file = %s \n", oom_path);
            exit(0);
        }else
        {
            w_len = write(fd_oom, oom_adj, 1);
            if (w_len == -1)
            {
                printf("write failed ret = %d\n", ret);
                exit(0);
            } 
        }
		if(fd_oom > 0)
			close(fd_oom);
    }
    
    bzero(oom_path, 512);
    sprintf(oom_path, "/proc/%d/oom_score_adj",pid);
    if( access(oom_path, W_OK) == -1 )
    {
        printf("cannot find oom_path = %s \n", oom_path);
        exit(0);
    }else
    {
        fd_oom = open(oom_path, O_TRUNC|O_WRONLY);
        if ( fd_oom == -1 )
        {
            printf("cannot open file = %s \n", oom_path);
            exit(0);
        }else
        {
            w_len = write(fd_oom, oom_adj, 1);
            if (w_len == -1)
            {
                printf("write failed ret = %d\n", ret);
                exit(0);
            } 
        }
		if(fd_oom > 0)
			close(fd_oom);
    }

    if(argc<11)
    {
        print_version("npp");
        usage(argv[i]);
        exit(1);
    }
    i++;
    /* get param */
    /* process_type */
    processParam.process_type = (u_int)atoi(argv[i++]); 
    if(processParam.process_type != NPP_PROCESS_TYPE_NPC)
    {
#ifdef HAVE_CHERRY		
        if(processParam.process_type!=NPP_PROCESS_TYPE_TRANSPARENT 
				&& processParam.process_type!=NPP_PROCESS_TYPE_PROXY)
        {
            usage(argv[0]);
            exit(1);
        }
#else
        usage(argv[0]);
        exit(1);
#endif
    }
    /* shmid */
    processParam.shmid = (u_int)atoi(argv[i++]); 
    /* dbclient_ip */
    paramSize = strlen(argv[i]);
    if(paramSize>=40)
    {
        printf("size of dbclient_ip must less than 40 byte\n");
        exit(1);
    }
    z_strcpy((char *)&processParam.dbclient_ipstr,argv[i++], __FILE__, __LINE__, Smem_LogError_Format);
    /* dbclient_port */
    processParam.dbclient_port = (u_int)atoi(argv[i++]); 
    /* dbclient_mac */
    paramSize = strlen(argv[i]);
    if(paramSize>=30)
    {
        printf("size of dbclient_mac must less than 30 byte\n");
        exit(1);
    }
    memset(tmp_param,0x00,sizeof(tmp_param));
    memset(processParam.dbclient_mac,0x00,sizeof(processParam.dbclient_mac));
    z_strcpy((char *)tmp_param,argv[i++], __FILE__, __LINE__, Smem_LogError_Format);
    j = 0;
    for(k=0;k<paramSize;k++)
    {        
        if(tmp_param[k]!=':' && tmp_param[k]!='-')
        {
            processParam.dbclient_mac[j] = tmp_param[k];
            j++;
        }
    }

    /* dbserver_ip */
    paramSize = strlen(argv[i]);
    if(paramSize>=40)
    {
        printf("size of dbserver_ip must less than 40 byte\n");
        exit(1);
    }
    z_strcpy((char *)&processParam.dbserver_ipstr,argv[i++], __FILE__, __LINE__, Smem_LogError_Format);
    /* dbserver_port */
    processParam.dbserver_port = (u_int)atoi(argv[i++]); 
	if(strchr((char *)processParam.dbserver_ipstr, '.') != NULL)
	{
    	__DB_ADDRESS = DBFW_HTON32(str2ip(processParam.dbserver_ipstr));
	}else{
		u_int64 dbserver_ip_int[2];
#ifdef HAVE_CHERRY
		__SOCK_TYPE = AF_INET6;
#endif
		Dbfw_common_ipv6_string_2_array((char *)processParam.dbserver_ipstr, (u_char *)dbserver_ip_int);
		__DB_ADDRESS = Dbfw_hash_xor_key16(dbserver_ip_int);
	}
    __DB_PORT    = processParam.dbserver_port;
    OraNet_DumpSql("__DB_ADDRESS = %u  __DB_PORT=%u\n",__DB_ADDRESS,__DB_PORT);
    /* 根据客户端port取模绑定CPU */
    /* dbserver_mac */
    paramSize = strlen(argv[i]);
    if(paramSize>=30)
    {
        printf("size of dbserver_mac must less than 30 byte\n");
        exit(1);
    }
    memset(tmp_param,0x00,sizeof(tmp_param));
    memset(processParam.dbserver_mac,0x00,sizeof(processParam.dbserver_mac));
    z_strcpy((char *)tmp_param,argv[i++], __FILE__, __LINE__, Smem_LogError_Format);
    j = 0;
    for(k=0;k<paramSize;k++)
    {        
        if(tmp_param[k]!=':' && tmp_param[k]!='-')
        {
            processParam.dbserver_mac[j] = tmp_param[k];
            j++;
        }
    }

    /* handle or sessionid for NPC */
    processParam.proxy_socket = 0;
    processParam.proxy_socket = (u_int)atoi(argv[i++]); 
    processParam.init_session = 0;
    capbufid = 1;
    if(processParam.process_type==NPP_PROCESS_TYPE_NPC)
    {
        if(argc<11)
        {
            usage(argv[0]);
            exit(1);
        }
#ifdef HAVE_CHERRY
    	processParam.init_session = (u_short)atoi(argv[i++]);    /* 20151216 guoxw 在旁路模式下也需要初始化*/
#else
        capbufid = (u_short)atoi(argv[i++]);
#endif
    }
#ifdef HAVE_CHERRY
    else if(processParam.process_type==NPP_PROCESS_TYPE_TRANSPARENT)
    {
        OraNet_DumpSql("type = NPP_PROCESS_TYPE_TRANSPARENT\n");
        if(argc<11)
        {
            usage(argv[0]);
            exit(1);
        }
        processParam.init_session = (u_short)atoi(argv[i++]);
    }
    else if(processParam.process_type==NPP_PROCESS_TYPE_PROXY)
    {
        OraNet_DumpSql("type = NPP_PROCESS_TYPE_PROXY\n");
        if(argc<14)
        {
            usage(argv[0]);
            exit(1);
        }
        capbufid = (u_short)atoi(argv[i++]);
		processParam.shmid_proxy   = (u_int)atoi(argv[i++]);
		processParam.client_socket = (u_int)atoi(argv[i++]);
		processParam.server_socket = (u_int)atoi(argv[i++]);
		processParam.init_session = (u_short)atoi(argv[i++]);
    }
#endif
    /* print all param for trace */
    OraNet_DumpSql("process_type  = %d\n",processParam.process_type);
    OraNet_DumpSql("shmid         = %d\n",processParam.shmid);
    OraNet_DumpSql("dbclient_ip   = %s\n",processParam.dbclient_ipstr);
    OraNet_DumpSql("dbclient_port = %d\n",processParam.dbclient_port);
    OraNet_DumpSql("dbclient_mac  = %s\n",processParam.dbclient_mac);
    OraNet_DumpSql("dbserver_ip   = %s\n",processParam.dbserver_ipstr);
    OraNet_DumpSql("dbserver_port = %d\n",processParam.dbserver_port);
    OraNet_DumpSql("dbserver_mac  = %s\n",processParam.dbserver_mac);
    Smem_ChkPerformanceSwitchOn_NotThreadSafe();
    /* 初始化内存池 */
    __SLOT_OF_CHUNKS = (Dbfw_Mem_SlotOfChunk*)malloc(sizeof(Dbfw_Mem_SlotOfChunk));
    __MEM_STACKWALK  = (Dbfw_Mempool_StackWalk *)malloc(sizeof(Dbfw_Mempool_StackWalk));
    i = Dbfw_Mempool_InitSlots(__SLOT_OF_CHUNKS);
        
    /* init sga and sessbuf , tlog buf */
//	shmat(processParam.shmid, NULL, SHM_RDONLY); //added by xxd to protect shm,20160405
//    __DBFW_SGA_ADDR = Dbfw_AttachShm(processParam.shmid);
//	shmat(processParam.shmid, NULL, SHM_RDONLY); //added by xxd to protect shm,20160405
	ret = Dbfw_Fixarray_AttachBuffByMyShmId(processParam.shmid,&__SGA_FIXARRAY);
	if(ret < 0)
	{
		printf("attach sga error:%d, exit.",ret);
        exit(1);
	}
	
	if(SmemInitGranulesParams() < 0)
    {
		Dbfw_Fixarray_DetachBuff(&__SGA_FIXARRAY);
			
        printf("initialize config file for smem errror, exit.");
        exit(1);
    }
#if defined ENABLE_DBSCLOUD
#ifdef ENABLE_CLUSTER
	global_hostid = Dbfw_Fixarray_GetHostid(&__SGA_FIXARRAY);
	global_regionid = Dbfw_Fixarray_GetRegionid(&__SGA_FIXARRAY);	
    if (0 != dbsc_extshm_init(global_hostid))
    {
        OraNet_DumpSql("dbsc_sga_attach_all failed.\n");
        exit(1);
	}
#else
    if (0 != dbsc_extshm_init(0))
	{
        OraNet_DumpSql("dbsc_sga_attach_all failed.\n");
        exit(1);
	}
#endif
#endif
	
	__MEM_POOL = Dbfw_Mempool_Sga_Init(&__SGA_FIXARRAY,__SLOT_OF_CHUNKS);
	i = Dbfw_Mempool_InitOrResetStackWalk(__MEM_STACKWALK);
    __SGA_SESSBUF = (Dbfw_Sga_SessBuff*)ZMalloc(sizeof(Dbfw_Sga_SessBuff));         /*  */
    __SGA_TLOGBUF = (Dbfw_Sga_TlogBuff*)ZMalloc(sizeof(Dbfw_Sga_TlogBuff));
    __NPP_ALL_CONFIG    = (Npp_All_Config*)ZMalloc(sizeof(Npp_All_Config));
    __VPATCH_INPUT_INFO = (VPatch_InputInfo*)ZMalloc(sizeof(VPatch_InputInfo));
    memset(__VPATCH_INPUT_INFO,0x00,sizeof(VPatch_InputInfo));
    memset(&__SGA_RTBUF, 0x00, sizeof(Dbfw_Sga_RTBuff_Buff));
    /* 初始化NPP的配置参数和DB、Risk信息 */
    ret = Npp_InitAllConfigItem(&__SGA_FIXARRAY,__NPP_ALL_CONFIG);

    // 将创建链接移动到该位置 使用从共享内存中获取的参数 
#ifdef ENABLE_TELNET 
    g_telnet_mysql = mysql_init(NULL);
    if (!mysql_real_connect(g_telnet_mysql, (char*)__NPP_ALL_CONFIG->s_auditdb_ip, (char*)__NPP_ALL_CONFIG->s_auditdb_user, (char*)__NPP_ALL_CONFIG->s_auditdb_pwd, (char*)__NPP_ALL_CONFIG->s_auditdb_schema, __NPP_ALL_CONFIG->s_auditdb_port, NULL, 0))
    {
		Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"connect to DC fail. errno=%d, errmsg:%s", mysql_errno(g_telnet_mysql),mysql_error(g_telnet_mysql));
        return 1000;
    }
#endif    

    ret = Dbfw_Sga_Sess_AttachBuff(&__SGA_FIXARRAY, __SGA_SESSBUF);
    ret = Dbfw_Sga_Tlog_AttachBuff(&__SGA_FIXARRAY,__SGA_TLOGBUF);
    ret = Dbfw_Sga_ACBuff_AttachBuff(&__SGA_FIXARRAY,&__SGA_ACBUF);
    ret = Dbfw_Sga_SQLT_AttachBuff(&__SGA_FIXARRAY, &__SGA_SQLTBUF);
	ret = Dbfw_Sga_RTBuff_AttachBuff(&__SGA_FIXARRAY, &__SGA_RTBUF);
	ret = Dbfw_Sga_CapBuff_AttachBuff(&__SGA_FIXARRAY, &__SGA_CAPBUF);
    /* 初始化__FILTER_RESULT变量 */
    /* 注册crash处理例程 */
    Dbfw_RegisterProcessCrashFunctionWithCoredump(handle_trap_with_coredump);
	Dbfw_NppSetMemLimit();
	Mempool_set_memlimit_function(handle_trap_with_coredump);

    __PROCESS_ID = (u_int)getpid();
    /* 向SGA注册本进程 */
    Dbfw_Fixarray_SetProcess(&__SGA_FIXARRAY,__PROCESS_ID,DBFW_PTYPE_NPP);
    /* 设置进程参数到fixArea */
    for(i=1;i<argc;i++)
    {
       ret = Dbfw_Fixarray_SetValueAndValuelenForProcess(&__SGA_FIXARRAY,__PROCESS_ID,(i-1),(u_char*)argv[i],strlen((char*)argv[i]),DBFW_PTYPE_NPP);
       if(ret==65535)
       {
            OraNet_DumpSql("Dbfw_Fixarray_SetValueAndValuelenForProcess error(%d) for Npp's param[%d]=%s\n",ret,i,(char*)argv[i]);
       }
    }

    /* 初始化NPP的配置参数和DB、Risk信息 */
    ret = Npp_InitDbfwAndDbInfo(__NPP_ALL_CONFIG);
#ifdef ENABLE_TELNET
	__SGA_AC_XSEC_DATABASE = (AC_XSec_Databse*)ZMalloc(sizeof(AC_XSec_Databse));
	__SGA_AC_XSEC_DATABASE->dialect = DBFW_DBTYPE_TELNET;
	__NPP_ALL_CONFIG->dbfw_fordb_state = 1;
	__DB_ISFIND = 1;
#endif 


    /* 获得DBFW系统的实例名 */
    memset(&__DBFW_INSTANCE_NAME,0x00,sizeof(__DBFW_INSTANCE_NAME));
    z_strcpy((char*)__DBFW_INSTANCE_NAME,(char*)__NPP_ALL_CONFIG->s_instance_name, __FILE__, __LINE__, Smem_LogError_Format);
    
    /* 初始化所有Npp的log文件 */
    Npp_InitLogfile((char*)__NPP_ALL_CONFIG->s_log_home);
	
	Smem_InitLogfile((char*)__NPP_ALL_CONFIG->s_log_home);
    /* 注册非预期退出处理程序 */
    Dbfw_RegisterProcessExitFunction(handler_unexpect_exit);

#ifdef MEM_OUT_OF_BOUND_CHECK
	char npp_out_of_bound_name[256];
	time_t  ts;
	char datetime_str[15];
	FILE *  fp_outofbound = NULL;
	int len=0;
	memset(npp_out_of_bound_name,0,sizeof(npp_out_of_bound_name));
	z_strcpy(npp_out_of_bound_name,(char*)__NPP_ALL_CONFIG->s_log_home, __FILE__, __LINE__, Smem_LogError_Format);
	strcat(npp_out_of_bound_name,"/cdump/memoob_"); //memory out of bound
	strcat(npp_out_of_bound_name,(char*)__DBFW_INSTANCE_NAME);
	strcat(npp_out_of_bound_name,(char*)"_npp_");
	ts = time(NULL);
	Time2Str(ts,datetime_str);
	strcat(npp_out_of_bound_name,datetime_str);
	len = strlen(npp_out_of_bound_name);
	sprintf(npp_out_of_bound_name+len,"_%s_%d",processParam.dbclient_ipstr,processParam.dbclient_port);
	len = strlen(npp_out_of_bound_name);
	sprintf(npp_out_of_bound_name+len,"_%d.log",__PROCESS_ID);
	if((fp_outofbound = fopen(npp_out_of_bound_name, "w")) == NULL)
	{
        Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"open log file error %s,errno:%d",npp_out_of_bound_name,errno);
	}
	else
	{
        dup2(fileno(fp_outofbound),1);
        dup2(fileno(fp_outofbound),2);
	}
#endif
	/*  alter by liyanjun,2020-03-17, 增加开关，应对tcpreplay打包loop的情况， 处理重传包 */
    if(access("/dev/shm/npp_tcpreplay",F_OK) == 0)
    {
        __NPP_TCPREPLAY_SWITCH = true;
    }
    /* 2014-01-27 添加dbtype处理 */
    if(!db_type)
    {
        db_type = (u_char*)malloc(12);
        memset(db_type,0x00,12);
        switch(__SGA_AC_XSEC_DATABASE->dialect)
        {
        case DBFW_DBTYPE_ORACLE:
            z_strcpy((char*)db_type,(char*)"oracle", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        case DBFW_DBTYPE_MSSQL:
		case DBFW_DBTYPE_SYBASE:
            z_strcpy((char*)db_type,(char*)"mssql", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        case DBFW_DBTYPE_DB2: /* DB2 */
            z_strcpy((char*)db_type,(char*)"db2", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        case DBFW_DBTYPE_TERADATA: /* TeraData */
            z_strcpy((char*)db_type,(char*)"teradata", __FILE__, __LINE__, Smem_LogError_Format);
            break;
		case DBFW_DBTYPE_POSTGREE: /*postgres*/
			z_strcpy((char*)db_type,(char*)"pstgre", __FILE__, __LINE__, Smem_LogError_Format);
			break;
        case DBFW_DBTYPE_MYSQL:
        case DBFW_DBTYPE_SHENTONG:   /* gbase */
            z_strcpy((char*)db_type,(char*)"mysql", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        case DBFW_DBTYPE_DM:
            z_strcpy((char*)db_type,(char*)"dameng", __FILE__, __LINE__, Smem_LogError_Format);
            break;
		case DBFW_DBTYPE_KINGBASE:
			z_strcpy((char*)db_type,(char*)"kbase", __FILE__, __LINE__, Smem_LogError_Format);
			break;
        case DBFW_DBTYPE_OSCAR: /*DBFW_DBTYPE_OSCAR*/
            z_strcpy((char*)db_type,(char*)"oscar", __FILE__, __LINE__, Smem_LogError_Format);
            break;
		case DBFW_DBTYPE_IFX: /*informix*/
		case DBFW_DBTYPE_GBASE8T:
			z_strcpy((char*)db_type,(char*)"ifx", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_CACHEDB: /*cachedb*/
			z_strcpy((char*)db_type,(char*)"cachdb", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_HBASE:/*hbase*/
		    z_strcpy((char*)db_type,(char*)"hbase", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_MONGODB:/*mongodb*/
			z_strcpy((char*)db_type, (char*)"mongodb", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_HIVE:/*hive*/
			z_strcpy((char*)db_type, (char*)"hive", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_REDIS:/*redis*/
			z_strcpy((char*)db_type, (char*)"redis", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_TELNET:/*telnet*/
			z_strcpy((char*)db_type, (char*)"telnet", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_IMPALA:/*impala*/
			z_strcpy((char*)db_type, (char*)"impala", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_HRPC:/*hdfs*/
			z_strcpy((char*)db_type, (char*)"hrpc", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_SENTRY:/*sentry*/
			z_strcpy((char*)db_type, (char*)"sentry", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_HANA:/*hana*/
			z_strcpy((char*)db_type, (char*)"hana", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_ES:/*elasticsearch*/
			z_strcpy((char*)db_type, (char*)"es", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_WEBHTTP:/*webhttp*/
			z_strcpy((char*)db_type, (char*)"webhttp", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_SYBASEIQ:   /*sybaseiq database*/
            z_strcpy((char*)db_type, (char*)"iq", __FILE__, __LINE__, Smem_LogError_Format);
			break;
        case DBFW_DBTYPE_GAUSSDBT:   /*sybaseiq database*/
            z_strcpy((char*)db_type, (char*)"gausst", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        case DBFW_DBTYPE_ZOOKEEPER:   /*sybaseiq database*/
            z_strcpy((char*)db_type, (char*)"zk", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        default:
            break;
        }
    }
    __NPP_ALL_CONFIG->start_for_transparent = 0;    /* 初始化为0 */
        /* DA或DA半透明模式 */
    if(processParam.process_type==NPP_PROCESS_TYPE_NPC)
    {
        __NPP_PROCESS_TYPE = NPP_PROCESS_TYPE_NPC;
        __NPP_ALL_CONFIG->capbuf_id = capbufid;
        __NPP_ALL_CONFIG->sessionid_fornpc = (u_short)(processParam.proxy_socket);
        handle_npc(processParam);
    }
#ifdef HAVE_CHERRY
    else if(processParam.process_type==NPP_PROCESS_TYPE_TRANSPARENT)
    {
        __NPP_PROCESS_TYPE = NPP_PROCESS_TYPE_NPC;  /* 设置为NPC类型 */
        __NPP_ALL_CONFIG->capbuf_id = capbufid;
        __NPP_ALL_CONFIG->sessionid_fornpc = (u_short)(processParam.proxy_socket);
        __NPP_ALL_CONFIG->start_for_transparent = 1;
        handle_npc(processParam);
    }
    else if(processParam.process_type==NPP_PROCESS_TYPE_PROXY)
    {
        __NPP_PROCESS_TYPE = NPP_PROCESS_TYPE_PROXY;  /* 设置为NPC类型 */
        __NPP_ALL_CONFIG->capbuf_id = capbufid;
        __NPP_ALL_CONFIG->sessionid_fornpc = (u_short)(processParam.proxy_socket);
        handle_threeway_proxy(processParam);
    }
#endif

    /* 向SGA撤销本进程 */
    Dbfw_Fixarray_DeleteProcess(&__SGA_FIXARRAY,__PROCESS_ID,DBFW_PTYPE_NPP);
    /* 将NPP进程个数减一 */
    Dbfw_Sga_SQLT_DetachBuff(& __SGA_SQLTBUF);
    Dbfw_Sga_Tlog_DetachBuff( __SGA_TLOGBUF);
    Dbfw_Sga_Sess_DetachBuff( __SGA_SESSBUF);
	Dbfw_Sga_CapBuff_DetachBuff( &__SGA_CAPBUF);
    /* 关闭所有的log文件 */
    if(__NPP_ALL_CONFIG)
        ZFree(__NPP_ALL_CONFIG);
    if(__SGA_TLOGBUF)
        ZFree(__SGA_TLOGBUF);
    if(__SGA_SESSBUF)
        ZFree(__SGA_SESSBUF);

    if(__VPATCH_INPUT_INFO)
    {
        if(__VPATCH_INPUT_INFO->statement_len>0)
            ZFree(__VPATCH_INPUT_INFO->statement);
        ZFree(__VPATCH_INPUT_INFO);
    }
#ifdef ENABLE_TELNET
		ZFree(__SGA_AC_XSEC_DATABASE);
#endif
    /* 检查内存是否出现泄漏，并将泄漏结果输出到cdump下 */
#ifdef DUMP_MEMORY_LEAK
    Dbfw_CheckAndDumpMempoolLeak_WithClient((char*)db_type,(char*)processParam.dbclient_ipstr,processParam.dbclient_port);
#endif
	if(db_type)
	{
		free(db_type);
		db_type = NULL;
	}
	Dbfw_Sga_RTBuff_DetachBuff(&__SGA_RTBUF);
	Dbfw_Fixarray_DetachBuff(&__SGA_FIXARRAY);
    /* 关闭iconv句柄 */
#ifdef MEM_OUT_OF_BOUND_CHECK
	if(fp_outofbound != NULL)
	{
		fclose(fp_outofbound);
		fp_outofbound = NULL;
	}
#endif

#ifdef ENABLE_HBASE
    hbase_Shutdown_Protobuf();
#endif
#ifdef ENABLE_TELNET 
        if (g_telnet_mysql)
        {
            mysql_close(g_telnet_mysql);
            g_telnet_mysql = NULL;
        }
#endif

    return(0);

}




/*处理代理三通数据传输的问题*/
void handle_threeway_proxy(Npp_ProcessParam p_processParam)
{
#ifdef HAVE_CHERRY
 handle_connections(p_processParam.client_socket,p_processParam.server_socket,NULL, 1, (char *)p_processParam.dbclient_mac, (char *)p_processParam.dbserver_mac,(char *)p_processParam.dbserver_ipstr, p_processParam.init_session);
handle_threeway_proxy_quit:

 OraNet_PrintTrace("handle_threeway_proxy_quit\n");
#endif
}



/*
	初始化Handle_npc函数使用的变量
	输入：所有的指针对象必须已经完成了ZMalloc,函数内部如果发现为NULL，会自动进行ZMalloc
	返回值：
		1 - 成功
		-1 - 初始化重要变量失败，需要退出
*/
int Init_HandleNpc_Variable(Npp_Runtime_Common	*rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry, Npp_ProcessParam p_processParam)
{
//	u_char* capbuf_addr = NULL;	/* capbuf区的地址 */
	char	errbuf[256];		/* API调用返回的错误信息 */
	int		ret = 0;
	if(rt_com==NULL)
	{
	    return -999;
	}
	if(rt_npc==NULL)
	{
	    return -999;
	}
	if(rt_cherry==NULL)
	{
	    return -999;
	}
	/* 1.1 初始化tcp_info */
	rt_com->tcp_info = (OraTNS_TCPInfo*)ZMalloc(sizeof(OraTNS_TCPInfo));
	if(strchr((char *)p_processParam.dbclient_ipstr, '.') != NULL)
	{
		rt_com->tcp_info->client_ip[0] = DBFW_HTON32(str2ip(p_processParam.dbclient_ipstr));		
	}else{
		Dbfw_common_ipv6_string_2_array((char *)p_processParam.dbclient_ipstr, (u_char *)&rt_com->tcp_info->client_ip);
	}
	z_strcpy((char *)rt_com->tcp_info->client_ip_str,(char *)p_processParam.dbclient_ipstr, __FILE__, __LINE__, Smem_LogError_Format);
	z_strcpy((char *)rt_com->tcp_info->client_mac_str , (char *)p_processParam.dbclient_mac, __FILE__, __LINE__, Smem_LogError_Format);
	rt_com->tcp_info->client_port = (u_int64)p_processParam.dbclient_port;
	if(strchr((char *)p_processParam.dbserver_ipstr, '.') != NULL)
	{
		rt_com->tcp_info->oracle_server_ip[0] = DBFW_HTON32(str2ip(p_processParam.dbserver_ipstr));
//		rt_com->tcp_info->oracle_server_ip_key= rt_com->tcp_info->oracle_server_ip[0];
	}else{
		Dbfw_common_ipv6_string_2_array((char *)p_processParam.dbserver_ipstr, (u_char *)&rt_com->tcp_info->oracle_server_ip);
//		rt_com->tcp_info->oracle_server_ip_key = Dbfw_hash_xor_key16(p_processParam.dbserver_ipstr);
	}
	z_strcpy((char *)rt_com->tcp_info->oracle_server_ip_str , (char *)p_processParam.dbserver_ipstr, __FILE__, __LINE__, Smem_LogError_Format);
	z_strcpy((char *)rt_com->tcp_info->oracle_server_mac_str,(char *)p_processParam.dbserver_mac, __FILE__, __LINE__, Smem_LogError_Format);
	rt_com->tcp_info->oracle_server_port = (u_int64)p_processParam.dbserver_port;
	rt_com->tcp_info->tcp_secquence = 0;
	rt_com->tcp_info->tcp_ack = 0;
	OraNet_DumpSql("step[1.1] : init tcp_info ok\n");
	/* 初始化tcp_info完成 */

	/* 1.2 初始化__ORA_SESSION */

	Init_Session_Global(rt_com->tcp_info,p_processParam.init_session,SOURCECODE,__LINE__);
	OraNet_DumpSql("step[1.2] : init session ok\n");
	/* 初始化__ORA_SESSION结束 */
	
	/* 1.3 初始化TIS相关变量 */
	rt_npc->cap_header	= (Tis_Index*)ZMalloc(sizeof(Tis_Index));
	rt_npc->pkg_hdr		= NULL;
	rt_npc->tis			= NULL;
	rt_npc->tis_slot	= NULL;

	OraNet_DumpSql("step[1.3] : init TIS ok\n");
	/* 初始化TIS相关变量结束 */

	/* 1.4 初始化与SQL改写包处理有关的默认数据 */
	memset(&rt_com->rewrite_packet,0x00,sizeof(rt_com->rewrite_packet));
	OraNet_DumpSql("step[1.4] : init rt_com->rewrite_packet ok\n");
	/* 初始化与SQL改写包处理有关的逻辑 结束 */

    /* 1.5 初始化rt_npc->ethernetframe等数据，避免由于Tis_Get/Tis_Slot_Invalid失败引起的goto ，然后rt_npc->parseresult等变量没有初始化造成core */
    memset(&rt_npc->ethernetframe,0x00,sizeof(Dbfw_EthernetFrame));
    memset(&rt_npc->parseresult,0x00,sizeof(Dbfw_EthernetParseResult));
    memset(&rt_npc->tcp_secandack,0x00,sizeof(rt_npc->tcp_secandack));
	OraNet_DumpSql("step[1.5] : init rt_npc->ethernetframe... ok\n");
	/* 初始化rt_npc->ethernetframe等数据结束 */

	/* 1.6 设置包冗余过滤处理的数组下标初始值，0XFF表示没有完成冗余过滤处理 */
	rt_npc->full_dir_mac_idx = 0xFF;
	OraNet_DumpSql("step[1.6] : init rt_npc->full_dir_mac_idx=0xFF ok\n");

	/* 1.7 初始化包乱序缓冲区 */
	/* 2014-05-12 添加包乱序检查相关逻辑,必须在第一次进入goto handle_npc_quit_real前执行 */
	/* 2016-04-12 这里删除了已经不再使用的HAVE_TCP_RECORDER算法相关的代码 */
#ifdef NEW_TCP_REORDER

    if(rt_npc->new_tcpreorder_buffer.out_of_order_buff==NULL)
    {
    	rt_npc->new_tcpreorder_buffer.out_of_order_buff = (Dbfw_OutOfOrderBuffer*)ZMalloc(sizeof(Dbfw_OutOfOrderBuffer));
    }
	OraNet_DumpSql("step[1.7] : init rt_npc->new_tcpreorder_buffer ok\n");
#endif

	/* 1.8 初始化CapBuf_LoopData结构体:loop_data */
	/**
	* SGA 内存调整,CAPBUF区起始地址，从以前102向前移动17个颗粒，调整为85
	* 代红伟 2014/11/27
	*/
	rt_npc->loop_data = (CapBuf_LoopData *)ZMalloc(sizeof(CapBuf_LoopData));
  
//	memset(errbuf,0,sizeof(errbuf));
//	rt_npc->tis = Tis_Get(capbuf_addr,errbuf);
//	if(rt_npc->tis == NULL)
//	{
		/* 获取rt_npc->tis区指针失败 */
//		Npp_LogError((u_char*)errbuf,-1,0,__FILE__, __LINE__, __FUNCTION__);
		/* 此处不能直接return，这样有些申请的内存不会被释放，且session的槽位也不会释放 */
		//goto handle_npc_quit_real;
//		return -1;
//	}
	
//	__SGA_CAPBUF = (void *)rt_npc->tis;
	rt_npc->tis = __SGA_CAPBUF.tis;
	
	ret = Tis_Slot_Invalid(rt_npc->tis,(u_int)__NPP_ALL_CONFIG->sessionid_fornpc);
	if(ret < 0)
	{
		/* 检查rt_npc->tis区对应的会话槽结果为失败 */
		sprintf(errbuf,"Tis_Slot_Invalid failed. session id:%d return:%d clientip:%s client_port:%llu",__NPP_ALL_CONFIG->sessionid_fornpc,ret,rt_com->tcp_info->client_ip_str,rt_com->tcp_info->client_port);
		Npp_LogError((u_char*)errbuf,-1,0,__FILE__, __LINE__, __FUNCTION__);
		/* 此处不能直接return，这样有些申请的内存不会被释放，且session的槽位也不会释放 */
		//goto handle_npc_quit_real;
		return -1;
	}
	/* 获取rt_npc->tis槽指针 */
	//rt_npc->tis_slot = (Tis_Slot*)Tis_Slot_Addr(rt_npc->tis,(u_int)__NPP_ALL_CONFIG->sessionid_fornpc);
	//printf("npp Info: Get rt_npc->tis Success  gap:%d\n",rt_npc->tis_slot->gap);

	rt_npc->loop_data->capbuf_addr = (u_char *)__SGA_CAPBUF.tis;
	rt_npc->loop_data->session_id = __NPP_ALL_CONFIG->sessionid_fornpc;

	OraNet_DumpSql("step[1.8] : init rt_npc->loop_data ok\n");

	/* 
		1.9 初始化分配rt_npc->ethernetframe的frame_data数据缓冲区 
		必须在这里预先分配，因为后面会使用到
	*/
    rt_npc->ethernetframe.max_frame_size = MAX_FRAME_SIZE_FORNPC;
    rt_npc->ethernetframe.frame_data = (u_char*)ZMalloc(rt_npc->ethernetframe.max_frame_size);
	OraNet_DumpSql("step[1.9] : init rt_npc->ethernetframe.frame_data ok, max_frame_size=%d(byte)\n",rt_npc->ethernetframe.max_frame_size);

	/* 
		1.10 设置用于进行stmt个数检查的初始时间戳 
		该时间戳用于进行stmt个数的检查，检查逻辑为：
		每间隔10分钟，检查一次stmp_table_hash和newstmt_table中的stmt数量
		如果stmp_table_hash中stmt数量超过STMT_COUNT_LOG_FORSTMTTABLE时，记录日志信息
		目的是用于发现可能存在的内存泄漏和语句句柄没有释放的bug
		是在佛山项目时加入的
	*/
	rt_npc->last_stmt_time = Npp_GetEpochTime_MicroSecond();
	OraNet_DumpSql("step[1.10] : init rt_npc->last_stmt_time ok\n");

	rt_npc->new_connect = 1;		/* 设置rt_npc->new_connect标记为1，很重要 */
	memset(rt_npc->ip_port,0x00,sizeof(rt_npc->ip_port));
	return 1;
}



/*
	HandleNpc模式下的cherry篡改包逻辑
	返回：
	  1 - 完成了篡改
	  0 - 没有篡改(非cherry)
*/
int Npp_Cherry_DoTamper_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
#ifdef HAVE_CHERRY
	/* 每次循环，需要重新初始化以下rt_com->rewrite_packet变量(与SQL改写包处理有关的逻辑) */
	rt_com->rewrite_packet.packparse_result = 0;
	rt_com->rewrite_packet.is_switchoff = 0;
	rt_com->rewrite_packet.rowlimit_result = 0;
	if(__ORA_SESSION)
		__ORA_SESSION->help_parse_result=NPP_RESULT_NORMAL;
	//printf("[CHERRY] : rt_com->rewrite_packet.is_switchoff = %d\n",rt_com->rewrite_packet.is_switchoff);
	OraNet_DumpSql("Npp_Cherry_DoTamper_ForHandleNpc:__ORA_SESSION->need_tamper:%d,__ORA_SESSION->help_tamper_flag:%d\n",__ORA_SESSION->need_tamper,__ORA_SESSION->help_tamper_flag);
	if(__ORA_SESSION->need_tamper>0)
	{
		/* 发送篡改通讯包 */
		/* 检查当前的篡改标记是否是需要阻断了 */
		//printf("[CHERRY] : help_tamper_flag = %d\n",__ORA_SESSION->help_tamper_flag);
		if(__ORA_SESSION->enc_checksum == 0x03 && __ORA_SESSION->help_tamper_flag == DBFW_TAMPER_SWITCHOFF)
		{
			Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_TAMPER|DBFW_TAMPER_TYPE_SWITCHOFF);
							__ORA_SESSION->help_tamper_flag = 0;
				#ifdef DUMP_MEMORY_LEAK
							__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
				#else
							__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
				#endif  /* DUMP_MEMORY_LEAK */
		}
		else
		{
			if(__ORA_SESSION->help_tamper_flag==DBFW_TAMPER_DORESET)
			{
				/* 是，发送篡改+RESET包;然后设置process_exit_flag进程退出标记，在后面的处理中会检查该标记并退出会话 */
				Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_TAMPER|DBFW_TAMPER_TYPE_SWITCHOFF);
				__ORA_SESSION->help_tamper_flag = 0;
	#ifdef DUMP_MEMORY_LEAK
				__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
	#else
				__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
	#endif  /* DUMP_MEMORY_LEAK */
			}
			else
			{
				Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_TAMPER);
			}            
			if(__ORA_SESSION->enc_checksum == 0x03)
				__ORA_SESSION->help_tamper_flag = 0;
		}
			
		__ORA_SESSION->need_tamper = 0; /* 清理当前包篡改标记,避免后续的非篡改包被篡改 */
		OraNet_DumpSql("cherry step[12] tamp pack over\n ");
		
	}
	else if(__ORA_SESSION->help_tamper_flag==DBFW_TAMPER_DORESET)
	{
		/* 检查当前的篡改标记是否是需要阻断了 */
		/* 是，发送阻断包;然后设置process_exit_flag进程退出标记，在后面的处理中会检查该标记并退出会话 */
		Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
		__ORA_SESSION->help_tamper_flag = 0;
#ifdef DUMP_MEMORY_LEAK
		__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
#else
		__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
#endif  /* DUMP_MEMORY_LEAK */
		OraNet_DumpSql("cherry step[12] tamp pack over\n ");
	}
	else if(__ORA_SESSION->help_tamper_flag == DBFW_TAMPER_TYPE_DISCARD)
	{
		Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_DISCARD);
		__ORA_SESSION->help_tamper_flag = 0;
	}
	else
	{
		/* 发送正常的通讯包 */
		if(rt_cherry->begin_loop_flag==1)
		{
			//OraNet_DumpSql("Dbfw_SetSendQueueToRtbuf DBFW_TAMPER_TYPE_NORMAL\n");
			Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_NORMAL);
		}
		rt_cherry->begin_loop_flag = 1;
	}
	return 1;
#else
	return 0;
#endif  /* HAVE_CHERRY */
}

/************************************************************************/
/* 在每次循环开始时，进行进程状态和信号量检查和处理，包括如下：
   进程DBFW_HANDLEEXIT_FORMEMCHECK退出标记的检查
   信号量超时
   DBFW_HANDLEEXIT_FORREORDER检查
   并进行相应处理 
	返回值
	  2 - 后续要进行“丢包和包乱序的超时处理”
	  1 - continue loop
	  0 - 继续后面的处理
	  -1 - quit_real
	  -2 - quit
/************************************************************************/
int NPP_SemwaitAndExitFlag_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int ret = 0;
	/* 2015-04-10 增加退出标记检查和处理逻辑，取代handle信号 */
    if(__NPP_ALL_CONFIG->process_exit_flag==DBFW_HANDLEEXIT_FORMEMCHECK)
    {
        /* 
            需要进行内存检查的退出处理 
            1:保存会话信息
            2：根据情况进行内存泄漏检查
        */
        rt_npc->save_session_for_drawback = 1;
		OraNet_DumpSql("step[4.1] exception for process_exit_flag=DBFW_HANDLEEXIT_FORMEMCHECK(%d)\n",__NPP_ALL_CONFIG->process_exit_flag);
        //goto handle_npc_quit_real;
		return -1;
    }
	else if(__NPP_ALL_CONFIG->process_exit_flag == DBFW_HANDLEEXIT_FORREORDER)
	{
		//Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"exit_flag is DBFW_HANDLEEXIT_FORREORDER");
		OraNet_DumpSql("step[4.2] exception for process_exit_flag=DBFW_HANDLEEXIT_FORREORDER(%d)\n",__NPP_ALL_CONFIG->process_exit_flag);
		/* 后面要进入对信号量超时和DBFW_HANDLEEXIT_FORREORDER的统一处理程序,并且不再接受信号量 */
		//ret = -1;
	}
	else
    {   
		/* 没有需要处理的异常，开始接收NPC的信号量 */
        process_exit_forflag();
        int* p_smemid = NULL;
        p_smemid = __SGA_SESSBUF->semid_head + __NPP_ALL_CONFIG->sessionid_fornpc;
        ret = Dbfw_LockSemTimed((*p_smemid),1000/* 1000ms */);
    }
	/************************************************************************/
	/* 下面是信号量超时，和DBFW_HANDLEEXIT_FORREORDER的处理程序                    */
	/************************************************************************/
    if(ret<0 || __NPP_ALL_CONFIG->process_exit_flag == DBFW_HANDLEEXIT_FORREORDER)
    {
        if(__NPP_ALL_CONFIG->process_exit_flag != DBFW_HANDLEEXIT_FORREORDER)
        {     
			/* 检查是否当前操作被信号处理函数中断，如果发生则重新开始循环 */
            if(errno == EINTR) 
                return 1;	/* continue loop */
        }

        /* 2015-04-10 增加退出标记检查和处理逻辑，取代handle信号 */
        process_exit_forflag();
		/* 
            2014-09-11 增加自动退出标记的检查 
            自动退出的标记是由NPC进程根据内存使用情况和发呆时间来设置的
        */
            /* 设置了该标记，自动退出,退出前先恢复标记 */
            /* 离开(注意这里应该是真实的退出) */
        /* 
            达梦数据库存在一个很讨厌的行为：
            在发呆时，没间隔5秒，会互相发送一个空包（长度为0的空包）
        */		
        if(errno == EAGAIN || __NPP_ALL_CONFIG->process_exit_flag == DBFW_HANDLEEXIT_FORREORDER)
        {
			/* 设置rt_npc->timeout_recorder值，每发生一次超时1秒增加一次 */
			if(rt_npc->timeout_recorder<128)
			{
				rt_npc->timeout_recorder = rt_npc->timeout_recorder + 1;
			}
			if(errno == EAGAIN)
			{
				/* Semphone超时 */
				//OraNet_DumpSql("step[14.1] Semphone timeout\n");					
			}
			else
			{
				/* process_exit_flag */
				OraNet_DumpSql("step[4.7] process_exit_flag = %d\n",__NPP_ALL_CONFIG->process_exit_flag);
			}
#ifdef HAVE_CHERRY
            /* 功能 3.2.3 NPP将会话结束的FIN，FIN+ACK，ACK包返回 */
            /* 
				在启动方式为DPDK全透明网桥时,检查是否已经等待FIN后续包超时了 
				这个逻辑是用于处理当收到FIN包后，一直没有再收到ACK包的问题,超时时间为1秒
			*/
            if(__NPP_ALL_CONFIG->start_for_transparent==1 && __ORA_SESSION->timestamp_fin>0)
            {
                u_int64 timestamp_now;
                Dbfw_Fixarray_GetEpochTime_MicroSecond_FromSga(&__SGA_FIXARRAY, &timestamp_now);
                if((timestamp_now-__ORA_SESSION->timestamp_fin)>=TIMEOUT_FIN_FOR_CHERRY)
                {
                    /* 超过了1秒,挂起或退出 */
					OraNet_DumpSql("step[4.8] set process_exit_flag for TIMEOUT_FIN_FOR_CHERRY\n");
                    __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORREORDER;
                    __ORA_SESSION->timestamp_fin = 0;
                    //goto handle_npc_quit;	/* 注意：不要再这里退出，而是设置标记后等到下一轮的处理退出 */
                }
            }
#endif
			/* 
				检查是否有前台页面引起的配置变更 
				如果有配置变更，则Npp_CheckChangeAndReloadAllConfig函数内部将刷新缓冲区，并重置参数和计数值
			*/
			Npp_CheckChangeAndReloadAllConfig(__NPP_ALL_CONFIG);
			if(__DB_ISFIND == 0 && __NPP_ALL_CONFIG->has_inst == 0)
				return -1;

            /* 
                检查是否出现全0的IP 
                造成该问题的原因可能是因为进程池的设置不正确，也可能是通讯包错误
				这里纯粹是一个狗皮膏防守逻辑,出现这样的问题肯定是程序的bug引起的
            */
            if((u_int)rt_com->tcp_info->oracle_server_ip[0]==0 || (u_int)rt_com->tcp_info->client_ip[0]==0)
            {
                /* 出现异常 */
				OraNet_DumpSql("step[4.13] exception for all zero ip : oracle_server_ip=%llu, client_ip=%llu\n",rt_com->tcp_info->oracle_server_ip[0],rt_com->tcp_info->client_ip[0]);
                //goto handle_npc_quit_real;
				return -1;
            }
            /* 这里是一个很适合进行心处理的位置 */
            /* 设置fixarea 区的AliveSignal */
            rt_com->alive_time = Npp_GetEpochTime_MicroSecond();
            __NPP_ALL_CONFIG->current_time = rt_com->alive_time;
            Dbfw_Fixarray_SetProcessAliveSignal(&__SGA_FIXARRAY, __PROCESS_ID, rt_com->alive_time,DBFW_PTYPE_NPP);
			NPP_ConnectFilter(__ORA_SESSION,&(rt_com->rewrite_packet));
			NPP_HandleTlog(rt_com->alive_time,__ORA_SESSION);
			/* 
				下面是为了发现可能存在的语句句柄没有正常关闭而进行的定期检查逻辑 
				参考前面初始化rt_npc->last_stmt_time时写的注释信息
			*/
		    if((rt_com->alive_time - rt_npc->last_stmt_time) > 600000000)//每隔10分钟
		    {
			    char strlog[128];
			    int stmt_count = ZHashCount(__ORA_SESSION->stmp_table_hash);
			    int newstmt_count = ZHashCount(__ORA_SESSION->newstmt_table);
			    if(stmt_count > 500 || newstmt_count > 1)
			    {
				    memset(strlog,0,sizeof(strlog));
				    sprintf(strlog,"stmp_table_hash:%d  newstmt_table:%d",stmt_count,newstmt_count);
				    NPP_LOG_INFO((u_char*)strlog);						
			    }
			    rt_npc->last_stmt_time = rt_com->alive_time;
		    }
                           
			/* 
				2015-01-08  orcle 动态端口时1521端口的进程存活5s没有数据，则杀死该进程 
				这样做的原因是可能由于1521断后的通讯包丢失了断连接的tcp握手包引起NPP一直没有退出
				而这样的NPP不能等很长时间再退出。
			*/
			if(rt_npc->timeout_recorder>5 && __SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_ORACLE && __ORA_SESSION->is_redirect_pack == 5)
			{
				rt_npc->static_port_ret = Npp_FindProtectedDatabasePort_Static(&__SGA_FIXARRAY,__DB_ADDRESS,__DB_PORT);
				if(rt_npc->static_port_ret == 1)
				{
                    Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,
                        (char*)"Quit For no package (%d second) after recieve REDIRECT package"
                        ,rt_npc->timeout_recorder);
					return -1;
				}
			}
			/* 2014-12-29 下边的逻辑不适用于没有keepalive的数据库类型上，mysql就是这样的情况，所以给mysql过滤掉 */
            if(rt_npc->timeout_recorder>30 && (__SGA_AC_XSEC_DATABASE->dialect != DBFW_DBTYPE_MYSQL && __SGA_AC_XSEC_DATABASE->dialect != DBFW_DBTYPE_SHENTONG))
            {
                /* 发呆时间超过30秒，并且本会话所有采集到数据总和没有超过256字节，则退出会话 */
                if(rt_com->total_pack_size<256)
                {
					OraNet_DumpSql("step[4.16] exception no data for 30 sec\n");
                    /* 离开 */
                    rt_npc->save_session_for_drawback = 1;  /* 退出时保存会话信息用于找回 */
                    //goto handle_npc_quit_real;
					return -1;
                }
            }
            /* 
                丢包和包乱序的超时处理 
				1：旧的丢包排序算法，使用原有的逻辑(已经删除该部分代码)
                2：NEW_TCP_REORDER排序算法
            */
			if(rt_npc->timeout_recorder>60)
            {
                /* 前面的逻辑没有走到，必须在这里清零 */
                rt_npc->timeout_recorder = 0;
            }
			/* 重新开始下一轮的处理: for(;;) */
            //continue;
			return 2;
        }
        else
        {
            /* 信号量异常 */
            OraNet_DumpSql("step[4.17] semphone error\n");                
            /* 离开 */
#ifdef DUMP_MEMORY_LEAK
			/* TODO 这里是否需要增加对cherry的处理?需要与gxw确认 */
            /* 2014-09-19 取消信号量异常的日志 */
            //Npp_Exception_WithLog(NPP_ERROR_SEMPHONE,ret,__FILE__, __LINE__, __FUNCTION__,__SGA_SESSBUF->sem_for_session->semid[__ORA_SESSION->help_session_id]);                
            rt_npc->save_session_for_drawback = 1;  /* 退出时保存会话信息用于找回 */
            rt_npc->exit_for_sephone_error = 1;     /* 设置信号量异常并退出标记 */
            OraNet_DumpSql("step[14.16] exit for DUMP_MEMORY_LEAK\n");
            //goto handle_npc_quit;
			return -2;
#else
            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
            process_exit_forflag();
#endif
        }
    }
	return 0;
}

/************************************************************************/
/* 在每次循环开始时，异常状态检查
	返回值
	  1 - continue loop
	  0 - 继续后面的处理
	  -1 - quit_real
	  -2 - quit
/************************************************************************/
int NPP_ProcessException_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	//int ret = 0;
	int stmt_count = 0;
	/* 
        检查是否出现全0的IP 
        造成该问题的原因可能是因为进程池的设置不正确，也可能是通讯包错误
		这里纯粹是一个狗皮膏防守逻辑,出现这样的问题肯定是程序的bug引起的
    */
    if((u_int)rt_com->tcp_info->oracle_server_ip[0]==0 || (u_int)rt_com->tcp_info->client_ip[0]==0)
    {
        /* 出现异常 */
		OraNet_DumpSql("step[5.2] exception for all zero ip : oracle_server_ip=%llu, client_ip=%llu\n",(u_int)rt_com->tcp_info->oracle_server_ip[0],(u_int)rt_com->tcp_info->client_ip[0]);
        //goto handle_npc_quit_real;
		return -1;
    }

    /* 
		2015-04-24 增加NPP进程内存限制检查 
		原因：NPP进程目前仍然存在内存泄漏的情况，特别是在旁路模式下出现由于丢包引起的各种通讯包异常
		因此，主要对内存的使用进行控制，一旦超出了假设的内存使用量，则退出NPP
		目的：防止大量NPP内存泄漏引起系统的内存不足
		缺省的内存限制：10M
	*/
    if(Dbfw_NppUsedMemlIsOverLimit(0)==1)
    {
		OraNet_DumpSql("step[5.3] exception Dbfw_NppUsedMemlIsOverLimit\n");
        /* 超出了内存限制,检查会话的stmt数量,如果stmt的数量小于128个(粗略估计)，则认为出现了内存泄漏 */        
        stmt_count = ZHashCount(__ORA_SESSION->stmp_table_hash);
        if(stmt_count<128)
		{
			OraNet_DumpSql("step[5.4] exit for Dbfw_NppUsedMemlIsOverLimit and stmt_count=%d\n",stmt_count);
            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
		}
    }
    /* 2015-04-10 增加退出标记检查和处理逻辑，取代handle信号，本逻辑只有设置了内存泄漏检查的宏之后才会进入 */
    if(__NPP_ALL_CONFIG->process_exit_flag==DBFW_HANDLEEXIT_FORMEMCHECK)
    {
        /* 
            需要进行内存检查的退出处理 
            1:保存会话信息
            2：根据情况进行内存泄漏检查
        */
		OraNet_DumpSql("step[5.5] exit for DBFW_HANDLEEXIT_FORMEMCHECK\n");
        rt_npc->save_session_for_drawback = 1;
        //goto handle_npc_quit;
		return -2;
    }
    //process_exit_forflag();
    /* 
        2014-09-11 增加自动退出的检查 
        自动退出的标记是由NPC进程根据内存使用情况和发呆时间来设置的
    */
        /* 设置了该标记，自动退出,退出前先恢复标记 */
        //Npp_LogError((u_char*)"auto close for NPC's memory check",-1,0,__FILE__, __LINE__, __FUNCTION__);
        /* 离开 */
        //goto handle_npc_quit;
	return 0;
}

/*
	NPP进程心跳处理：刷新Alivetime
*/
void NPP_Alivetime_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	GetLocalTime_Now(&__NPP_ALL_CONFIG->tm_current);
    /* 发送AliveSignal和WorkSignal */
    Dbfw_Fixarray_GetEpochTime_MicroSecond_FromSga(&__SGA_FIXARRAY, &rt_com->alive_time);
    __NPP_ALL_CONFIG->current_time = rt_com->alive_time;
    /* 2014-09-11 
       当session的压力很大时，触发的次数会很频繁
       而worktime和alivetime的值理论上只需要每秒变化一次即可
       这种情况下，为了减少设置worktime和alivetime的次数,需要增加一个最后一次设置alivetime的时间戳指示器，用于判断
       当last_alivetime+1000000 < alivetime时，才设置一次
    */
    if((rt_com->last_alive_time+1000000) <= rt_com->alive_time)
    {
        /* 当最后记录的last_alivetime与当前时间相差一秒或以上时，则记录一次 */
        Dbfw_Fixarray_SetProcessAliveSignal(&__SGA_FIXARRAY, __PROCESS_ID, rt_com->alive_time,DBFW_PTYPE_NPP);
        Dbfw_Fixarray_SetProcessWorkSignal(&__SGA_FIXARRAY, __PROCESS_ID, rt_com->alive_time,DBFW_PTYPE_NPP);
        rt_com->last_alive_time = rt_com->alive_time;
    }
}

/*
	开始从capbuf区获取可用的通讯包地址,并检查获取是否出现异常
	返回值
		1 - continue loop
		0 - 继续后面的处理
		-1 - handle_npc_quit_real
		-2 - handle_npc_quit
*/
int NPP_ReadTisHeaderFromCapbuf_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int ret = 0;
	char errbuf[256];					/* API调用返回的错误信息 */
	memset(errbuf,0x00,sizeof(errbuf));

    ret = Tis_Content_Read(rt_npc->tis,(u_int)__NPP_ALL_CONFIG->sessionid_fornpc,rt_npc->cap_header,errbuf);
    if(ret < 0)
    {
		OraNet_DumpSql("step[8.1] Tis_Content_Read Failed:%d %s\n",ret, errbuf);
        //Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"Tis_Content_Read error ret=%d, sessionid=%d,",ret,__NPP_ALL_CONFIG->sessionid_fornpc);
		if(ret == -6) // Tis_Slot_Invalid
		{
			OraNet_DumpSql("step[8.2] exit for Tis_Content_Read Failed -6\n");
			//goto handle_npc_quit_real;
			return -1;
		}
		memset(errbuf,0,sizeof(errbuf));
		//continue;
		return 1;
	}
	if(ret == 0)
	{
		/* 没有可用的数据包 */
		//continue;
		return 1;
	}
    rt_npc->pkg_hdr = (Tis_Package_Header*)(rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset);

	if(Tis_Content_Type(rt_npc->tis) == 1)				          // tis content block模式
	{
	    /* 构建nfw_memqueue_node发送队列数据 */
	    __NPP_ALL_CONFIG->nfw_memqueue_node.value = rt_npc->cap_header->data_offset;  /* 包偏移量 */
	    __NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_TAMPER_TYPE_NORMAL;
	    __NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
	}

#ifdef HAVE_CHERRY
    /* 功能 3.2.3 NPP将会话结束的FIN，FIN+ACK，ACK包返回 */
    if(__NPP_ALL_CONFIG->start_for_transparent==1 && __ORA_SESSION->timestamp_fin>0)
    {
        u_int64 timestamp_now;
        Dbfw_Fixarray_GetEpochTime_MicroSecond_FromSga(&__SGA_FIXARRAY, &timestamp_now);
        /* 之前出现过了FIN包，无论什么包都立即转发，不再解析 */
        if((timestamp_now-__ORA_SESSION->timestamp_fin)>=1000000)
        {
            /* 超过了1秒,挂起或退出 */
            __ORA_SESSION->timestamp_fin = 0;
            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORREORDER;
        }
		//continue;
		return 1;
    }
    ///* fix bug 1970 : 在挂起状态下直接发送 */
    //if(__DB_ISFIND==0 || __NPP_ALL_CONFIG->dbfw_fordb_state==0)
    //{
    //    /* 不是被保护的DB，或者被保护的数据库的状态为“失效”，直接旁路 */
    //    //continue;
	//	return 1;
    //}
#endif
    /* 
		检查magic1和magic2
		如果是进程池，则首先检查是否不是在挂起状态 
	*/
    if(rt_npc->pkg_hdr->magic1 != TIS_MAGIC || rt_npc->pkg_hdr->magic2 != TIS_MAGIC_SHORT)
	{
		/* rt_npc->tis读取数据是出现magic1和magic2错误，一般出现这种情况是由于环形缓冲区数据被覆盖引起的 */
		Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"rt_npc->pkg_hdr->magic1 = %x   rt_npc->pkg_hdr->magic2 = %x",rt_npc->pkg_hdr->magic1,rt_npc->pkg_hdr->magic2);
		Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"current package[sec=%u , ack=%u, size=%u   client_port=%u]",rt_npc->parseresult.tcp_header.sequence,
			rt_npc->parseresult.tcp_header.acknowledge,
			rt_npc->parseresult.data_size,rt_com->tcp_info->client_port);
        /* 
            丢包处理 ：
            如果发生丢包，则将session下所有的stmt都要释放，同时将缓冲区清除
        */
		OraNet_DumpSql("step[8.3] exception magic1 or magic2 error magic1=%x , magic2=%x\n",rt_npc->pkg_hdr->magic1,rt_npc->pkg_hdr->magic2);
        Ora_ClearTcpPackageBuffer(rt_com->tcp_info);
		ClearSession_ForLosePack(__ORA_SESSION);
		rt_npc->isReleaseAllStmtForNpcLossPack_flag = 1;
		/* 修复天翼爱音乐现场出现的MySQL丢包引起的SGA乱问题 */
		if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL || __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG)
		{
			if(MYSQL_LoginOver(__ORA_SESSION)==0)
			{
				/* 没有登录完成，需要按照无连接会话处理 */
				OraNet_DumpSql("step[8.4] NPP_SetSessionForHandlePcap for mysql not login\n");
				NPP_SetSessionForHandlePcap(__ORA_SESSION);
			}
		}
		/* 这里删除了已经不再使用的HAVE_TCP_RECORDER处理程序 */
#ifdef NEW_TCP_REORDER
        /* 重置乱序缓冲区和状态数据 */
        Dbfw_TcpReorder_ResetAll(&rt_npc->new_tcpreorder_buffer);
#endif
		//continue;
		return 1;
	}
	rt_npc->cap_header->data_offset += sizeof(Tis_Package_Header);
	//OraNet_DumpSql("Tis_Slot_Read offset:%x  size:%d\n",rt_npc->cap_header->data_offset,rt_npc->cap_header->data_size);
	return 0;

}

/*
	开始从capbuf区获取可用的通讯包地址,并检查获取是否出现异常
	返回值
		1 - continue loop
		0 - 继续后面的处理
*/
int NPP_ReadTisDataFromCapbuf_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int ret = 0;
	if(rt_npc->ethernetframe.max_frame_size<rt_npc->cap_header->data_size)
    {
        /* 
			之前分配的max_frame_size尺寸不足，重新分配 
			这样做的原因是：如果max_frame_size尺寸足够的情况下frame_data不需要被free了，而是循环使用，性能好
		*/
        rt_npc->ethernetframe.frame_size = 0;
        ZFree(rt_npc->ethernetframe.frame_data);
        rt_npc->ethernetframe.max_frame_size = rt_npc->cap_header->data_size;
        rt_npc->ethernetframe.frame_data = (u_char*)ZMalloc(rt_npc->ethernetframe.max_frame_size);
    }
    rt_npc->ethernetframe.cursor = 0;
    rt_npc->ethernetframe.frame_size = rt_npc->cap_header->data_size;
	if(rt_npc->ethernetframe.frame_data==NULL)
	{
		rt_npc->ethernetframe.frame_data = (u_char*)ZMalloc(rt_npc->ethernetframe.max_frame_size);
	}
	/* 这里进行拷贝的时候，可能会由于环形缓冲区的覆盖造成拷贝的数据是错误的 */
    z_memcpy(rt_npc->ethernetframe.frame_data,rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,rt_npc->cap_header->data_size, __FILE__, __LINE__, Smem_LogError_Format);
	/*陈寿仓*/
#ifdef DUMP_TCPDATA
	if(dump_tcpdata)
	{
		acp_dump_raw(dump_tcpdata,rt_npc->ethernetframe.frame_data,rt_npc->cap_header->data_size);
	}
#endif 
	/* 
		将rt_npc->ethernetframe中的裸包数据进行tcp解析，转存到rt_npc->parseresult中 
		注意：这里使用的是内存拷贝的方式，会存在性能的损失
	*/
    if(rt_npc->parseresult.data_size>0)
    {
        ZFree(rt_npc->parseresult.parse_data);
        rt_npc->parseresult.data_size = 0;
    }
	rt_npc->parseresult.data_size = 0;
	rt_npc->ethernetframe.vxlan_port = __NPP_ALL_CONFIG->s_vxlan_port;
	/* 由于前面可能出现由于环形缓冲区的覆盖造成拷贝的数据是错误的,所以需要在Npp_ParseEthernetFrame内部进行数据的检查 */
    ret = Npp_ParseEthernetFrame(&rt_npc->ethernetframe,&rt_npc->parseresult);

	/* 修复CAPBUF环形缓冲区数据异常引起的通讯包解析错误 */
	/* 处理通讯包不符合格式，可能产生的原因是环形缓冲区被覆盖 */
	if(ret<=0)
	{
	    if(ret == (NPP_ERROR_NETPARSER_GREFREAGMENT - NPP_ERRNO_START))
	    {
	        /*GRE 的ip分片包，等以下个包*/
	        return 1;
	    }
		/* 解析rt_npc->ethernetframe失败 */
		OraNet_DumpSql("step[9.1] exception Npp_ParseEthernetFrame fail ret = %d\n",ret);
		Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"tcp package is bad ret = %d",ret);
		Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"current package[sec=%u , ack=%u, size=%u  client_port=%u]",rt_npc->parseresult.tcp_header.sequence,
			rt_npc->parseresult.tcp_header.acknowledge,
			rt_npc->parseresult.data_size,rt_com->tcp_info->client_port);
        /* 
            丢包处理 ：
            如果发生丢包，则将session下所有的stmt都要释放，同时将缓冲区清除
        */
        Ora_ClearTcpPackageBuffer(rt_com->tcp_info);
		ClearSession_ForLosePack(__ORA_SESSION);
		rt_npc->isReleaseAllStmtForNpcLossPack_flag = 1;
		/* 修复天翼爱音乐现场出现的MySQL丢包引起的SGA乱问题 */
		if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL || __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG)
		{
			if(MYSQL_LoginOver(__ORA_SESSION)==0)
			{
				/* 没有登录完成，需要按照无连接会话处理 */
				OraNet_DumpSql("step[9.2] NPP_SetSessionForHandlePcap for mysql not login\n");
				NPP_SetSessionForHandlePcap(__ORA_SESSION);
			}
		}
		/* 这里删除了已经不再使用的HAVE_TCP_RECORDER处理程序 */
#ifdef NEW_TCP_REORDER
        /* 重置乱序缓冲区和状态数据 */
        Dbfw_TcpReorder_ResetAll(&rt_npc->new_tcpreorder_buffer);
#endif
		//continue;
		return 1;
	}
	else
	{
		/* 通讯包数据获取成功 */
		/* fix bug 1970 : 在挂起状态下直接发送 */
#ifndef ENABLE_TELNET
        if(__DB_ISFIND==0 || __NPP_ALL_CONFIG->dbfw_fordb_state==0)
	    {
	        /* 不是被保护的DB，或者被保护的数据库的状态为“失效”，直接旁路 */
	        //continue;
			if(rt_npc->parseresult.tcp_header.fin==1 || rt_npc->parseresult.tcp_header.rst==1)
			{
				return 2;
			}
			else
			{
				return 1;
			}
	    }
#endif

		return 0;
	}
}

/*
	通讯包冗余过滤
	修复大连农商行多交换机进行引起的10.8.144.225请求无法审计问题(sec+ack匹配方法) 
	具体算法：
	首先找到第一个SYN+ACK可以匹配的请求包和应答包，并记录相应的请求包的DB MAC地址和应答包的DB MAC地址
	然后使用下来的全部DB MAC地址进行后续通讯包的过滤
	在成功匹配请求和应答包之前，不对通讯包进行解析，而是加入到一个buffer缓冲区中,但如果是SYN+ACK包则放行
	注意：当成功匹配后，需要重置客户端和服务器的MAC地址
	已支持的场景：正常的单链路，RAC下的双链路，RAC下的双链路+上下行网卡
	返回值
		1 - continue loop
		0 - 继续后面的处理
*/
int NPP_RedundantPackageFilter_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int i = 0;
	/* 获取当前的包的DB MAC地址(可能存在性能问题) */
	rt_npc->db_mac = 0;
	rt_npc->direction_formac = NPP_GetPcapDirect(rt_npc->parseresult,rt_com->tcp_info);
	if(rt_npc->direction_formac==USER2ORA)
	{
		/* C->S方向通讯包，目标MAC地址是DB的MAC */
		z_memcpy(&rt_npc->db_mac,&(rt_npc->parseresult.ethernet.mac_dest),sizeof(rt_npc->parseresult.ethernet.mac_dest), __FILE__, __LINE__, Smem_LogError_Format);                            
	}
	else
	{
		z_memcpy(&rt_npc->db_mac,&(rt_npc->parseresult.ethernet.mac_src),sizeof(rt_npc->parseresult.ethernet.mac_src), __FILE__, __LINE__, Smem_LogError_Format);
	}
	
	if(__NPP_ALL_CONFIG->capbuf_id == 2)
    {
        return 0;
    }
    
	/* 性能测试点2.1,持续占用1.3CPU */
	if(rt_npc->full_dir_mac_idx<PCAP_ETH_ADDR_ARRAY)
	{
		/* 已经有匹配成功的sec+ack对了 */
		/* 过滤方法2：过滤MAC地址是否是正确的，此种方法可以过滤掉另一条链路镜像的通讯包，理论上是绝对可靠和准确的 */                
		if(rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].db_mac_req!=rt_npc->db_mac && rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].db_mac_resp!=rt_npc->db_mac)
		{
			/* 是需要丢弃的通讯包 */
			OraNet_DumpSql("step[10.1] ***drop pack for rt_npc->db_mac not match\n");                        
			//OraNet_DumpSql("***drop pack for rt_npc->db_mac=%X ; secquence=%u ack=%u ; rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].secquence=%u, rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].ack=%u\n",
			//rt_npc->db_mac,rt_npc->parseresult.tcp_header.sequence,rt_npc->parseresult.tcp_header.acknowledge,rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].secquence,rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].ack);
			//continue;
			return 1;
		}
		else
		{
			/* 符合特征的通讯包，可以进行解析了 */
			return 0;
		}		
	}
	else
	{
		if(__NPP_ALL_CONFIG->s_oneway_audit_switch == 1 && rt_npc->package_count >= __NPP_ALL_CONFIG->s_oneway_audit_pctcount)
		{
			/* 开启单向审计，强制开始审计 */
			int cursor = 0;	
			for(i=0;i<PCAP_ETH_ADDR_ARRAY;i++)
			{
				if(rt_npc->tcp_secandack[i].secquence == 0 && rt_npc->tcp_secandack[i].ack == 0)
				{
					break;
				}
				if(rt_npc->tcp_secandack[i].dyna_tcpdata_buf.length >  rt_npc->tcp_secandack[cursor].dyna_tcpdata_buf.length)
				{
					cursor = i;
				}
			}
			if(NULL != __ORA_SESSION)
			{
			    __ORA_SESSION->start_for_oneway_audit = 1;
			}
			/* 是另一个方向的通讯包 */
			/* 通讯包完整了 */
			rt_npc->full_dir_mac_idx = cursor;
			/* 保存当前的包的MAC地址 */
			if(rt_npc->direction_formac==USER2ORA)
			{
				/* C->S方向通讯包，目标MAC地址是DB的MAC */
				rt_npc->tcp_secandack[cursor].db_mac_req = rt_npc->db_mac;
			}
			else
			{
				rt_npc->tcp_secandack[cursor].db_mac_resp = rt_npc->db_mac;
			}
			OraNet_DumpSql("-----------FULL PACK MAC FOR secquence=%u ack=%u idx = %d\n",rt_npc->parseresult.tcp_header.sequence,rt_npc->parseresult.tcp_header.acknowledge,rt_npc->full_dir_mac_idx);
			OraNet_DumpSql("[%d] db_mac_req = %llX , db_mac_resp=%llX\n",cursor,rt_npc->tcp_secandack[cursor].db_mac_req,rt_npc->tcp_secandack[cursor].db_mac_resp);
			OraNet_DumpSql("----------------------------------------- \n");
			/* 这里删除了已经不再使用的HAVE_TCP_RECORDER处理程序 */
#ifdef NEW_TCP_REORDER
			/* 重置乱序缓冲区 */
			Dbfw_TcpReorder_ClearOutOfReorderPack(&rt_npc->new_tcpreorder_buffer);
#endif
			if(rt_npc->mac_addr_count>1)
			{
				OraNet_DumpSql("step[10.3] -----------RESET for secquence------------- \n");
				/* 超过了1个MAC地址 */
				/* 这里删除了已经不再使用的HAVE_TCP_RECORDER处理程序 */
#ifdef NEW_TCP_REORDER
				/* 重置缓冲区的运行时数据 */
				Dbfw_TcpReorder_ResetRuntimeData(&rt_npc->new_tcpreorder_buffer);
#endif
				Ora_ClearTcpPackageBuffer(rt_com->tcp_info);
				ClearSession_ForLosePack(__ORA_SESSION);
				//rt_npc->isReleaseAllStmtForNpcLossPack_flag = 1;
				/* 修复天翼爱音乐现场出现的MySQL丢包引起的SGA乱问题 */
				if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL || __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG)
				{
					if(MYSQL_LoginOver(__ORA_SESSION)==0)
					{
						/* 没有登录完成，需要按照无连接会话处理 */
						OraNet_DumpSql("step[10.3.1] NPP_SetSessionForHandlePcap for mysql not login\n");
						NPP_SetSessionForHandlePcap(__ORA_SESSION);
					}
				}
			}
			/* 设置正确的MAC地址 */
			memset(rt_com->tcp_info->client_mac_str,0x00,sizeof(rt_com->tcp_info->client_mac_str));
			memset(rt_com->tcp_info->oracle_server_mac_str,0x00,sizeof(rt_com->tcp_info->oracle_server_mac_str));
			if(rt_npc->direction_formac==USER2ORA)
			{
				z_strcpy((char *)rt_com->tcp_info->client_mac_str , (char *)rt_npc->parseresult.ethernet.mac_src, __FILE__, __LINE__, Smem_LogError_Format);
				z_strcpy((char *)rt_com->tcp_info->oracle_server_mac_str , (char *)rt_npc->parseresult.ethernet.mac_dest, __FILE__, __LINE__, Smem_LogError_Format);
			}
			else
			{
				z_strcpy((char *)rt_com->tcp_info->client_mac_str , (char *)rt_npc->parseresult.ethernet.mac_dest, __FILE__, __LINE__, Smem_LogError_Format);
				z_strcpy((char *)rt_com->tcp_info->oracle_server_mac_str , (char *)rt_npc->parseresult.ethernet.mac_src, __FILE__, __LINE__, Smem_LogError_Format);
			}
			OraNet_DumpSql("step[10.4] start parse dyna_tcpdata_buf[%d].length = %d\n",rt_npc->full_dir_mac_idx,rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].dyna_tcpdata_buf.length);
			/* 清理无用的缓冲区数据 */
			for(int clear_idx=0;clear_idx<PCAP_ETH_ADDR_ARRAY;clear_idx++)
			{
				if(clear_idx!=rt_npc->full_dir_mac_idx)
				{
					if(rt_npc->tcp_secandack[clear_idx].dyna_tcpdata_buf.max_length>0)
					{
						Dbfw_DynStr_Free(&rt_npc->tcp_secandack[clear_idx].dyna_tcpdata_buf);
					}
				}
			}
			//break;  /* 通讯包匹配成功，处理完成，跳出 */
			return 0;
		}
		/* 截至目前还没有成功匹配上请求和应答包的SEC+ACK,继续匹配 */
		rt_npc->tmp_secandack_1 = (u_int64)rt_npc->parseresult.tcp_header.sequence + (u_int64)rt_npc->parseresult.tcp_header.acknowledge;
		for(i=0;i<PCAP_ETH_ADDR_ARRAY;i++)
		{
			if(rt_npc->tcp_secandack[i].secquence>0 && rt_npc->tcp_secandack[i].ack>0)
			{
				OraNet_DumpSql("step[10.2] current secquence=%u ack=%u, data_size= %u\n",rt_npc->parseresult.tcp_header.sequence,rt_npc->parseresult.tcp_header.acknowledge,rt_npc->parseresult.data_size);
				OraNet_DumpSql("step[10.2] array's sec&ack verify for %d secquence=%u ack=%u, data_size= %u\n",i,rt_npc->tcp_secandack[i].secquence,rt_npc->tcp_secandack[i].ack,rt_npc->parseresult.data_size);
				rt_npc->tmp_secandack_0 = (u_int64)rt_npc->tcp_secandack[i].secquence + (u_int64)rt_npc->tcp_secandack[i].ack +(u_int64)rt_npc->tcp_secandack[i].data_size;
				OraNet_DumpSql("step[10.2] rt_npc->tmp_secandack_0=%u rt_npc->tmp_secandack_1= %u ; rt_npc->direction_formac=%d, rt_npc->tcp_secandack[i].last_direct=%d\n",rt_npc->tmp_secandack_0,rt_npc->tmp_secandack_1,rt_npc->direction_formac,rt_npc->tcp_secandack[i].last_direct);
				if(((rt_npc->tmp_secandack_0) == rt_npc->tmp_secandack_1) 
				    || ((rt_npc->tmp_secandack_0+1) == rt_npc->tmp_secandack_1/* for SYN or SYN+ACK */)
				    || ((rt_npc->direction_formac<3 && rt_npc->tcp_secandack[i].last_direct ==rt_npc->direction_formac)
				        &&(rt_npc->tcp_secandack[i].secquence + rt_npc->tcp_secandack[i].data_size == (u_int64)rt_npc->parseresult.tcp_header.sequence)
				        &&((rt_npc->tcp_secandack[i].ack <= rt_npc->parseresult.tcp_header.acknowledge)
				            ||((rt_npc->tcp_secandack[i].ack > rt_npc->parseresult.tcp_header.acknowledge)
				                && (rt_npc->tcp_secandack[i].ack > rt_npc->parseresult.tcp_header.acknowledge + INT_MAX)
				                )
				            ) /* for 只有单向包，反向丢包，正向连续*/
				        )
				    )
				{
					/* 包接上了 */                            
					if(rt_npc->direction_formac<3 && rt_npc->tcp_secandack[i].last_direct!=rt_npc->direction_formac)
					{
						/* 是另一个方向的通讯包 */
						/* 通讯包完整了 */
						rt_npc->full_dir_mac_idx = i;
						/* 保存当前的包的MAC地址 */
						if(rt_npc->direction_formac==USER2ORA)
						{
							/* C->S方向通讯包，目标MAC地址是DB的MAC */
							rt_npc->tcp_secandack[i].db_mac_req = rt_npc->db_mac;
						}
						else
						{
							rt_npc->tcp_secandack[i].db_mac_resp = rt_npc->db_mac;
						}
						OraNet_DumpSql("-----------FULL PACK MAC FOR secquence=%u ack=%u\n",rt_npc->parseresult.tcp_header.sequence,rt_npc->parseresult.tcp_header.acknowledge);
						OraNet_DumpSql("[%d] db_mac_req = %llX , db_mac_resp=%llX\n",i,rt_npc->tcp_secandack[i].db_mac_req,rt_npc->tcp_secandack[i].db_mac_resp);
						OraNet_DumpSql("----------------------------------------- \n");
						/* 这里删除了已经不再使用的HAVE_TCP_RECORDER处理程序 */
#ifdef NEW_TCP_REORDER
						/* 重置乱序缓冲区 */
						Dbfw_TcpReorder_ClearOutOfReorderPack(&rt_npc->new_tcpreorder_buffer);
#endif
						if(rt_npc->mac_addr_count>1)
						{
							OraNet_DumpSql("step[10.3] -----------RESET for secquence------------- \n");
							/* 超过了1个MAC地址 */
							/* 这里删除了已经不再使用的HAVE_TCP_RECORDER处理程序 */
#ifdef NEW_TCP_REORDER
							/* 重置缓冲区的运行时数据 */
							Dbfw_TcpReorder_ResetRuntimeData(&rt_npc->new_tcpreorder_buffer);
#endif
							Ora_ClearTcpPackageBuffer(rt_com->tcp_info);
							ClearSession_ForLosePack(__ORA_SESSION);
							//rt_npc->isReleaseAllStmtForNpcLossPack_flag = 1;
							/* 修复天翼爱音乐现场出现的MySQL丢包引起的SGA乱问题 */
							if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL || __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG)
							{
								if(MYSQL_LoginOver(__ORA_SESSION)==0)
								{
									/* 没有登录完成，需要按照无连接会话处理 */
									OraNet_DumpSql("step[10.3.1] NPP_SetSessionForHandlePcap for mysql not login\n");
									NPP_SetSessionForHandlePcap(__ORA_SESSION);
								}
							}
						}
						/* 设置正确的MAC地址 */
						memset(rt_com->tcp_info->client_mac_str,0x00,sizeof(rt_com->tcp_info->client_mac_str));
						memset(rt_com->tcp_info->oracle_server_mac_str,0x00,sizeof(rt_com->tcp_info->oracle_server_mac_str));
						if(rt_npc->direction_formac==USER2ORA)
						{
							z_strcpy((char *)rt_com->tcp_info->client_mac_str , (char *)rt_npc->parseresult.ethernet.mac_src, __FILE__, __LINE__, Smem_LogError_Format);
							z_strcpy((char *)rt_com->tcp_info->oracle_server_mac_str , (char *)rt_npc->parseresult.ethernet.mac_dest, __FILE__, __LINE__, Smem_LogError_Format);
						}
						else
						{
							z_strcpy((char *)rt_com->tcp_info->client_mac_str , (char *)rt_npc->parseresult.ethernet.mac_dest, __FILE__, __LINE__, Smem_LogError_Format);
							z_strcpy((char *)rt_com->tcp_info->oracle_server_mac_str , (char *)rt_npc->parseresult.ethernet.mac_src, __FILE__, __LINE__, Smem_LogError_Format);
						}
						OraNet_DumpSql("step[10.4] start parse dyna_tcpdata_buf[%d].length = %d\n",rt_npc->full_dir_mac_idx,rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].dyna_tcpdata_buf.length);
						/* 清理无用的缓冲区数据 */
						for(int clear_idx=0;clear_idx<PCAP_ETH_ADDR_ARRAY;clear_idx++)
						{
							if(clear_idx!=rt_npc->full_dir_mac_idx)
							{
								if(rt_npc->tcp_secandack[clear_idx].dyna_tcpdata_buf.max_length>0)
								{
									Dbfw_DynStr_Free(&rt_npc->tcp_secandack[clear_idx].dyna_tcpdata_buf);
								}
							}
						}
						//break;  /* 通讯包匹配成功，处理完成，跳出 */
						return 0;
					}
					else if(rt_npc->direction_formac<3)
					{
                        rt_npc->package_count++;
                        if(!(((rt_npc->tmp_secandack_0) == rt_npc->tmp_secandack_1) 
        				    || ((rt_npc->tmp_secandack_0+1) == rt_npc->tmp_secandack_1/* for SYN or SYN+ACK */)))
        				{
        				    /*单向丢包，标记mysql的无连接会话标记，但是继续拼包处理*/
        				    
                            if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL || __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG)
                            {
                                if(MYSQL_LoginOver(__ORA_SESSION)==0)
                                {
                                    /* 没有登录完成，需要按照无连接会话处理 */
                                    OraNet_DumpSql("step[10.3.1] NPP_SetSessionForHandlePcap for mysql not login\n");
                                    NPP_SetSessionForHandlePcap(__ORA_SESSION);
                                }
                            }
        				}
                        /* 理论上是与之前同一个方向的通讯包,继续后面的处理 */
						rt_npc->tcp_secandack[i].secquence = rt_npc->parseresult.tcp_header.sequence;
						rt_npc->tcp_secandack[i].ack = rt_npc->parseresult.tcp_header.acknowledge;
						rt_npc->tcp_secandack[i].data_size =rt_npc->parseresult.data_size;
						rt_npc->tcp_secandack[i].last_direct = rt_npc->direction_formac;
						/* 记录DB服务器的MAC地址 */
						if(rt_npc->direction_formac==USER2ORA)
						{
							/* C->S方向通讯包，目标MAC地址是DB的MAC */
							rt_npc->tcp_secandack[i].db_mac_req = rt_npc->db_mac;
						}
						else
						{
							rt_npc->tcp_secandack[i].db_mac_resp = rt_npc->db_mac;
						}
						/* 检查是否是SYN或SYN+ACK包，是则进入后面的处理 */
#ifdef NPC_USE_SYNANDACK_START
						/* SYN+ACK创建NPP模式 */
						if(rt_npc->parseresult.tcp_header.syn==1 && rt_npc->parseresult.tcp_header.ack==1)
#else
						/* SYN创建NPP模式 */
						if(rt_npc->parseresult.tcp_header.syn==1 && rt_npc->parseresult.tcp_header.ack==0)
#endif
						{
							/* 后面开始处理SYN+ACK逻辑 */
							//break;
							return 0;
						}
						/* alter by liyanjun,2016-06-24, fixed bug dbf2947*/
						if(rt_npc->parseresult.tcp_header.rst==1 || rt_npc->parseresult.tcp_header.fin==1)
						{
							return 0;
						}
						/* 否则将数据加入到dyna_tcpdata_buf缓冲区 */                                
						if(rt_npc->parseresult.data_size>0)
						{
							/* 加入到rt_npc->tcp_secandack的缓冲区中,前面肯定已经分配了dyna_tcpdata_buf缓冲区了,但这里也需要进行防守检查 */
							if(rt_npc->tcp_secandack[i].dyna_tcpdata_buf.max_length>0)
							{
								/* 已经分配过了 */
								/* 先检查尺寸是否超限，超限则清空，并重置 */
								if(rt_npc->tcp_secandack[i].dyna_tcpdata_buf.length > PCAP_DYNATCPBUF_MAXSIZE)
								{
									Dbfw_DynStr_Free(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf);
									Dbfw_Init_Dynamic_String(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf,(char*)"",1024,1024);
								}
								Dbfw_DynStr_Append_Mem(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf,(char*)rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size);
							}
							else
							{
								/* 理论上不应该进入这个逻辑 */
								Dbfw_Init_Dynamic_String(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf,(char*)"",1024,1024);
								Dbfw_DynStr_Append_Mem(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf,(char*)rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size);
							}
						}
						OraNet_DumpSql("step[10.5] dyna_tcpdata_buf[%d].length = %d\n",i,rt_npc->tcp_secandack[i].dyna_tcpdata_buf.length);
						//goto handle_npc_start_loop;   /* 在成功匹配SEC+ACK前，不进行处理 */
						return 1;
					}
					else
					{
						/* 是未知方向的通讯包，不处理 */
						//goto handle_npc_start_loop;
                        rt_npc->package_count++;
                        return 1;
					}
				}
				else
				{
					/* 包没有接上，检查差值有多大 */
					if(rt_npc->tmp_secandack_1 > rt_npc->tmp_secandack_0)
					{
						/* 这种关系是符合逻辑的 */
						if(rt_npc->tmp_secandack_1>(rt_npc->tmp_secandack_0+(u_int64)(1024*1024)))
						{
							/* 是需要进行下一轮检查的通讯包 */
							//OraNet_DumpSql("***drop pack for secquence=%u ack=%u\n",rt_npc->parseresult.tcp_header.sequence,rt_npc->parseresult.tcp_header.acknowledge);
							if(i==(PCAP_ETH_ADDR_ARRAY-1))
							{
								rt_npc->package_count++;
								/* 已经到了数组的末尾，仍然没有匹配的，或已经占满了数组元素，直接丢弃 */
								OraNet_DumpSql("step[10.6] -----------i==(PCAP_ETH_ADDR_ARRAY-1)------------- %d\n",i);
								//goto handle_npc_start_loop;
								return 1;
							}
							continue;
							//return 1;
						}
						else
						{
							rt_npc->package_count++;
							/* 是接近的通讯包，用这个新包替换,理论上这里应该是已经发生丢包了，需要重置rt_npc->tcp_secandack[i].dyna_tcpdata_buf */
							//OraNet_DumpSql("@@@parse pack for mac data_size=%d, sequence = %u, help_nosql_for_losspack = %d\n",rt_npc->parseresult.data_size,rt_npc->parseresult.tcp_header.sequence, __ORA_SESSION->help_nosql_for_losspack);
							rt_npc->tcp_secandack[i].secquence = rt_npc->parseresult.tcp_header.sequence;
							rt_npc->tcp_secandack[i].ack = rt_npc->parseresult.tcp_header.acknowledge;
							rt_npc->tcp_secandack[i].data_size =rt_npc->parseresult.data_size;
							rt_npc->tcp_secandack[i].last_direct = rt_npc->direction_formac;
							/* 记录DB服务器的MAC地址 */
							//rt_npc->db_mac = 0;
							if(rt_npc->direction_formac==USER2ORA)
							{
								/* C->S方向通讯包，目标MAC地址是DB的MAC */
								rt_npc->tcp_secandack[i].db_mac_req = rt_npc->db_mac;
							}
							else
							{
								rt_npc->tcp_secandack[i].db_mac_resp = rt_npc->db_mac;
							}
							/* 检查是否是SYN或SYN+ACK包，是则进入后面的处理 */
#ifdef NPC_USE_SYNANDACK_START
							/* SYN+ACK创建NPP模式 */
							if(rt_npc->parseresult.tcp_header.syn==1 && rt_npc->parseresult.tcp_header.ack==1)
#else
							/* SYN创建NPP模式 */
							if(rt_npc->parseresult.tcp_header.syn==1 && rt_npc->parseresult.tcp_header.ack==0)
#endif
							{
								/* 后面开始处理SYN+ACK逻辑 */
								//break;
								return 0;
							}
							
							/* alter by liyanjun,2016-06-24, fixed bug dbf2947*/
							if(rt_npc->parseresult.tcp_header.rst==1 || rt_npc->parseresult.tcp_header.fin==1)
							{
								return 0;
							}
							
							/* 否则将数据加入到dyna_tcpdata_buf缓冲区 */
							if(rt_npc->parseresult.data_size>0)
							{
								/* 加入到rt_npc->tcp_secandack的缓冲区中,前面肯定已经分配了dyna_tcpdata_buf缓冲区了,但这里也需要进行防守检查 */
								if(rt_npc->tcp_secandack[i].dyna_tcpdata_buf.max_length>0)
								{
									/* 已经分配过了 */
									/* 理论上这里应该是已经发生丢包了，需要重置rt_npc->tcp_secandack[i].dyna_tcpdata_buf */
									//if(rt_npc->tcp_secandack[i].dyna_tcpdata_buf.length > PCAP_DYNATCPBUF_MAXSIZE)
									{
										Dbfw_DynStr_Free(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf);
										Dbfw_Init_Dynamic_String(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf,(char*)"",1024,1024);
									}
									Dbfw_DynStr_Append_Mem(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf,(char*)rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size);
								}
								else
								{
									/* 理论上不应该进入这个逻辑 */
									Dbfw_Init_Dynamic_String(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf,(char*)"",1024,1024);
									Dbfw_DynStr_Append_Mem(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf,(char*)rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size);
								}
							}
							OraNet_DumpSql("step[10.7] dyna_tcpdata_buf[%d].length = %d\n",i,rt_npc->tcp_secandack[i].dyna_tcpdata_buf.length);
							//goto handle_npc_start_loop;   /* 在成功匹配SEC+ACK前，不进行处理 */
							return 1;
							//break;
						}
					}
					else
					{
						/* 是需要进行下一轮检查的通讯包 */
						if(i==(PCAP_ETH_ADDR_ARRAY-1))
						{
							rt_npc->package_count++;
							/* 已经到了数组的末尾，仍然没有匹配的，或已经占满了数组元素，直接丢弃 */
							OraNet_DumpSql("step[10.8] -----------i==(PCAP_ETH_ADDR_ARRAY-1)------------- %d\n",i);
							//goto handle_npc_start_loop;
							return 1;
						}
						continue;
						//return 1;
					}
				}
			}
			else
			{
				rt_npc->package_count++;
				/* 没有出现SEC和ACK值，添加到新的rt_npc->tcp_secandack数组元素下，需要重置rt_npc->tcp_secandack[i].dyna_tcpdata_buf */
				OraNet_DumpSql("start sec&ack verify for %d secquence=%u ack=%u\n",i,rt_npc->parseresult.tcp_header.sequence,rt_npc->parseresult.tcp_header.acknowledge);
				rt_npc->tcp_secandack[i].secquence = rt_npc->parseresult.tcp_header.sequence;
				rt_npc->tcp_secandack[i].ack = rt_npc->parseresult.tcp_header.acknowledge;
				rt_npc->tcp_secandack[i].data_size =rt_npc->parseresult.data_size;
				rt_npc->tcp_secandack[i].last_direct = rt_npc->direction_formac;
				/* 记录DB服务器的MAC地址 */
				//rt_npc->db_mac = 0;
				if(rt_npc->direction_formac==USER2ORA)
				{
					/* C->S方向通讯包，目标MAC地址是DB的MAC */
					rt_npc->tcp_secandack[i].db_mac_req = rt_npc->db_mac;
				}
				else
				{
					rt_npc->tcp_secandack[i].db_mac_resp = rt_npc->db_mac;
				}
				rt_npc->mac_addr_count = i+1;
				/* 添加完成 */
				/* 检查是否是SYN或SYN+ACK包，是则进入后面的处理 */
#ifdef NPC_USE_SYNANDACK_START
				/* SYN+ACK创建NPP模式 */
				if(rt_npc->parseresult.tcp_header.syn==1 && rt_npc->parseresult.tcp_header.ack==1)
#else
				/* SYN创建NPP模式 */
				if(rt_npc->parseresult.tcp_header.syn==1 && rt_npc->parseresult.tcp_header.ack==0)
#endif
				{
					/* 后面开始处理SYN+ACK逻辑 */
					//break;
					return 0;
				}
				
				/* alter by liyanjun,2016-06-24, fixed bug dbf2947*/
				if(rt_npc->parseresult.tcp_header.rst==1 || rt_npc->parseresult.tcp_header.fin==1)
				{
					return 0;
				}
				/* 否则将数据加入到dyna_tcpdata_buf缓冲区 */
				if(rt_npc->parseresult.data_size>0)
				{
					/* 加入到rt_npc->tcp_secandack的缓冲区中,前面肯定已经分配了dyna_tcpdata_buf缓冲区了,但这里也需要进行防守检查 */
					if(rt_npc->tcp_secandack[i].dyna_tcpdata_buf.max_length>0)
					{
						/* 已经分配过了 */
						/* 理论上这里应该是一个新的缓冲区，需要重置rt_npc->tcp_secandack[i].dyna_tcpdata_buf */
						//if(rt_npc->tcp_secandack[i].dyna_tcpdata_buf.length > PCAP_DYNATCPBUF_MAXSIZE)
						{
							Dbfw_DynStr_Free(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf);
							Dbfw_Init_Dynamic_String(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf,(char*)"",1024,1024);
						}
						Dbfw_DynStr_Append_Mem(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf,(char*)rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size);
					}
					else
					{
						Dbfw_Init_Dynamic_String(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf,(char*)"",1024,1024);
						Dbfw_DynStr_Append_Mem(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf,(char*)rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size);
					}
				}
				OraNet_DumpSql("step[10.9] dyna_tcpdata_buf[%d].length = %d\n",i,rt_npc->tcp_secandack[i].dyna_tcpdata_buf.length);
				//goto handle_npc_start_loop;   /* 在成功匹配SEC+ACK前，不进行处理 */
				return 1;
			}
		}
	}
	/* 可以继续后面的处理了 */
	return 0;
}

/*
	通讯包匹配处理
	IP和端口是否是本会话匹配的检查
	返回值
		1 - continue loop(不匹配)
		0 - 继续后面的处理(匹配成功)
*/
int NPP_MatchPackageAddress_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	u_int64 ip_srcaddr[2];
	u_int64 ip_destaddr[2];
	u_int64 *p_uint64;

	if(rt_npc->parseresult.ethernet.type == 0x86dd)
	{
		p_uint64 = (u_int64*)rt_npc->parseresult.ipv6_header.ip_srcaddr;
		ip_srcaddr[0] = p_uint64[0];
		ip_srcaddr[1] = p_uint64[1];
		p_uint64 = (u_int64*)rt_npc->parseresult.ipv6_header.ip_destaddr;
		ip_destaddr[0] = p_uint64[0];
		ip_destaddr[1] = p_uint64[1];
	}else{
		ip_srcaddr[0] = rt_npc->parseresult.ipv4_header.ip_srcaddr;
		ip_srcaddr[1] = 0;
		ip_destaddr[0] = rt_npc->parseresult.ipv4_header.ip_destaddr;
		ip_destaddr[1] = 0;
	}
	
	if(ip_srcaddr[0]==rt_com->tcp_info->client_ip[0] && ip_srcaddr[1]==rt_com->tcp_info->client_ip[1] && 
		rt_npc->parseresult.tcp_header.source_port==(u_short)rt_com->tcp_info->client_port
		)
	{
		/* 客户端IP和端口匹配上了 */
		if(ip_destaddr[0]==rt_com->tcp_info->oracle_server_ip[0] && ip_destaddr[1]==rt_com->tcp_info->oracle_server_ip[1] &&
			rt_npc->parseresult.tcp_header.dest_port==(u_short)rt_com->tcp_info->oracle_server_port
			)
		{
			/* 服务器的IP和端口也匹配上了 */                        
			//direction = USER2ORA;
			rt_npc->parseresult.direction = USER2ORA;
			return 0;
		}
		else
		{
			/* 匹配错误 */
			OraNet_DumpSql("step[11.1] match direction error 1\n");
			OraNet_DumpSql("client_ip=%llu %llu  client_port=%u\n",ip_srcaddr[0],ip_srcaddr[1],rt_npc->parseresult.tcp_header.source_port);
			OraNet_DumpSql("server_ip=%llu %llu  server_port=%u\n",ip_destaddr[0],ip_destaddr[1],rt_npc->parseresult.tcp_header.dest_port);
			Npp_LogError_Format(NPP_ERROR_NETPARSER_ADDRESSERR-NPP_ERRNO_START,0,
				__FILE__,__LINE__,__FUNCTION__,
				(char*)"not expect server. we expect [%08x-%08x]:%u --> [%08x-%08x]:%u, but current socket is [%08x-%08x]:%u --> [%08x-%08x]:%u fin:%d rst:%d",
				rt_com->tcp_info->client_ip[0],rt_com->tcp_info->client_ip[1],rt_com->tcp_info->client_port,
				rt_com->tcp_info->oracle_server_ip[0],rt_com->tcp_info->oracle_server_ip[1],rt_com->tcp_info->oracle_server_port,
				ip_srcaddr[0],ip_srcaddr[1],rt_npc->parseresult.tcp_header.source_port,
				ip_destaddr[0],ip_destaddr[1],rt_npc->parseresult.tcp_header.dest_port,
				rt_npc->parseresult.tcp_header.fin,rt_npc->parseresult.tcp_header.rst);
			//continue;
			return 1;
		}
	}
	else if(ip_srcaddr[0]==rt_com->tcp_info->oracle_server_ip[0] && ip_srcaddr[1]==rt_com->tcp_info->oracle_server_ip[1] &&
		rt_npc->parseresult.tcp_header.source_port==(u_short)rt_com->tcp_info->oracle_server_port
		)
	{
		/* 服务器的IP和端口匹配上了 */
		if(ip_destaddr[0]==rt_com->tcp_info->client_ip[0] && ip_destaddr[1]==rt_com->tcp_info->client_ip[1] && 
			rt_npc->parseresult.tcp_header.dest_port==(u_short)rt_com->tcp_info->client_port
			)
		{
			/* 客户端IP和端口匹配上了 */
			//direction = ORA2USER;
			rt_npc->parseresult.direction = ORA2USER;
			return 0;
		}
		else
		{
			/* 匹配错误 */
			OraNet_DumpSql("step[11.2] match direction error 2\n");
			OraNet_DumpSql("client_ip=%llu %llu  client_port=%u\n",ip_srcaddr[0],ip_srcaddr[1],rt_npc->parseresult.tcp_header.source_port);
			OraNet_DumpSql("server_ip=%llu %llu  server_port=%u\n",ip_destaddr[0],ip_destaddr[1],rt_npc->parseresult.tcp_header.dest_port);
			Npp_LogError_Format(NPP_ERROR_NETPARSER_ADDRESSERR-NPP_ERRNO_START,0,
				__FILE__,__LINE__,__FUNCTION__,
				(char*)"not expect server. we expect [%08x-%08x]:%u --> [%08x-%08x]:%u, but current socket is [%08x-%08x]:%u --> [%08x-%08x]:%u fin:%d rst:%d",
				rt_com->tcp_info->client_ip[0],rt_com->tcp_info->client_ip[1],rt_com->tcp_info->client_port,
				rt_com->tcp_info->oracle_server_ip[0],rt_com->tcp_info->oracle_server_ip[1],rt_com->tcp_info->oracle_server_port,
				ip_srcaddr[0],ip_srcaddr[1],rt_npc->parseresult.tcp_header.source_port,
				ip_destaddr[0],ip_destaddr[1],rt_npc->parseresult.tcp_header.dest_port,
				rt_npc->parseresult.tcp_header.fin,rt_npc->parseresult.tcp_header.rst);
			//continue;
			return 1;
		}
	}
	else
	{
		/* 匹配错误 */
		OraNet_DumpSql("step[11.3] match direction error\n");
		OraNet_DumpSql("client_ip=%llu %llu  client_port=%u\n",ip_srcaddr[0],ip_srcaddr[1],rt_npc->parseresult.tcp_header.source_port);
			OraNet_DumpSql("server_ip=%llu %llu  server_port=%u\n",ip_destaddr[0],ip_destaddr[1],rt_npc->parseresult.tcp_header.dest_port);
			Npp_LogError_Format(NPP_ERROR_NETPARSER_ADDRESSERR-NPP_ERRNO_START,0,
				__FILE__,__LINE__,__FUNCTION__,
				(char*)"not expect server. we expect [%08x-%08x]:%u --> [%08x-%08x]:%u, but current socket is [%08x-%08x]:%u --> [%08x-%08x]:%u fin:%d rst:%d",
				rt_com->tcp_info->client_ip[0],rt_com->tcp_info->client_ip[1],rt_com->tcp_info->client_port,
				rt_com->tcp_info->oracle_server_ip[0],rt_com->tcp_info->oracle_server_ip[1],rt_com->tcp_info->oracle_server_port,
				ip_srcaddr[0],ip_srcaddr[1],rt_npc->parseresult.tcp_header.source_port,
				ip_destaddr[0],ip_destaddr[1],rt_npc->parseresult.tcp_header.dest_port,
				rt_npc->parseresult.tcp_header.fin,rt_npc->parseresult.tcp_header.rst);
		//continue;
		return 1;
	}
}

/*
	旁路审计的无连接会话处理,并根据配置进行会话找回处理(CONNECTREBUILD),和无SQL会话处理(ENABLE_NOSQL_SESSION)
	返回值
		1 - continue loop(失败),本函数不会返回1
		0 - 继续后面的处理(匹配成功)
*/
int NPP_UnConnectSession_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry, Npp_ProcessParam p_processParam)
{
	if(rt_npc->npc_is_connect_syn==0)
    {
		/* 之前没有创建过连接,属于无连接的会话 */
        rt_npc->npc_is_connect_syn = 1;
        /* 客户端创建连接 */
		OraNet_DumpSql("step[13.1]\n");
        OraNet_DumpSql("****************new session for no connect****************\n");
        OraNet_DumpSql("****client_ip=%u   client_port=%u****\n",rt_npc->parseresult.ipv4_header.ip_srcaddr,rt_npc->parseresult.tcp_header.source_port);
        OraNet_DumpSql("**********************************************************\n");
        /* 判断是否是已经处理过连接的进程 */
        if(rt_npc->new_connect==1)
        {
            /* 之前没有处理过，不需要理会，将rt_npc->new_connect置为0即可 */
            rt_npc->new_connect = 0;
        }
        else
        {
        }
        
#ifdef HAVE_CHERRY
        if(__ORA_SESSION->syncd_session)
        	__ORA_SESSION->help_session_state = DBFW_SESSION_STATE_NORMAL;  /* 20151119 guoxw 同步的会话 */
        else
        	__ORA_SESSION->help_session_state = DBFW_SESSION_STATE_NOCONNECT; /* 设置为无连接会话状态 */
#else
        __ORA_SESSION->help_session_state = DBFW_SESSION_STATE_NOCONNECT; /* 设置为无连接会话状态 */
#endif
    
        NPP_SetSessionForHandlePcap(__ORA_SESSION); /* 可能已经进行了无连接会话协议的智能识别，但结果未必是正确的 */
/* 下面是会话找回的处理逻辑，通过编译参数来启用 */
#ifdef CONNECTREBUILD
		// TODO: 据说该逻辑已废弃，暂时不支持ipv6
		OraNet_DumpSql("step[13.2] enter CONNECTREBUILD\n");
		rt_npc->ip_port_key_find = Npp_DrawBackSessionInfo_ForUnconnSession(
										rt_npc->parseresult.ipv4_header.ip_destaddr,
										rt_npc->parseresult.tcp_header.dest_port,
										rt_npc->parseresult.ipv4_header.ip_srcaddr,
										rt_npc->parseresult.tcp_header.source_port
										);

        /* 对于无连接会话，需要进行tlog处理 */
        /* 生成连接记录 */
		if(rt_npc->ip_port_key_find ==0)
		{
		}
		else
		{
		}
#else	/* CONNECTREBUILD */
/* 没有定义会话找回逻辑 */
        /* 下面的tlog数据不一定会真正的写入,与ora_session->help_tlog_sessionflag标记有关 */
#endif	/* CONNECTREBUILD */
    }
	return 0;
}

/*
	检查丢包和乱序包，并进行乱序包重排序处理
	返回值
		1 - continue loop(失败),本函数不会返回1
		0 - 继续后面的处理(匹配成功)
*/
int NPP_CheckAndProcess_LoseOrReorderPack_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	u_int	direction = 0;				/* 通讯的方向 */
	int ret = 0;
	int result = 0;	/* 返回结果0或1 */
	direction = rt_npc->parseresult.direction;
#ifdef NEW_TCP_REORDER

	if(__NPP_ALL_CONFIG->capbuf_id == 2)
	{
		rt_npc->tcp_ordercheck_result = DBFW_TCPPACKAGE_NORMAL;
		rt_npc->tcpsecquence_error_flag = 0;
		ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,direction,rt_com->alive_time);
		result = 0; /* 继续后面的处理 */
		return result;
	}
	
	/* 新乱序包处理算法，不需要区分通讯包方向 */
	rt_npc->tcp_ordercheck_result = Dbfw_TcpReorder_CheckPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,direction,rt_com->alive_time,1);
	/* 性能测试点2.3 持续1.3 CPU */
	//continue;
	switch (rt_npc->tcp_ordercheck_result)
	{
		case DBFW_TCPPACKAGE_NORMAL:    /* 正常的通讯包 */
			rt_npc->tcpsecquence_error_flag = 0;
			if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat == 1 && __ORA_SESSION->enc_store_pack == 0)
			{
				/* 向缓存区中放包 */
				ret = Dbfw_TcpReorder_AddOutOfOrderPackToBuffer(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult);
				OraNet_DumpSql("===== kdmp_stat=1 add out of order ret = %d\n",ret);
				result = 1;
			}
			else if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat == 2 && __ORA_SESSION->enc_store_pack == 0)
			{
				/* 从乱序中拿包 */
				OraNet_DumpSql("rt_npc->new_tcpreorder_buffer->out_of_order_buff->element_count:%d\n",rt_npc->new_tcpreorder_buffer.out_of_order_buff->element_count);
				ret = Dbfw_TcpReorder_AddOutOfOrderPackToBuffer(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult);
				/* 从乱序缓冲区中获取第一个通讯包 */
				ret = Dbfw_TcpReorder_UseFirstOutOfReorderPack(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult);
				if(ret>0)
				{
                    OraNet_DumpSql("step[14.20] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_UseFirstOutOfReorderPack] match ok,"
                                   "begin parse, [sec=%u , ack=%u, size=%u, direction = %s]\n"
                                   , rt_npc->parseresult.tcp_header.sequence, rt_npc->parseresult.tcp_header.acknowledge
                                   , rt_npc->parseresult.data_size, (rt_npc->parseresult.direction == USER2ORA ? "Request" : "Response"));
					/* 成功,使用获取的第一个通讯包作为新的“开始” */
					OraNet_DumpSql("\n");
					rt_npc->tcpsecquence_error_flag = 0;
					ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,rt_npc->parseresult.direction,rt_com->alive_time);
					direction = rt_npc->parseresult.direction;
					//__ORA_SESSION->tamper_data_addr = NULL;
					result = 0;	/* 继续后面的处理 */
				}
				else
				{
					/* 获取第一个通讯包失败，重新开始下一轮解析 */
					//continue;
					//result = 1;	/* 进入下一轮 */
					__ORA_SESSION->enc_store_pack = 1;
					ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,direction,rt_com->alive_time);
					result = 0;	/* 继续后面的处理 */
				}

				OraNet_DumpSql("===== kdmp_stat=2 get out of order ret = %d\n",ret);
				//result = 0;	/* 继续后面的处理 */
			}
			else
			{
				//OraNet_DumpSql("step[14.1] [NEW_TCP_REORDER:USER->ORA] Normal \n");
				ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,direction,rt_com->alive_time);
				result = 0;	/* 继续后面的处理 */
			}
			break;
		case DBFW_TCPPACKAGE_REPLAY:    /* TCP Replay */
			if(direction==USER2ORA)
				OraNet_DumpSql("step[14.2] [NEW_TCP_REORDER:USER->ORA] TCP Replay \n");
			else
				OraNet_DumpSql("step[14.3] [NEW_TCP_REORDER:ORA->USER] TCP Replay \n");
			/* 清理乱序缓冲区的全部数据 */
			ret = Dbfw_TcpReorder_ResetAll(&rt_npc->new_tcpreorder_buffer);                        
			/* 重置乱序缓冲区数据 */
			ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,direction,rt_com->alive_time);
			rt_npc->new_tcpreorder_buffer.tcp_replay_flag = 1;
			result = 0;	/* 继续后面的处理 */
			break;
		case DBFW_TCPPACKAGE_RETRANSMISSION:    /* 重传包 */
			if(direction==USER2ORA)
				OraNet_DumpSql("step[14.4] [NEW_TCP_REORDER:USER->ORA] TCP Retransmission \n");
			else
				OraNet_DumpSql("step[14.5] [NEW_TCP_REORDER:ORA->USER] TCP Retransmission \n");
#ifdef HAVE_CHERRY
			if(__NPP_ALL_CONFIG->start_for_transparent==1)
			{
				/* 启动方式为DPDK全透明网桥时 */
				if(rt_npc->parseresult.tcp_header.sequence==__ORA_SESSION->retransmission_sequence_c2s)
				{
					/* 与上次重传的包的secquence是一样的，将计数值加1 */
					__ORA_SESSION->retransmission_count_c2s++;
				}
				else
				{
					/* 与上次重传的包的secquence不一样，重置 */
					__ORA_SESSION->retransmission_sequence_c2s = rt_npc->parseresult.tcp_header.sequence;
					__ORA_SESSION->retransmission_count_c2s = 1;
				}
				if(__ORA_SESSION->retransmission_count_c2s>=DBFW_TAMPER_TIMEOUT_COUNT_FOR_RETRANSMISSION)
				{
#ifdef USE_RUNTIME_OVERRUN_OPER
					if(__NPP_ALL_CONFIG->start_for_transparent==1)        // 网桥模式
					{
						struct timeval tv;
						gettimeofday(&tv, NULL);
						rt_cherry->retrans_bypass_flag = 1;
						rt_cherry->retrans_bypass_time = tv.tv_sec * 1000000 + tv.tv_usec;
						
						u_char value[SGA_PARAM_VALUES_LEN] = {0};
						int ret;
						ret = Dbfw_Fixarray_GetValueAndValuelenInGlobal(&__SGA_FIXARRAY, S_NPP_RETRANS_BYPASS_DURA, (u_char*)value, SGA_PARAM_VALUES_LEN);
						if(ret != GET_PARAM_ERROR)
							rt_cherry->retrans_bypass_dura = atoi((char*)value);
						else
							rt_cherry->retrans_bypass_dura = 0;
						
						__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->retrans_pkt, 1);
						/* 去掉该日志，郑州教育局的时候产生该日志，占用大量IO */
						//Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"get one retransmit packet, will bypass in %d seconds.", rt_cherry->retrans_bypass_dura);
					}
#endif					
					/* 超过了代表超时的重传次数,发送超时处理请求(无论是否有需要发送的通讯包) */
					/* 发送正常的通讯包 */
					Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_TIMEOUT);
				}
			}
#endif  /* HAVE_CHERRY */
			//continue;   /* 进入下一轮 */
			if(true == __NPP_TCPREPLAY_SWITCH)
            {
			    result = 0;
            }
			else
            {
                result = 1;    /* 进入下一轮 */
            }
			break;
		case DBFW_TCPPACKAGE_KEEPALIVE:     /* KeepAlive包 */
			if(direction==USER2ORA)
				OraNet_DumpSql("step[14.6] [NEW_TCP_REORDER:USER->ORA] KeepAlive \n");
			else
				OraNet_DumpSql("step[14.7] [NEW_TCP_REORDER:ORA->USER] KeepAlive \n");
			//continue;
			result = 1;	/* 进入下一轮 */
			break;
		case DBFW_TCPPACKAGE_ACK:           /* ACK包 */
			if(direction==USER2ORA)
				OraNet_DumpSql("step[14.8] [NEW_TCP_REORDER:USER->ORA] ACK \n");
			else
				OraNet_DumpSql("step[14.9] [NEW_TCP_REORDER:ORA->USER] ACK \n");
			//continue;
			result = 1;	/* 进入下一轮 */
			break;
		case DBFW_TCPPACKAGE_LOSS:          /* 丢包啦 */
			if(direction==USER2ORA)
			{
				OraNet_DumpSql("step[14.10] [NEW_TCP_REORDER:USER->ORA][%d->%d] packet is missing \n",rt_npc->parseresult.tcp_header.source_port,rt_npc->parseresult.tcp_header.dest_port);
			}
			else
			{
				OraNet_DumpSql("step[14.11] [NEW_TCP_REORDER:ORA->USER][%d->%d] packet is missing \n",rt_npc->parseresult.tcp_header.source_port,rt_npc->parseresult.tcp_header.dest_port);
			}
			OraNet_DumpSql("\t sequence=%u    acknowledge=%u    data_size=%d\n",
							rt_npc->parseresult.tcp_header.sequence,rt_npc->parseresult.tcp_header.acknowledge,rt_npc->parseresult.data_size);
			/* 
				丢包处理 ：
				如果发生丢包，则将session下所有的stmt都要释放
				清理当前TCP数据，重新从乱序缓冲区中取出第一个通讯包作为新的开始
			*/
			Ora_ClearTcpPackageBuffer(rt_com->tcp_info);
			ClearSession_ForLosePack(__ORA_SESSION);
			rt_npc->isReleaseAllStmtForNpcLossPack_flag = 1;
			if(__ORA_SESSION)
			{
				__ORA_SESSION->loss_count ++ ;
			}
			/* 修复天翼爱音乐现场出现的MySQL丢包引起的SGA乱问题 */
			if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL || __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG)
			{
				if(MYSQL_LoginOver(__ORA_SESSION)==0)
				{
					/* 没有登录完成，需要按照无连接会话处理 */
					OraNet_DumpSql("step[14.12] NPP_SetSessionForHandlePcap for mysql not login\n");
					NPP_SetSessionForHandlePcap(__ORA_SESSION);
				}
			}
			//Dbfw_TcpReorder_GetNextReorderPack(&rt_npc->new_tcpreorder_buffer,&out_buf_parseresult_tmp);

			/* 
				fix bug : 福彩现场包fucai_48269.cap 的丢语句问题(预期554条)
				丢包后:
				1:先将当前通讯包加入到乱序缓冲区中，因为当前通讯包可能是缓冲区中最“前”的通讯包
				2:从缓冲区中取出第一个通讯包作为丢包后的第一个处理的通讯包
			*/
			/* 将乱序包加入到乱序包缓冲区(强制填充) */
			ret = Dbfw_TcpReorder_AddOutOfOrderPackToBuffer(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,1);
			/* 从乱序缓冲区中获取第一个通讯包 */
			ret = Dbfw_TcpReorder_UseFirstOutOfReorderPack(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult);
			if(ret>0)
			{
				/* 成功,使用获取的第一个通讯包作为新的“开始” */
				OraNet_DumpSql("step[14.13] [DBFW_TCPPACKAGE_LOSS:Dbfw_TcpReorder_UseFirstOutOfReorderPack] have match pack\n");
                OraNet_DumpSql("step[14.20] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_UseFirstOutOfReorderPack] match ok,"
                               "begin parse, [sec=%u , ack=%u, size=%u, direction = %s]\n"
                               , rt_npc->parseresult.tcp_header.sequence, rt_npc->parseresult.tcp_header.acknowledge
                               , rt_npc->parseresult.data_size, (rt_npc->parseresult.direction == USER2ORA ? "Request" : "Response"));
				rt_npc->tcpsecquence_error_flag = 0;
				ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,rt_npc->parseresult.direction,rt_com->alive_time);
				direction = rt_npc->parseresult.direction;
				__ORA_SESSION->tamper_data_addr = NULL;
				result = 0;	/* 继续后面的处理 */
			}
			else
			{
				/* 获取第一个通讯包失败，重新开始下一轮解析 */
				//continue;
				result = 1;	/* 进入下一轮 */
			}
			/* 这里不能使用清理包乱序缓冲区和所有运行时数据，然后重新开始 */			
			break;
		case DBFW_TCPPACKAGE_OUTOFORDER:    /* 乱序了 */
			if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat == 1)
			{
				/* 向缓存区中放包 */
				ret = Dbfw_TcpReorder_AddOutOfOrderPackToBuffer(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult);
				OraNet_DumpSql("===== kdmp_stat=1 add out of order ret = %d\n",ret);
				result = 1;
			}
			else if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat == 2)
			{
				/* 从乱序中拿包 */
				ret = Dbfw_TcpReorder_AddOutOfOrderPackToBuffer(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult);
				/* 从乱序缓冲区中获取第一个通讯包 */
				ret = Dbfw_TcpReorder_UseFirstOutOfReorderPack(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult);
				if(ret>0)
				{
					/* 成功,使用获取的第一个通讯包作为新的“开始” */
					OraNet_DumpSql("\n");
                    OraNet_DumpSql("step[14.20] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_UseFirstOutOfReorderPack] match ok,"
                                   "begin parse, [sec=%u , ack=%u, size=%u, direction = %s]\n"
                                   , rt_npc->parseresult.tcp_header.sequence, rt_npc->parseresult.tcp_header.acknowledge
                                   , rt_npc->parseresult.data_size, (rt_npc->parseresult.direction == USER2ORA ? "Request" : "Response"));
					rt_npc->tcpsecquence_error_flag = 0;
					ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,rt_npc->parseresult.direction,rt_com->alive_time);
					direction = rt_npc->parseresult.direction;
					__ORA_SESSION->tamper_data_addr = NULL;
					result = 0;	/* 继续后面的处理 */
				}
				else
				{
					/* 获取第一个通讯包失败，重新开始下一轮解析 */
					//continue;
					result = 1;	/* 进入下一轮 */
				}

				OraNet_DumpSql("===== kdmp_stat=2 get out of order ret = %d\n",ret);
				//result = 0;	/* 继续后面的处理 */
			}
			else
			{
				if(direction==USER2ORA)
					OraNet_DumpSql("step[14.14] [NEW_TCP_REORDER:USER->ORA] out of order[sequence=%u,ack=%u,data_size=%u] \n",rt_npc->parseresult.tcp_header.sequence,rt_npc->parseresult.tcp_header.acknowledge,rt_npc->parseresult.data_size);
				else
					OraNet_DumpSql("step[14.15] [NEW_TCP_REORDER:ORA->USER] out of order[sequence=%u,ack=%u,data_size=%u] \n",rt_npc->parseresult.tcp_header.sequence,rt_npc->parseresult.tcp_header.acknowledge,rt_npc->parseresult.data_size);
				rt_npc->tcpsecquence_error_flag = 1;
				/* 将乱序包加入到乱序包缓冲区 */
				ret = Dbfw_TcpReorder_AddOutOfOrderPackToBuffer(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult);
				if(ret==-1)
				{
					/* new_tcpreorder_buffer空间满了，理论不会进入本逻辑,按照丢包处理 */
					OraNet_DumpSql("step[14.16] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_AddOutOfOrderPackToBuffer] ret=%d\n",ret);
					/* 
						丢包处理 ：
						如果发生丢包，则将session下所有的stmt都要释放
						清理当前TCP数据，重新从乱序缓冲区中取出第一个通讯包作为新的开始
					*/
				
					if(__ORA_SESSION)
					{
						__ORA_SESSION->loss_count ++ ;
					}
					Ora_ClearTcpPackageBuffer(rt_com->tcp_info);
					ClearSession_ForLosePack(__ORA_SESSION);
					rt_npc->isReleaseAllStmtForNpcLossPack_flag = 1;
					/* 修复天翼爱音乐现场出现的MySQL丢包引起的SGA乱问题 */
					if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL || __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG)
					{
						if(MYSQL_LoginOver(__ORA_SESSION)==0)
						{
							/* 没有登录完成，需要按照无连接会话处理 */
							OraNet_DumpSql("step[14.17] NPP_SetSessionForHandlePcap for mysql not login\n");
							NPP_SetSessionForHandlePcap(__ORA_SESSION);
						}
					}
					/* 
						fix bug : 福彩现场包fucai_48269.cap 的丢语句问题(预期554条)
						丢包后:
						1:先将当前通讯包加入到乱序缓冲区中，因为当前通讯包可能是缓冲区中最“前”的通讯包
						2:从缓冲区中取出第一个通讯包作为丢包后的第一个处理的通讯包
					*/
					/* 将乱序包加入到乱序包缓冲区(强制填充) */
					ret = Dbfw_TcpReorder_AddOutOfOrderPackToBuffer(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,1);
					/* 从乱序缓冲区中获取第一个通讯包 */
					ret = Dbfw_TcpReorder_UseFirstOutOfReorderPack(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult);
					if(ret>0)
					{
						/* 成功,使用获取的第一个通讯包作为新的“开始” */
                        OraNet_DumpSql("step[14.20] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_UseFirstOutOfReorderPack]  ok,"
                                       "begin parse, [sec=%u , ack=%u, size=%u, direction = %s]\n"
                                       , rt_npc->parseresult.tcp_header.sequence, rt_npc->parseresult.tcp_header.acknowledge
                                       , rt_npc->parseresult.data_size, (rt_npc->parseresult.direction == USER2ORA ? "Request" : "Response"));
						rt_npc->tcpsecquence_error_flag = 0;
						ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,rt_npc->parseresult.direction,rt_com->alive_time);
						direction = rt_npc->parseresult.direction;
						__ORA_SESSION->tamper_data_addr = NULL;
						result = 0;	/* 继续后面的处理 */
					}
					else
					{
						/* 获取第一个通讯包失败，重新开始下一轮解析 */
						//continue;
						result = 1;	/* 进入下一轮 */
					}
				}
				else
				{
					/* 添加乱序包成功 */
					OraNet_DumpSql("step[14.19] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_AddOutOfOrderPackToBuffer] OK, ret=%d\n",ret);
					/* 
						从乱序缓冲区中查找下一个符合的通讯包
					*/
					do 
					{
						rt_npc->tcp_nextorder_result = Dbfw_TcpReorder_GetNextReorderPack(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult);

						if(rt_npc->tcp_nextorder_result==0)
						{
							/* 没有匹配的，重新开始 */
							break;  /* 从这里离开 */
						}
						else if(rt_npc->tcp_nextorder_result==-1)
						{
							/* 没有匹配的，重新开始 */
							//OraNet_DumpSql("[DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_GetNextReorderPack] no match pack, continue\n");
							continue;
						}
						else if(rt_npc->tcp_nextorder_result==1)
						{
                            OraNet_DumpSql("step[14.20] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_GetNextReorderPack] match ok,"
                                           "begin parse, [sec=%u , ack=%u, size=%u, direction = %s]\n"
                                           , rt_npc->parseresult.tcp_header.sequence, rt_npc->parseresult.tcp_header.acknowledge
                                           , rt_npc->parseresult.data_size, (rt_npc->parseresult.direction == USER2ORA ? "Request" : "Response"));
							/* 找到匹配的 */
							break;
						}
					} while (1==1);
					if(rt_npc->tcp_nextorder_result==0 || rt_npc->tcp_nextorder_result==-1)
					{
						/* 没有匹配的，重新开始 */
						OraNet_DumpSql("step[14.20] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_GetNextReorderPack] no match pack, continue\n");
						//continue;
						result = 1;	/* 进入下一轮 */
					}
					else if(rt_npc->tcp_nextorder_result==1)
					{
						/* 找到匹配的 */
						OraNet_DumpSql("step[14.21] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_GetNextReorderPack] have match pack\n");
						rt_npc->tcpsecquence_error_flag = 0;
						ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,rt_npc->parseresult.direction,rt_com->alive_time);
						direction = rt_npc->parseresult.direction;
						__ORA_SESSION->tamper_data_addr = NULL;
						result = 0;	/* 继续后面的处理 */
					}
					else
					{
						OraNet_DumpSql("step[14.22] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_GetNextReorderPack] unknown continue\n");
						//continue;
						result = 1;	/* 进入下一轮 */
					}
				}
			}
			break;
		default:
			if(direction==USER2ORA)
				OraNet_DumpSql("step[14.23] [NEW_TCP_REORDER:USER->ORA] --ATTENTION-- default \n");
			else
				OraNet_DumpSql("step[14.24] [NEW_TCP_REORDER:ORA->USER] --ATTENTION-- default \n");
			//continue;   /* 进入下一轮 */
			result = 1;	/* 进入下一轮 */
			break;
	}
#else   /* NEW_TCP_REORDER */
	/* 这里删除了已经不再使用的HAVE_TCP_RECORDER处理程序,改为记录异常并丢弃包 */
	OraNet_DumpSql("step[14.25] error code for HAVE_TCP_RECORDER\n");
	Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"error code for HAVE_TCP_RECORDER");
	//continue;	/* 进入下一轮 */
	result = 1;	/* 进入下一轮 */
#endif  /* NEW_TCP_REORDER */
	return result;
}

int NPP_SqlProcess(Npp_RewriteNetPacket *rewrite_packet,OraNet8_Session *ora_session,int direction)
{
    int ret = 0;
    int parser_result = 0;
	/* SqlProcStmt==NULL 这段代码不能放在spy_field_result=0 之后，因为opt syp之后，如果报错
		需要根据spy_field_result值来判读单表取逻辑
	 */
/* 没有需要处理的语句，直接退出 */
    if (ora_session->SqlProcStmt == NULL)
    {
        return ret;
    }
#ifdef HAVE_SQL_SPY
    /* 脱敏用于spy时取表结构的标记，新语句时清理 ,db2的时候spy语句也会进行process，其实不应该，暂时先不处理了*/
	/* db2的已经处理了，不会进入两次了，但是判断逻辑还保留吧，理论上没有影响 */
	if(__ORA_SESSION->sessCommon.dialect == DBFW_DBTYPE_DB2)
	{
		if(__ORA_SESSION->is_spy_flag != 1)
    		ora_session->spy_field_result = 0;
	}
	else
	{
		ora_session->spy_field_result = 0;
	}
#endif
    
    ora_session->SqlProcStmt->sqlprocess_flag = 0;

    /*为了解决编译不大面积添加新的全局变量，在此初始化模糊化的SGA地址，供SQL处理函数使用*/

    if (__NPP_ALL_CONFIG->s_sqlfuzzy_in_swtich == 1)
    {
        sqlprocess_option_switch_on(&ora_session->sqlProcess, SQLPROC_OPT_SQLFUZZY_IN);
    }
    else
        /*重新加载是否合并IN参数列表的配置*/
    {
        sqlprocess_option_switch_off(&ora_session->sqlProcess, SQLPROC_OPT_SQLFUZZY_IN);
    }
    /*重新加载是否重写sql server双引号里的内容*/
    if (__NPP_ALL_CONFIG->s_sql_rwrite_param == 1)
    {
        sqlprocess_option_switch_on(&ora_session->sqlProcess, SQLPROC_OPT_DQ_REWRITE);
    }
    else
    {
        sqlprocess_option_switch_off(&ora_session->sqlProcess, SQLPROC_OPT_DQ_REWRITE);
    }
    /*重新加载是否对象名大小写敏感*/
    if (__NPP_ALL_CONFIG->s_sql_sensitive == 1)
    {
        sqlprocess_option_switch_on(&ora_session->sqlProcess, SQLPROC_OPT_SENSITIVE);
    }
    else
    {
        sqlprocess_option_switch_off(&ora_session->sqlProcess, SQLPROC_OPT_SENSITIVE);
    }
    if (__NPP_ALL_CONFIG->s_sqlfuzzy_switch == 1)
    {
        sqlprocess_option_switch_on(&ora_session->sqlProcess, SQLPROC_OPT_SQLFUZZY);
        if (NULL == ora_session->sqlProcess.pSQLFuzBuff)
        {
            ora_session->sqlProcess.pSQLFuzBuff = (void *) ZMalloc(sizeof(Dbfw_Sga_SqlFuzzyBuf));
            ret = Dbfw_Sga_SQLFuzzy_AttachBuff(&__SGA_FIXARRAY
                                               , (pDbfw_Sga_SqlFuzzyBuf) ora_session->sqlProcess.pSQLFuzBuff);
            if (ret < 0)
            {
                sqlprocess_option_switch_off(&ora_session->sqlProcess, SQLPROC_OPT_SQLFUZZY);
                if (NULL != ora_session->sqlProcess.pSQLFuzBuff)
                {
                    ZFree(ora_session->sqlProcess.pSQLFuzBuff);
                    ora_session->sqlProcess.pSQLFuzBuff = NULL;
                }
            }
        }
    }
    else
    {
        sqlprocess_option_switch_off(&ora_session->sqlProcess, SQLPROC_OPT_SQLFUZZY);
        if (NULL != ora_session->sqlProcess.pSQLFuzBuff)
        {
            Dbfw_Sga_SQLFuzzy_DetachBuff((pDbfw_Sga_SqlFuzzyBuf) ora_session->sqlProcess.pSQLFuzBuff);
            ZFree(ora_session->sqlProcess.pSQLFuzBuff);
            ora_session->sqlProcess.pSQLFuzBuff = NULL;
        }
    }
    if (__NPP_ALL_CONFIG->s_url_switch == 1)
    {
        sqlprocess_option_switch_on(&ora_session->sqlProcess, SQLPROC_OPT_URL);
        if (NULL == ora_session->sqlProcess.pURLBuff)
        {
            ora_session->sqlProcess.pURLBuff = (void *) ZMalloc(sizeof(Dbfw_Sga_UrlBuff));
            ret = Dbfw_Sga_Url_AttachBuff(&__SGA_FIXARRAY, (pDbfw_Sga_UrlBuff) ora_session->sqlProcess.pURLBuff);
            if (ret < 0)
            {
                sqlprocess_option_switch_off(&ora_session->sqlProcess, SQLPROC_OPT_URL);
                if (NULL != ora_session->sqlProcess.pURLBuff)
                {
                    ZFree(ora_session->sqlProcess.pURLBuff);
                    ora_session->sqlProcess.pURLBuff = NULL;
                }
            }
        }
    }
    else
    {
        sqlprocess_option_switch_off(&ora_session->sqlProcess, SQLPROC_OPT_URL);
        if (NULL != ora_session->sqlProcess.pURLBuff)
        {
            Dbfw_Sga_Url_DetachBuff((pDbfw_Sga_UrlBuff) ora_session->sqlProcess.pURLBuff);
            ZFree(ora_session->sqlProcess.pURLBuff);
            ora_session->sqlProcess.pURLBuff = NULL;
        }
    }

    if (__NPP_ALL_CONFIG->s_obj_switch == 1)
    {
        sqlprocess_option_switch_on(&ora_session->sqlProcess, SQLPROC_OPT_OBJECTS);
        if (NULL == ora_session->sqlProcess.pOBJBuff)
        {
            ora_session->sqlProcess.pOBJBuff = (void *) ZMalloc(sizeof(Dbfw_Sga_ObjectsBuff));
            ret = Dbfw_Sga_Obj_AttachBuff(&__SGA_FIXARRAY, (pDbfw_Sga_ObjectsBuff) ora_session->sqlProcess.pOBJBuff);
            if (ret < 0)
            {
                sqlprocess_option_switch_off(&ora_session->sqlProcess, SQLPROC_OPT_OBJECTS);
                if (NULL != ora_session->sqlProcess.pOBJBuff)
                {
                    ZFree(ora_session->sqlProcess.pOBJBuff);
                    ora_session->sqlProcess.pOBJBuff = NULL;
                }
            }
        }
    }
    else
    {
        sqlprocess_option_switch_off(&ora_session->sqlProcess, SQLPROC_OPT_OBJECTS);
        if (NULL != ora_session->sqlProcess.pOBJBuff)
        {
            Dbfw_Sga_Obj_DetachBuff((pDbfw_Sga_ObjectsBuff) ora_session->sqlProcess.pOBJBuff);
            ZFree(ora_session->sqlProcess.pOBJBuff);
            ora_session->sqlProcess.pOBJBuff = NULL;
        }
    }
    /*重新加载是否开启语法树开关*/
    if (__NPP_ALL_CONFIG->s_sql_parser_tree == 1)
    {
        ora_session->filter_sesscommon.sql_parser_tree = 1;
    }
    else
    {
         ora_session->filter_sesscommon.sql_parser_tree = 0;
    }

    /*会话成功解析到第一条语句，认为是成功会话，需要记录语句*/
    /*Attention ： 如果更改prepare语句的规则校验未知，改为prepare时校验，需要更改该判定条件。
        只有prepare语句时，仍然不能认为是会话登陆成功*/
    if (__NPP_ALL_CONFIG->s_prepare_audit_switch == 1)
    {
        ora_session->SqlProcStmt->un_write_sql_flag = 0;
    }
    /* 在做语句处理之前一定要初始化session，来决定做登陆校验以及赋值方言和会话信息，
        此时不一定需要生成session类型的tlog */
    if (ora_session->help_login_state == DBLOGIN_NOLOG)
    {
        NPP_DoActionForLoginOk(ora_session);
    }
#ifdef ENABLE_HRPC
    if ((ora_session->SqlProcStmt->tb_name.value && ora_session->SqlProcStmt->tb_name.length > 0)
        && (ora_session->sessCommon.dialect == DBFW_DBTYPE_HRPC))
    {
        ora_session->sqlProcess.table_name = &ora_session->SqlProcStmt->tb_name;
    }
#endif
#ifdef ENABLE_SENTRY
    if ((ora_session->SqlProcStmt->sentry_tbname.value && ora_session->SqlProcStmt->sentry_tbname.length > 0)
        && (ora_session->sessCommon.dialect == DBFW_DBTYPE_SENTRY))
    {
        ora_session->sqlProcess.table_name = &ora_session->SqlProcStmt->sentry_tbname;
    }
#endif
#ifdef ENABLE_REDIS
    if ((ora_session->SqlProcStmt->redis_tabname.str && ora_session->SqlProcStmt->redis_tabname.length > 0)
        && (ora_session->sessCommon.dialect == DBFW_DBTYPE_REDIS))
    {
        ora_session->sqlProcess.item_name = &ora_session->SqlProcStmt->redis_tabname;
    }
    if ((ora_session->SqlProcStmt->redis_fidname.str && ora_session->SqlProcStmt->redis_fidname.length > 0)
        && (ora_session->sessCommon.dialect == DBFW_DBTYPE_REDIS))
    {
        ora_session->sqlProcess.field_name = &ora_session->SqlProcStmt->redis_fidname;
    }
#endif
#ifdef ENABLE_ES
    if ((ora_session->SqlProcStmt->es_tabname.str && ora_session->SqlProcStmt->es_tabname.length > 0)
        && (ora_session->sessCommon.dialect == DBFW_DBTYPE_ES))
    {
        ora_session->sqlProcess.item_name = &ora_session->SqlProcStmt->es_tabname;
    }
#endif

    if ((ora_session->sessCommon.dialect != DBFW_DBTYPE_ORACLE)
        && (ora_session->sessCommon.dialect != DBFW_DBTYPE_SYBASE)
        && (ora_session->sessCommon.dialect != DBFW_DBTYPE_MSSQL)
        && (ora_session->sessCommon.dialect != DBFW_DBTYPE_TERADATA)
		&& (ora_session->sessCommon.dialect != DBFW_DBTYPE_HANA)
		&& (ora_session->sessCommon.dialect != DBFW_DBTYPE_GAUSSDBT))
    {
        /*其它数据库，重新生成本次的bind参数*/
        if (ora_session->SqlProcStmt->stmtCommon.bind_param.header.count > 0)
        {
            /*2017-08-15,alter by liyanjun,将动态字符串的重新释放重新初始化改为reset*/
            Dbfw_TypedVarData_Dyna_Reset(&ora_session->SqlProcStmt->stmtCommon.bind_param);
        }
        if (ora_session->SqlProcStmt->cmd_035e.cmd035e_header.param_count > 0 &&
            ora_session->SqlProcStmt->cmd_035e.cmd035e_data.paramvalue.row_num > 0 &&
            ora_session->SqlProcStmt->cmd_035e.cmd035e_data.paramvalue.row_data != NULL
                )
        {
            for (int i = 0; i < ora_session->SqlProcStmt->cmd_035e.cmd035e_header.param_count; i++)
            {
                if (i >= ORANET_MAX_BINDCOLUMN)
                {
                    Dbfw_TypedVarData_Dyna_Append(&ora_session->SqlProcStmt->stmtCommon.bind_param, NULL, 0
                                                  , LOG_DATA_PREPARE_PARAM, 1);
                    continue;
                }

                if (ora_session->SqlProcStmt->cmd_035e.cmd035e_data.paramvalue.row_data[i]->type_data == NULL)
                {
                    Dbfw_TypedVarData_Dyna_Append(&ora_session->SqlProcStmt->stmtCommon.bind_param, NULL, 0
                                                  , LOG_DATA_PREPARE_PARAM, 1);
                }
                else
                {
                    Dbfw_TypedVarData_Dyna_Append(&ora_session->SqlProcStmt->stmtCommon.bind_param
                                                  , ora_session->SqlProcStmt->cmd_035e.cmd035e_data.paramvalue.row_data[i]->type_data
                                                  , strlen(
                                    (const char *) ora_session->SqlProcStmt->cmd_035e.cmd035e_data.paramvalue.row_data[i]->type_data)
                                                  , LOG_DATA_PREPARE_PARAM, 1);
                }
            }
        }
    }
    ora_session->SqlProcStmt->stmtCommon.is_prepare = ora_session->SqlProcStmt->un_write_sql_flag;
    ora_session->SqlProcStmt->stmtCommon.captime_stamp = Npp_GetEpochTime_MicroSecond();
    //Dbfw_Fixarray_GetEpochTime_MicroSecond_FromSga(&__SGA_FIXARRAY, &ora_session->SqlProcStmt->stmtCommon.captime_stamp);
    if (ora_session->logsequence_login == 0)
    {
#ifdef ENABLE_CLUSTER
        ora_session->logsequence_login = Npp_GetNextLogsecquence_Bulk(
            ora_session->sqlProcess.pSQLTBuff
            ,__NPP_ALL_CONFIG->range_for_prefix
            ,__NPP_ALL_CONFIG->prefix_for_logSequence);
#else
        ora_session->logsequence_login = Npp_GetNextLogsecquence_Bulk(ora_session->sqlProcess.pSQLTBuff);
#endif
    }
#ifdef ENABLE_CLUSTER
    ora_session->SqlProcStmt->stmtCommon.logsecquence = Npp_GetNextLogsecquence_Bulk(
        ora_session->sqlProcess.pSQLTBuff
        ,__NPP_ALL_CONFIG->range_for_prefix
        ,__NPP_ALL_CONFIG->prefix_for_logSequence);
#else
    ora_session->SqlProcStmt->stmtCommon.logsecquence = Npp_GetNextLogsecquence_Bulk(ora_session->sqlProcess.pSQLTBuff);
#endif
    /*调用语句处理逻辑*/
    if (ora_session->SqlProcStmt->sqlprocess_flag == 0)    /*未校验过的语句或者需要再次校验的语句*/
    {

        OraNet_DumpSql("\n+Enter NPP_SqlProcess, stmt : %p\n", ora_session->SqlProcStmt);
        ora_session->sqlProcess.stmtCommon = &(ora_session->SqlProcStmt->stmtCommon);
        ora_session->sqlProcess.sessCommon = &(ora_session->sessCommon);
        ora_session->sqlProcess.filter_sesscommon = &(ora_session->filter_sesscommon);
        ora_session->sqlProcess.filter_sqlcommon = &(ora_session->SqlProcStmt->filter_sqlcommon);
        ora_session->sqlProcess.appEvent.applogin_bufblock
                = (Bslhash_t *) ((char *) __SGA_RTBUF.data.applogin_bufblock);

        /* nosql 数据库 */
        if (ora_session->sqlProcess.sessCommon->dialect == DBFW_DBTYPE_HBASE
            || ora_session->sqlProcess.sessCommon->dialect == DBFW_DBTYPE_MONGODB)
        {

#if defined (ENABLE_HBASE) || defined(ENABLE_MONGODB)
            Npp_Convert_Nostmt2Stmt(&ora_session->sessCommon, ora_session->SqlProcStmt->nosql_stmt
                                    , &ora_session->SqlProcStmt->stmtCommon);
            ora_session->SqlProcStmt->nosql_stmt = NULL;
#endif
        }
#if defined (ENABLE_CACHEDBM) && defined(ENABLE_CACHEDB)
        if (ora_session->sqlProcess.sessCommon->dialect == DBFW_DBTYPE_CACHEDB)
        {
            if (ora_session->SqlProcStmt->cache_jbind_flag == 1)
            {
                NppProcessSQL_SetTypetoAPISingle(&ora_session->sqlProcess);
            }
            else
            {
                NppProcessSQL_SetTypetoSQLSingle(&ora_session->sqlProcess);
            }
        }
#endif
        ret = Dbfw_Process_Sql(&ora_session->sqlProcess, false);

#ifdef HAVE_SQL_MODIFY_ENGINE
        __ORA_SESSION->need_spy_count = ora_session->sqlProcess.stmtCommon->need_spy_count;
        __ORA_SESSION->mask_result = ora_session->sqlProcess.filter_sqlcommon->mask_result;
#endif
#ifdef HAVE_SQL_MODIFY_ENGINE
#ifdef DBFW_PASSWD_BRIDGE
        /* 如果开启了密码桥，则如果登陆阶段出现alter session set current_schema= 的语句需要进行名称替换 */
        OraNet_DumpSql("sqlProcess->sessCommon->dialect:%d\n",ora_session->sqlProcess.sessCommon->dialect);
        OraNet_DumpSql("ora_session->passwd_bridge.need_bridge:%d\n",ora_session->passwd_bridge.need_bridge);
        if(ora_session->sqlProcess.sessCommon->dialect == DBFW_DBTYPE_ORACLE && ora_session->passwd_bridge.need_bridge == 1)
        {
            if((ora_session->sqlProcess.stmtCommon->sqltype_1 == DBFW_SQL_ORA_ALTER) && (ora_session->sqlProcess.stmtCommon->sqltype_2 == DBFW_SQL_ORA_ALTER_SESSION))
            {
                OraNet_DumpSql("start change current_schema\n");
                int auth_cursor = 0, idx =0, idx_count = 0;
                u_char current_schema[15] = "CURRENT_SCHEMA";
                current_schema[14] = '\0';
                u_char schema_name[128] = {0};

                do
                {
                    if((auth_cursor + strlen((char*)current_schema) < ora_session->sqlProcess.stmtCommon->sql_text_ori.length) && 
                        memcmp((char*)ora_session->sqlProcess.stmtCommon->sql_text_ori.value + auth_cursor, current_schema, strlen((char*)current_schema))==0)
                    {
                        auth_cursor = auth_cursor + strlen((char*)current_schema);
                        idx_count = ora_session->sqlProcess.stmtCommon->sql_text_ori.length - auth_cursor;
                        for(idx = 0; idx < idx_count; idx++)
                        {
                            if((ora_session->sqlProcess.stmtCommon->sql_text_ori.value[auth_cursor + idx] != ' ') &&
                                (ora_session->sqlProcess.stmtCommon->sql_text_ori.value[auth_cursor + idx] != '='))
                            {
                                auth_cursor = auth_cursor + idx;
                                break;
                            }
                        }
                        memcpy(schema_name, (char*)ora_session->sqlProcess.stmtCommon->sql_text_ori.value + auth_cursor, ora_session->sqlProcess.stmtCommon->sql_text_ori.length - auth_cursor);
                        OraNet_DumpSql("current_schema:%s\n",schema_name);
                        if((strlen((char*)schema_name) != 0) && (strlen((char*)schema_name) == strlen((char*)ora_session->passwd_bridge.web_db_name)))
                        {
                            if(strcasecmp((char*)schema_name, (char*)ora_session->passwd_bridge.web_db_name) == 0)
                            {
                                /* 需要替换 */
                                ora_session->change_schema_sql_len = auth_cursor + strlen((char*)ora_session->passwd_bridge.db_name) + 5;
                                ora_session->change_schema_sql = (u_char*)ZMalloc(ora_session->change_schema_sql_len);
                                memcpy(ora_session->change_schema_sql, (char*)ora_session->sqlProcess.stmtCommon->sql_text_ori.value, auth_cursor);
                                memcpy(ora_session->change_schema_sql+ auth_cursor, (char*)ora_session->passwd_bridge.db_name, strlen((char*)ora_session->passwd_bridge.db_name));
                            }
                        }
                        break;
                    }
                    else
                    {
                        auth_cursor = auth_cursor + 1;
                        if(auth_cursor + strlen((char*)current_schema) > ora_session->sqlProcess.stmtCommon->sql_text_ori.length)
                            break;
                    }
                }while(1);
            }
        }
#endif
#endif
        /*留住sql解析的结果，用来返回前置位语句解析结果，
        避免在函数返回前宕机，出现log_sequence为空的tlog*/
        parser_result = ret;

        /* sqlserver/sybase 数据库，处理以语句形式释放的句柄，避免长时间的内存占用 */
        if (ora_session->sessCommon.dialect == DBFW_DBTYPE_SYBASE
            || ora_session->sessCommon.dialect == DBFW_DBTYPE_MSSQL)
        {
            if (ora_session->sqlProcess.wait_release_handle != 0)
            {
                OraNet8_SqlStmtData *stmt_old = NULL;
                stmt_old = (OraNet8_SqlStmtData *) ZHashGet(ora_session->stmp_table_hash
                                                            , ora_session->sqlProcess.wait_release_handle);
                if (stmt_old != NULL)
                {
                    Release_Stmt(stmt_old);
                    stmt_old = NULL;
                    ZHashDelete(ora_session->stmp_table_hash, ora_session->sqlProcess.wait_release_handle);
                }
                ora_session->sqlProcess.wait_release_handle = 0;
            }
        }
        OraNet_DumpSql("\n-Quit NPP_SqlProcess\n");
    }

    /*语句处理后，重新生成logsequence和stmtsequence和capturetime*/
    /*由于进入这里，代表语句执行一次，需要生成一条tlog*/
    u_int64 captime_stamp = 0;
    for (ora_session->SqlProcStmt->currStmtCommon = ora_session->SqlProcStmt->stmtCommon.next;
         ora_session->SqlProcStmt->currStmtCommon != NULL;
         ora_session->SqlProcStmt->currStmtCommon = ora_session->SqlProcStmt->currStmtCommon->next)
    {
        if (0 == captime_stamp)
        {
            captime_stamp = Npp_GetEpochTime_MicroSecond();
        }

#ifdef ENABLE_CLUSTER
        ora_session->SqlProcStmt->currStmtCommon->logsecquence = Npp_GetNextLogsecquence_Bulk(
            ora_session->sqlProcess.pSQLTBuff
            ,__NPP_ALL_CONFIG->range_for_prefix
            ,__NPP_ALL_CONFIG->prefix_for_logSequence);
#else
        ora_session->SqlProcStmt->currStmtCommon->logsecquence = Npp_GetNextLogsecquence_Bulk(
                ora_session->sqlProcess.pSQLTBuff);
#endif
        ++ora_session->sqlProcess.stmt_sequence;
        ora_session->SqlProcStmt->currStmtCommon->stmt_sequence = ora_session->sqlProcess.stmt_sequence;
        ora_session->SqlProcStmt->currStmtCommon->captime_stamp = captime_stamp;
        ora_session->SqlProcStmt->currStmtCommon->tlog_threat_flag = 0;
        ora_session->SqlProcStmt->currStmtCommon->record_status = RECORD_STATUS_INIT;
        ora_session->SqlProcStmt->currStmtCommon->summary_status = SUMMARY_STATUS_INIT;
        if (direction == USER2ORA)
        {
            ora_session->SqlProcStmt->currStmtCommon->cost_time = 0;
            ora_session->SqlProcStmt->currStmtCommon->total_response_time = 0;
            ora_session->SqlProcStmt->currStmtCommon->help_record_cost_time_req = 0;
            ora_session->SqlProcStmt->currStmtCommon->help_record_cost_time_resp = 0;
            ora_session->SqlProcStmt->currStmtCommon->affect_rows = 0;
            ora_session->SqlProcStmt->currStmtCommon->error_code = DBFW_ERROR_CODE_UNKOWN;
            ora_session->SqlProcStmt->currStmtCommon->row_actually = 0;
            Dbfw_TypedVarData_Release(&ora_session->SqlProcStmt->currStmtCommon->error_msg);
            /* 2017-08-15,alter by liyanjun,修改动态字符串为重用 */
            Dbfw_TypedVarData_Dyna_Reset(&ora_session->SqlProcStmt->currStmtCommon->result_value);
        }

        OraNet_DumpSql("\n+Enter NPP_SqlProcess,Sql : %s(%llu,%u,%llu,%llu), affect_rows = %u result_control = %c\n"
                       , ora_session->SqlProcStmt->currStmtCommon->sql_text.value
                       , ora_session->SqlProcStmt->currStmtCommon->outside_sqlid
                       , ora_session->SqlProcStmt->currStmtCommon->stmt_sequence
                       , ora_session->SqlProcStmt->currStmtCommon->captime_stamp
                       , ora_session->SqlProcStmt->currStmtCommon->logsecquence
                       , ora_session->SqlProcStmt->currStmtCommon->affect_rows
                       , ora_session->SqlProcStmt->currStmtCommon->result_control);
    }
    /* 为了语句模版和对象信息存在首次执行时间，且保证logsequence不冲突，要在sql处理函数调用之前先生成一次捕获时间和logsequence；
     * 但是为了保证报错的多语句整体的显示顺序在之前正常执行的单语句之后，对于多语句，要在单语句的logsequence生成之后，重新生成主语句的logsequence */
    if(ora_session->SqlProcStmt->stmtCommon.child_count > 0)
    {
        if (0 == captime_stamp)
        {
            captime_stamp = Npp_GetEpochTime_MicroSecond();
        }
        ora_session->SqlProcStmt->stmtCommon.captime_stamp = captime_stamp;
        //Dbfw_Fixarray_GetEpochTime_MicroSecond_FromSga(&__SGA_FIXARRAY, &ora_session->SqlProcStmt->stmtCommon.captime_stamp);

        ora_session->SqlProcStmt->stmtCommon.logsecquence = Npp_GetNextLogsecquence_Bulk(
                ora_session->sqlProcess.pSQLTBuff);
    }
    ++ora_session->sqlProcess.stmt_sequence;
    ora_session->SqlProcStmt->stmtCommon.stmt_sequence = ora_session->sqlProcess.stmt_sequence;
    ora_session->SqlProcStmt->stmtCommon.tlog_threat_flag = 0;
    ora_session->SqlProcStmt->stmtCommon.record_status = RECORD_STATUS_INIT;
    ora_session->SqlProcStmt->stmtCommon.summary_status = SUMMARY_STATUS_INIT;
    ora_session->SqlProcStmt->audit_result_rows = 0;
    if (ora_session->sessCommon.dialect != DBFW_DBTYPE_CACHEDB)
    {
        ora_session->SqlProcStmt->audit_result_size = 0;
    }

    if (direction == USER2ORA)
    {
        ora_session->SqlProcStmt->stmtCommon.cost_time = 0;
        ora_session->SqlProcStmt->stmtCommon.total_response_time = 0;
        ora_session->SqlProcStmt->stmtCommon.help_record_cost_time_req = 0;
        ora_session->SqlProcStmt->stmtCommon.help_record_cost_time_resp = 0;
        ora_session->SqlProcStmt->stmtCommon.affect_rows = 0;
        ora_session->SqlProcStmt->stmtCommon.error_code = DBFW_ERROR_CODE_UNKOWN;
        ora_session->SqlProcStmt->stmtCommon.row_actually = 0;
        Dbfw_TypedVarData_Release(&ora_session->SqlProcStmt->stmtCommon.error_msg);
        /* 2017-08-15,alter by liyanjun,修改动态字符串为重用 */
        Dbfw_TypedVarData_Dyna_Reset(&ora_session->SqlProcStmt->stmtCommon.result_value);
        ora_session->help_last_ack_errorno = 0;
        ora_session->help_last_ack_affectrow = 0;
    }
    OraNet_DumpSql("\n+Enter NPP_SqlProcess,Sql : %s(%llu,%u,%llu,%llu), affect_rows = %u result_control = %c\n"
                   , ora_session->SqlProcStmt->stmtCommon.sql_text.value
                   , ora_session->SqlProcStmt->stmtCommon.outside_sqlid
                   , ora_session->SqlProcStmt->stmtCommon.stmt_sequence
                   , ora_session->SqlProcStmt->stmtCommon.captime_stamp
                   , ora_session->SqlProcStmt->stmtCommon.logsecquence, ora_session->SqlProcStmt->stmtCommon.affect_rows
                   , ora_session->SqlProcStmt->stmtCommon.result_control);


    /*调用处为应答方向，说明为prepare失败补做sql处理，此时如果是多语句，只记录整体。如果存在应答方向规则，需要补做应答方向校验*/
    /*由于prepare时不做SQL处理，所以在prepare报错解析时，还没有做语句拆分，所以需要此时补记记录方式的标记，并重新做应答方向规则校验*/
    /*Attention: 由于prepare时不做SQL处理，所以在NPP_DoActionForStmtAck调用时，还没有语句对象信息，所以此时需要补掉，否则该步骤多余*/

    /*调用方向为请求方向，为多语句初始化语句处理偏移归零*/
    if (ora_session->SqlProcStmt->stmtCommon.child_count > 0)
    {
        ora_session->SqlProcStmt->currStmtCommon = ora_session->SqlProcStmt->stmtCommon.next;
        ora_session->SqlProcStmt->stmtCommon.record_mask = RECORDMASK_NOT_LOG;
        ora_session->SqlProcStmt->stmt_idx = 1;
    }
    else
    {
        ora_session->SqlProcStmt->currStmtCommon = &ora_session->SqlProcStmt->stmtCommon;
        ora_session->SqlProcStmt->stmt_idx = 0;
    }
    OraNet_DumpSql("ora_session->SqlProcStmt->stmtCommon.result_control:%d\n"
                   , ora_session->SqlProcStmt->stmtCommon.result_control);
    OraNet_DumpSql("ora_session->SqlProcStmt->stmtCommon.is_prepare:%d\n"
                   , ora_session->SqlProcStmt->stmtCommon.is_prepare);
    OraNet_DumpSql("ora_session->SqlProcStmt->un_write_sql_flag:%d\n", ora_session->SqlProcStmt->un_write_sql_flag);
    if (ora_session->SqlProcStmt->stmtCommon.result_control == DBFW_SWITCHOFF_CHAR
        && ora_session->SqlProcStmt->stmtCommon.is_prepare == 0)
    {
        rewrite_packet->is_switchoff = 1;
        rewrite_packet->packparse_result = NPP_RESULT_SWITCHOFF;
    }
    if (ora_session->SqlProcStmt->stmtCommon.result_control == DBFW_BLOCKING_THROW_CHAR
        && ora_session->SqlProcStmt->stmtCommon.is_prepare == 0)
    {
        rewrite_packet->packparse_result = NPP_RESULT_BLOCKING_THROW;
    }
    if (ora_session->filter_sesscommon.two_factor_auth_sql == 1)
    {
        ora_session->SqlProcStmt->stmtCommon.result_control = DBFW_NONE_CHAR;
    }
#ifdef HAVE_APPROVAL
    if(ora_session->filter_sesscommon.is_code_sql == 1)
    {
		if (ora_session->SqlProcStmt->stmtCommon.result_control == DBFW_BLOCKING_THROW_CHAR
        && ora_session->SqlProcStmt->stmtCommon.is_prepare == 1)
		{
			rewrite_packet->packparse_result = NPP_RESULT_BLOCKING_THROW;
		}
        ora_session->SqlProcStmt->stmtCommon.result_control = DBFW_NONE_CHAR;
        if(ora_session->sqlProcess.sessCommon->dialect == DBFW_DBTYPE_DB2)
        {
            rewrite_packet->is_switchoff = 0;
            rewrite_packet->packparse_result = NPP_RESULT_NORMAL;
        }
    }
#endif
    if (parser_result > 0)
    {
        ora_session->SqlProcStmt->sqlprocess_flag = 1;
    }

    ora_session->SqlProcStmt = NULL;
#if defined ENABLE_EXTAC_MONITOR and defined ENABLE_WHITE_IPADDR
    if(direction == USER2ORA &&  ora_session->sessCommon.white_ipaddr == 1)
    {
        dbsc_sga_extac_monitor_stmt_add();
    }
#endif
    return ret;
}

/*
	处理Oracle通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/

int NPP_HandleOraclePackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	int have_tns_data = 0;
	direction = rt_npc->parseresult.direction;
    /* Oracle通讯协议处理 */
	/* 性能测试点3,持续占用1.3~1.7CPU */
	//break;
#ifdef HAVE_CHERRY
    /* 检查是否是可篡改的通讯包，并设置会话级的可篡改通讯包标记 */
    if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper
#ifdef ENABLE_TLS  	
		&& __ORA_SESSION->tls_switch != 1 /*tls暂时不支持篡改*/ 
#endif
	)
    {
        /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
        __ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */
        /* 在这里要判断SQL语句是否已经解析完成了，如没有完成，则肯定应该是当前包中会包含SQL语句的一部分 */
    }
    else
    {
        __ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
    }
#endif

#ifdef ENABLE_TLS  	
   	//判断是否需要TLS解密
   	OraNet_DumpSql("tls_switch=%d\n",__ORA_SESSION->tls_switch);
   	if(__ORA_SESSION->tls_switch == 1)
   	{
   		rt_com->tcp_buffer_size = TLS_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);    
    //OraNet_DumpSql("step[17.1] rt_com->tcp_buffer_size=%d\n",rt_com->tcp_buffer_size);
   		have_tns_data = 0;
   		do{
   			
			rt_com->tns_pack_data = TLS_Package_PreProcess(rt_com->tcp_info,direction,(u_int*)&rt_com->tns_package_size);
			OraNet_DumpSql("rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			//协议解析		
			if(rt_com->tns_package_size>0)
			{
				parse_ret = TLS_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,direction,(void **)&rt_npc->parseresult.parse_data,&rt_npc->parseresult.data_size);
				ZFree(rt_com->tns_pack_data); 
   				rt_com->tns_pack_data = NULL;
				if(parse_ret !=3)
				{
					OraNet_DumpSql("This is handshake, continue\n");
//					return 0;	
				}else{
					OraNet_DumpSql("This is app data, add buffer\n");
					have_tns_data = 1;
					rt_com->tcp_buffer_size = Ora_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
				}
			}
		} while (rt_com->tns_package_size>0);
		//如果是data数据，继续处理，否则，return
			if(!have_tns_data)
			{
				OraNet_DumpSql("This is handshake, continue\n");
				return 0;	
			}
   	}else{
		rt_com->tcp_buffer_size = Ora_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
	}
#else
	rt_com->tcp_buffer_size = Ora_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
#endif
    if(direction==USER2ORA)
    {
        /* Client->Server */
        do 
        {
            /* 进行TNS包的拆包、拼包和包解析处理 */
            rt_com->tns_pack_data = Ora_TnsPackage_PreProcess(rt_com->tcp_info,USER2ORA,(u_int*)&rt_com->tns_package_size);
            //OraNet_DumpSql("step[17.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
			/* 调试输出是否SQL语句解析已经完成 */
	#ifdef DEBUG_CHERRY
			if(__ORA_SESSION->help_parsesql_isover==0)
			{
				/* 没有完成 */
				printf("[DEBUG CHERRY] before OraTnsPackageParse : sql is not full\n");
			}
			else
			{
				/* SQL语句的解析已经完成了 */
				printf("[DEBUG CHERRY] before OraTnsPackageParse : sql is over\n");
			}
			if(__ORA_SESSION->have_package_header==1)
			{
				/* 有包头 */
				printf("[DEBUG CHERRY] before OraTnsPackageParse : have package header\n");
			}
			else
			{
				/* 没有包头 */
				printf("[DEBUG CHERRY] before OraTnsPackageParse : no package header\n");
			}
	#endif	/* DEBUG_CHERRY */
            /* 
                检查是否有包头，并设置 
                这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
                此时的结果会是help_parsesql_isover=1,have_package_header=1
                因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
            */
            if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
            {
                /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
                rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
                if(__ORA_SESSION->have_package_header==1)
                {
                    __ORA_SESSION->tamper_pack_type = 1;
                }                                    
            }
#endif	/* HAVE_CHERRY */
            if(rt_com->tns_package_size>0)
            {
                OraNet_DumpSql("step[17.3] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
                /* 性能测试点3.1 注释掉下面的解析函数调用,持续占用1.7CPU */
                parse_ret = OraTnsPackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&rt_com->rewrite_packet);
                if(rt_com->tns_pack_data!=NULL)
                    ZFree(rt_com->tns_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
                
#ifdef HAVE_CHERRY
                /* 下面开始CHERRY的篡改和阻断 */
                if(rt_com->rewrite_packet.is_switchoff==1)
                {
                    /* 
                        TODO : 阻断 
                        1:篡改当前包为拦截包，发送该包
                        2:等待04包返回，并篡改返回的报错信息,并发送
                        3:发送reset包
                    */
	#ifdef DEBUG_CHERRY
                    printf("[C->S]OraTnsPackageParse result is switchoff\n");
	#endif
					if(__ORA_SESSION->start_for_oneway_audit == 1)
					{
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
                    /* 步骤1：先篡改当前包 */
					OraNet_DumpSql("__ORA_SESSION->tamper_pack_type:%d\n",__ORA_SESSION->tamper_pack_type);
					OraNet_DumpSql("__ORA_SESSION->tamper_data_addr:%p\n",__ORA_SESSION->tamper_data_addr);
					OraNet_DumpSql("__ORA_SESSION->enc_store_pack :%d\n",__ORA_SESSION->enc_store_pack);
                    if(__ORA_SESSION->tamper_pack_type==1 && __ORA_SESSION->tamper_data_addr != NULL)
                    {
                        /* 有包头，可以篡改 */
                        /* 这里先直接对cap数据篡改 */
						OraNet_DumpSql("kdmp_stat:%d\n",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat);
						if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat == 2)
						{
							/*先解密 改包 再加密*/
							int tail_size = sizeof(short);
							char* decryp_pack = NULL;
							OraNet_DumpSql("rt_npc->cap_header->data_size:%d\n",rt_npc->cap_header->data_size);
							OraNet_DumpSql("__ORA_SESSION->tamper_data_size:%d\n",__ORA_SESSION->tamper_data_size);
							OraNet_DumpSql("rt_npc->cap_header->data_offset:%d\n",rt_npc->cap_header->data_offset);
							decryp_pack = (char*)ZMalloc(rt_npc->cap_header->data_size);
							u_int decrpy_pack_len_bef = rt_npc->cap_header->data_size - __ORA_SESSION->tamper_data_size;
							memcpy(decryp_pack, (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset, decrpy_pack_len_bef);
							memcpy(decryp_pack + decrpy_pack_len_bef, (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef, 10);
							int len = aes_256_cbc_decryp_pkg((__ORA_SESSION->use_login_sess_key_flag == 1) ? ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_session_key : ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key,
									__ORA_SESSION->tamper_data_addr + 10
									,__ORA_SESSION->tamper_data_size - 10
									,(u_char*)decryp_pack + decrpy_pack_len_bef + 10
									,__ORA_SESSION->tamper_data_size - 10);
							OraNet_DumpHex((char*)decryp_pack + decrpy_pack_len_bef, __ORA_SESSION->tamper_data_size);
							/*改包*/
							rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_ORACLE;
							rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ_HEADER;
							rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
							parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
								(char*)decryp_pack,
								rt_npc->cap_header->data_size,
								0
								);
							if(parse_ret>0)
							{
								OraNet_DumpHex((char*)decryp_pack + decrpy_pack_len_bef, __ORA_SESSION->tamper_data_size);
								//OraNet_DumpHex
								/* 加密 */
								// aes_256_cbc_encryp_pkg(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key,
								// (u_char*)decryp_pack + decrpy_pack_len_bef + 10
								// ,__ORA_SESSION->tamper_data_size - 10 - tail_size
								// ,(u_char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10
								// ,__ORA_SESSION->tamper_data_size - 10);
								memcpy((char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef, (char*)decryp_pack + decrpy_pack_len_bef, 10);
								if(__ORA_SESSION->pcsn == NULL)
									OraNet_DumpSql("__ORA_SESSION->pcsn is null\n");
								AES_KEY key;
								if(__ORA_SESSION->use_login_sess_key_flag == 1)
								{
									AES_set_encrypt_key(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_session_key, 256, &key);
								}
								else
								{
									AES_set_encrypt_key(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key, 256, &key);
								}
								aes_256_cbc_encryp_pkg_with_checksum(&key,
								(u_char*)decryp_pack + decrpy_pack_len_bef + 10
								,__ORA_SESSION->tamper_data_size - 10 - tail_size - 8
								,(u_char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10
								,__ORA_SESSION->tamper_data_size - 10
								,__ORA_SESSION->pcsn, __ORA_SESSION->enc_tamper_pkg_tail);

								//rt_npc->loop_data->capbuf_addr[rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10] = 0x01;

								OraNet_DumpHex((char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef,__ORA_SESSION->tamper_data_size);
							}
							if(decryp_pack)
								ZFree(decryp_pack);
						}
						else
						{
							rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_ORACLE;
							rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ_HEADER;
							rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
							parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
													(char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
													rt_npc->cap_header->data_size,
													0
													);
						}
                        if(parse_ret>0)
                        {
                            /* 篡改成功 */
                            __ORA_SESSION->help_tamper_flag=DBFW_TAMPER_SWITCHOFF;
                            __ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
                        }
                        else
                        {
                            /* 篡改失败，直接发送reset请求 */
                            Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
                            /* 退出自己 */
	#ifdef DUMP_MEMORY_LEAK
                            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
	#else
                            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
	#endif
                            continue;
// 							result = 1;	/* 进入下一轮 */
// 							return result;
                        }
                    }
                	/* 2017-11-03 长语句分tcp包 未分TNS包时，select语句后半部被清零时 可以报错，且能正常抛异常
                                  同样， delete语句后半部被清零时，语句未报错，因此oracle 中去掉
                                         改语句内容为零的逻辑。 */
                    else
                    {
						if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat == 2 && __ORA_SESSION->enc_store_pack == 0)
						{
							/* 加密通信，但是存储的包还没有处理完，此时不拦截阻断 */
						}
						else
						{
							/* 不可篡改，只能发送阻断包 */
							Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
		#ifdef DUMP_MEMORY_LEAK
							__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
		#else
							__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
		#endif
							continue;
	// 						result = 1;	/* 进入下一轮 */
	// 						return result;
						}
                    }
                }
                else if(rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                    rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                    rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
                    )
                {
                	if(__ORA_SESSION->start_for_oneway_audit == 1)
					{
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
                    /* TODO :拦截 */
                    OraNet_DumpSql("step[17.4] OraTnsPackageParse result is blocking throw\n");
					OraNet_DumpSql("__ORA_SESSION->tamper_pack_type:%d\n",__ORA_SESSION->tamper_pack_type);
					OraNet_DumpSql("__ORA_SESSION->tamper_data_addr:%p\n",__ORA_SESSION->tamper_data_addr);
					OraNet_DumpSql("__ORA_SESSION->enc_store_pack :%d\n",__ORA_SESSION->enc_store_pack);
					
                    if(__ORA_SESSION->tamper_pack_type==1 && __ORA_SESSION->tamper_data_addr != NULL)
                    {
                        /* 有包头，可以篡改 */
                        /* 这里先直接对cap数据篡改 */
						OraNet_DumpSql("kdmp_stat:%d\n",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat);
						if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat == 2)
						{
							/*先解密 改包 再加密*/
							int tail_size = sizeof(short);
							char* decryp_pack = NULL;
							OraNet_DumpSql("rt_npc->cap_header->data_size:%d\n",rt_npc->cap_header->data_size);
							OraNet_DumpSql("__ORA_SESSION->tamper_data_size:%d\n",__ORA_SESSION->tamper_data_size);
							OraNet_DumpSql("rt_npc->cap_header->data_offset:%d\n",rt_npc->cap_header->data_offset);
							decryp_pack = (char*)ZMalloc(rt_npc->cap_header->data_size);
							u_int decrpy_pack_len_bef = rt_npc->cap_header->data_size - __ORA_SESSION->tamper_data_size;
							memcpy(decryp_pack, (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset, decrpy_pack_len_bef);
							memcpy(decryp_pack + decrpy_pack_len_bef, (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef, 10);
							int len = aes_256_cbc_decryp_pkg((__ORA_SESSION->use_login_sess_key_flag == 1) ? ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_session_key : ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key,
									__ORA_SESSION->tamper_data_addr + 10
									,__ORA_SESSION->tamper_data_size - 10
									,(u_char*)decryp_pack + decrpy_pack_len_bef + 10
									,__ORA_SESSION->tamper_data_size - 10);
							OraNet_DumpHex((char*)decryp_pack + decrpy_pack_len_bef, __ORA_SESSION->tamper_data_size);
							/*改包*/
							rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_ORACLE;
							rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ_HEADER;
							rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
							parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
								(char*)decryp_pack,
								rt_npc->cap_header->data_size,
								0
								);
							if(parse_ret>0)
							{
								OraNet_DumpHex((char*)decryp_pack + decrpy_pack_len_bef, __ORA_SESSION->tamper_data_size);
								//OraNet_DumpHex
								/* 加密 */
								// aes_256_cbc_encryp_pkg(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key,
								// (u_char*)decryp_pack + decrpy_pack_len_bef + 10
								// ,__ORA_SESSION->tamper_data_size - 10 - tail_size
								// ,(u_char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10
								// ,__ORA_SESSION->tamper_data_size - 10);
								memcpy((char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef, (char*)decryp_pack + decrpy_pack_len_bef, 10);
								if(__ORA_SESSION->pcsn == NULL)
									OraNet_DumpSql("__ORA_SESSION->pcsn is null\n");
								AES_KEY key;
								if(__ORA_SESSION->use_login_sess_key_flag == 1)
								{
									AES_set_encrypt_key(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_session_key, 256, &key);
								}
								else
								{
									AES_set_encrypt_key(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key, 256, &key);
								}
								aes_256_cbc_encryp_pkg_with_checksum(&key,
								(u_char*)decryp_pack + decrpy_pack_len_bef + 10
								,__ORA_SESSION->tamper_data_size - 10 - tail_size - 8
								,(u_char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10
								,__ORA_SESSION->tamper_data_size - 10
								,__ORA_SESSION->pcsn, __ORA_SESSION->enc_tamper_pkg_tail);
								/* 如果设置该值时，oci的拦截会一直重复发语句 */
								//rt_npc->loop_data->capbuf_addr[rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10] = 0x01;

								OraNet_DumpHex((char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef,__ORA_SESSION->tamper_data_size);
							}
							if(decryp_pack)
								ZFree(decryp_pack);
						}
						else
						{
							rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_ORACLE;
							rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ_HEADER;
							rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
							parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
								(char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
								rt_npc->cap_header->data_size,
								0
								);
						}
                        if(parse_ret>0)
                        {
                            /* 篡改成功 */
                            __ORA_SESSION->help_tamper_flag=DBFW_TAMPER_THROW;
							__ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
                        }
                        else
                        {
                            /* 篡改失败，直接发送reset请求 */
                            Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
                            /* 退出自己 */
	#ifdef DUMP_MEMORY_LEAK
                            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
	#else
                            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
	#endif
                            continue;
// 							result = 1;	/* 进入下一轮 */
// 							return result;
                        }
                    }
                    else
					{
						if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat == 2 && __ORA_SESSION->enc_store_pack == 0)
						{
							/* 加密通信，但是存储的包还没有处理完，此时不拦截阻断 */
						}
						else
						{
							/* 不可篡改，只能发送阻断包 */
							Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
		#ifdef DUMP_MEMORY_LEAK
							__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
		#else
							__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
		#endif
							continue;
	// 						result = 1;	/* 进入下一轮 */
	// 						return result;
						}
                    }
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[17.5] OraTnsPackageParse result is pass\n");
                }
                /* CHERRY的篡改和阻断结束 */
#endif	/* HAVE_CHERRY */
            }
        } while (rt_com->tns_package_size>0);
    }
    else
    {
        /* Server->Client */
        do 
        {
            rt_com->tns_pack_data = Ora_TnsPackage_PreProcess(rt_com->tcp_info,ORA2USER,(u_int*)&rt_com->tns_package_size);
#ifdef HAVE_CHERRY
            /* 检查是否有包头，并设置 */
            if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
            {
                /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
                rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
                if(__ORA_SESSION->have_package_header==1)
                {
                    __ORA_SESSION->tamper_pack_type = 1;
                }
            }                                
#endif
            if(rt_com->tns_package_size>0)
            {
                OraNet_DumpSql("step[17.6] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
                /* CHERRY 设置help_parsesql_isover,也就是当出现应答包是，将SQL语句解析完成的标记设置为未完成 */
                __ORA_SESSION->help_parsesql_isover = 0;
                /* CHERRY结束 */
				/* 性能测试点3.2 注释掉下面的解析函数调用,持续占用1.7CPU */
                parse_ret = OraTnsPackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,&rt_com->rewrite_packet);
                //OraNet_DumpSql("step[17.7] ORA2USER : parse over return = %d\n",parse_ret);
                if(rt_com->tns_pack_data!=NULL)
                    ZFree(rt_com->tns_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
				OraNet_DumpSql("respon\n");
				OraNet_DumpSql("rt_com->rewrite_packet.packparse_result:%d\n",rt_com->rewrite_packet.packparse_result);
				OraNet_DumpSql("__ORA_SESSION->help_parse_result:%d\n",__ORA_SESSION->help_parse_result);
				OraNet_DumpSql("__ORA_SESSION->tamper_pack_type:%d\n",__ORA_SESSION->tamper_pack_type);
				OraNet_DumpSql("rt_com->rewrite_packet.is_switchoff:%d\n",rt_com->rewrite_packet.is_switchoff);
#ifdef HAVE_CHERRY
                /* 
                    应答包的拦截和阻断，必须在应答包有包头的情况下进行
                    无论任何应答包，都替换为0C包内容替换为01 00 01,表示取消操作
                    但只有取消操作后立即reset才能真正取消事务
                */
                if(rt_com->rewrite_packet.is_switchoff==1 || __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF)
                {
                    /* 
                        TODO : 阻断 
                        1:篡改当前包为拦截包，发送该包
                        2:等待04包返回，并篡改返回的报错信息,并发送
                        3:发送reset包
                    */
	#ifdef DEBUG_CHERRY
                    printf("[S->C]OraTnsPackageParse result is switchoff\n");
	#endif
                    /* 步骤1：先篡改当前包 */
                    if(__ORA_SESSION->tamper_pack_type==1 &&  __ORA_SESSION->tamper_data_addr != NULL)
                    {
                        /* 有包头，可以篡改 */
                        /* 这里先直接对cap数据篡改 */
						OraNet_DumpSql("kdmp_stat:%d\n",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat);
						if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat == 2)
						{
							/*先解密 改包 再加密*/
							int tail_size = sizeof(short);
							char* decryp_pack = NULL;
							OraNet_DumpSql("rt_npc->cap_header->data_size:%d\n",rt_npc->cap_header->data_size);
							OraNet_DumpSql("__ORA_SESSION->tamper_data_size:%d\n",__ORA_SESSION->tamper_data_size);
							OraNet_DumpSql("rt_npc->cap_header->data_offset:%d\n",rt_npc->cap_header->data_offset);
							decryp_pack = (char*)ZMalloc(rt_npc->cap_header->data_size);
							u_int decrpy_pack_len_bef = rt_npc->cap_header->data_size - __ORA_SESSION->tamper_data_size;
							memcpy(decryp_pack, (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset, decrpy_pack_len_bef);
							memcpy(decryp_pack + decrpy_pack_len_bef, (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef, 10);
							int len = aes_256_cbc_decryp_pkg((__ORA_SESSION->use_login_sess_key_flag == 1) ? ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_session_key : ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key,
									__ORA_SESSION->tamper_data_addr + 10
									,__ORA_SESSION->tamper_data_size - 10
									,(u_char*)decryp_pack + decrpy_pack_len_bef + 10
									,__ORA_SESSION->tamper_data_size - 10);
							OraNet_DumpHex((char*)decryp_pack + decrpy_pack_len_bef, __ORA_SESSION->tamper_data_size);
							/*改包*/
							rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_ORACLE;
							rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ_HEADER;
							rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
							parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
								(char*)decryp_pack,
								rt_npc->cap_header->data_size,
								0
								);
							if(parse_ret>0)
							{
								OraNet_DumpHex((char*)decryp_pack + decrpy_pack_len_bef, __ORA_SESSION->tamper_data_size);
								//OraNet_DumpHex
								/* 加密 */
								// aes_256_cbc_encryp_pkg(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key,
								// (u_char*)decryp_pack + decrpy_pack_len_bef + 10
								// ,__ORA_SESSION->tamper_data_size - 10 - tail_size
								// ,(u_char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10
								// ,__ORA_SESSION->tamper_data_size - 10);
								memcpy((char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef, (char*)decryp_pack + decrpy_pack_len_bef, 10);
								if(__ORA_SESSION->pcsn == NULL)
									OraNet_DumpSql("__ORA_SESSION->pcsn is null\n");
								AES_KEY key;
								if(__ORA_SESSION->use_login_sess_key_flag == 1)
								{
									AES_set_encrypt_key(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_session_key, 256, &key);
								}
								else
								{
									AES_set_encrypt_key(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key, 256, &key);
								}
								aes_256_cbc_encryp_pkg_with_checksum(&key,
								(u_char*)decryp_pack + decrpy_pack_len_bef + 10
								,__ORA_SESSION->tamper_data_size - 10 - tail_size - 8
								,(u_char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10
								,__ORA_SESSION->tamper_data_size - 10
								,__ORA_SESSION->pcsn, __ORA_SESSION->enc_tamper_pkg_tail);
								/* 应答方向不注释，注释掉后oci的阻断，不能抛异常 */
								rt_npc->loop_data->capbuf_addr[rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10] = 0x01;

								OraNet_DumpHex((char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef,__ORA_SESSION->tamper_data_size);
							}
							if(decryp_pack)
								ZFree(decryp_pack);
						}
						else
						{
							rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_ORACLE;
							rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_RESP_HEADER;
							rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
							parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
													(char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
													rt_npc->cap_header->data_size,
													0
													);
						}
                        if(parse_ret>0)
                        {
                            /* 篡改成功 */
                            __ORA_SESSION->help_tamper_flag=DBFW_TAMPER_SWITCHOFF;
							__ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
                        }
                        else
                        {
                            /* 篡改失败，直接发送reset请求 */
                            Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
                            /* 退出自己 */
	#ifdef DUMP_MEMORY_LEAK
                            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
	#else
                            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
	#endif
                            continue;
// 							result = 1;	/* 进入下一轮 */
// 							return result;
                        }
                    }
                    else
                    {
                        /* 只要没有HEADER则不可篡改，只能发送阻断包 */
                        Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
	#ifdef DUMP_MEMORY_LEAK
                        __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
	#else
                        __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
	#endif
                        continue;
// 						result = 1;	/* 进入下一轮 */
// 						return result;
                    }
                }
                else if(rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                    rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                    rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
                    __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
                    )
                {
                    /* TODO :拦截 */
	#ifdef DEBUG_CHERRY
                    printf("[S->C]OraTnsPackageParse result is throw\n");
	#endif
                    if(__ORA_SESSION->tamper_pack_type==1 &&  __ORA_SESSION->tamper_data_addr != NULL)
                    {
                        /* 有包头，可以篡改 */
                        /* 这里先直接对cap数据篡改 */
						OraNet_DumpSql("kdmp_stat:%d\n",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat);
						if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat == 2)
						{
							/*先解密 改包 再加密*/
							int tail_size = sizeof(short);
							char* decryp_pack = NULL;
							OraNet_DumpSql("rt_npc->cap_header->data_size:%d\n",rt_npc->cap_header->data_size);
							OraNet_DumpSql("__ORA_SESSION->tamper_data_size:%d\n",__ORA_SESSION->tamper_data_size);
							OraNet_DumpSql("rt_npc->cap_header->data_offset:%d\n",rt_npc->cap_header->data_offset);
							decryp_pack = (char*)ZMalloc(rt_npc->cap_header->data_size);
							u_int decrpy_pack_len_bef = rt_npc->cap_header->data_size - __ORA_SESSION->tamper_data_size;
							memcpy(decryp_pack, (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset, decrpy_pack_len_bef);
							memcpy(decryp_pack + decrpy_pack_len_bef, (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef, 10);
							int len = aes_256_cbc_decryp_pkg((__ORA_SESSION->use_login_sess_key_flag == 1) ? ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_session_key : ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key,
									__ORA_SESSION->tamper_data_addr + 10
									,__ORA_SESSION->tamper_data_size - 10
									,(u_char*)decryp_pack + decrpy_pack_len_bef + 10
									,__ORA_SESSION->tamper_data_size - 10);
							OraNet_DumpHex((char*)decryp_pack + decrpy_pack_len_bef, __ORA_SESSION->tamper_data_size);
							/*改包*/
							rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_ORACLE;
							rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ_HEADER;
							rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
							parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
								(char*)decryp_pack,
								rt_npc->cap_header->data_size,
								0
								);
							if(parse_ret>0)
							{
								OraNet_DumpHex((char*)decryp_pack + decrpy_pack_len_bef, __ORA_SESSION->tamper_data_size);
								//OraNet_DumpHex
								/* 加密 */
								// aes_256_cbc_encryp_pkg(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key,
								// (u_char*)decryp_pack + decrpy_pack_len_bef + 10
								// ,__ORA_SESSION->tamper_data_size - 10 - tail_size
								// ,(u_char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10
								// ,__ORA_SESSION->tamper_data_size - 10);
								memcpy((char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef, (char*)decryp_pack + decrpy_pack_len_bef, 10);
								if(__ORA_SESSION->pcsn == NULL)
									OraNet_DumpSql("__ORA_SESSION->pcsn is null\n");
								AES_KEY key;
								if(__ORA_SESSION->use_login_sess_key_flag == 1)
								{
									AES_set_encrypt_key(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_session_key, 256, &key);
								}
								else
								{
									AES_set_encrypt_key(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key, 256, &key);
								}
								aes_256_cbc_encryp_pkg_with_checksum(&key,
								(u_char*)decryp_pack + decrpy_pack_len_bef + 10
								,__ORA_SESSION->tamper_data_size - 10 - tail_size - 8
								,(u_char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10
								,__ORA_SESSION->tamper_data_size - 10
								,__ORA_SESSION->pcsn, __ORA_SESSION->enc_tamper_pkg_tail);

								rt_npc->loop_data->capbuf_addr[rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10] = 0x01;

								OraNet_DumpHex((char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef,__ORA_SESSION->tamper_data_size);
							}
							if(decryp_pack)
								ZFree(decryp_pack);
						}
						else
						{
							rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_ORACLE;
							rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_RESP_HEADER;
							rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
							parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
								(char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
								rt_npc->cap_header->data_size,
								0
								);
						}
                        if(parse_ret>0)
                        {
                            /* 篡改成功 */
                            __ORA_SESSION->help_tamper_flag=DBFW_TAMPER_THROW;
							__ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
                        }
                        else
                        {
                            /* 篡改失败，直接发送reset请求 */
                            Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
                            /* 退出自己 */
	#ifdef DUMP_MEMORY_LEAK
                            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
	#else
                            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
	#endif
                            continue;
// 							result = 1;	/* 进入下一轮 */
// 							return result;
                        }
                    }
                    else
                    {
                        /* 只要没有HEADER则不可篡改，只能发送阻断包 */
                        Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
	#ifdef DUMP_MEMORY_LEAK
                        __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
	#else
                        __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
	#endif
                        continue;
// 						result = 1;	/* 进入下一轮 */
// 						return result;
                    }
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[17.7] OraTnsPackageParse result is pass\n");
					if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->kdmp_stat == 2)
						{
							if(__ORA_SESSION->need_tamper == 1)
							{
							/*先解密 改包 再加密*/
							//int tail_size = sizeof(short);
							//char* decryp_pack = NULL;
							OraNet_DumpSql("rt_npc->cap_header->data_size:%d\n",rt_npc->cap_header->data_size);
							OraNet_DumpSql("__ORA_SESSION->tamper_data_size:%d\n",__ORA_SESSION->tamper_data_size);
							OraNet_DumpSql("__ORA_SESSION->tamper_data_size_enc:%d\n",__ORA_SESSION->tamper_data_size_enc);
							// decryp_pack = (char*)ZMalloc(rt_npc->cap_header->data_size);
							u_int decrpy_pack_len_bef = rt_npc->cap_header->data_size - __ORA_SESSION->tamper_data_size_enc;
							// memcpy(decryp_pack, (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset, decrpy_pack_len_bef);
							// memcpy(decryp_pack + decrpy_pack_len_bef, (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef, 10);
							// int len = aes_256_cbc_decryp_pkg(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key,
							// 		__ORA_SESSION->tamper_data_addr + 10
							// 		,__ORA_SESSION->tamper_data_size - 10
							// 		,(u_char*)decryp_pack + decrpy_pack_len_bef + 10
							// 		,__ORA_SESSION->tamper_data_size - 10);
							// /*改包*/
							// rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_ORACLE;
							// rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ_HEADER;
							// rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
							// int parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
							// 	(char*)decryp_pack,
							// 	rt_npc->cap_header->data_size,
							// 	0
							// 	);
							//OraNet_DumpHex
							/* 加密 */
                    		// aes_256_cbc_encryp_pkg(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key,
                        	// (u_char*)decryp_pack + decrpy_pack_len_bef + 10
                        	// ,__ORA_SESSION->tamper_data_size - 10 - tail_size
                        	// ,(u_char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10
                        	// ,__ORA_SESSION->tamper_data_size - 10);
							if(__ORA_SESSION->pcsn == NULL)
								OraNet_DumpSql("__ORA_SESSION->pcsn is null\n");

							OraNet_DumpHex((char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef,10);
							OraNet_DumpHex((char*)__ORA_SESSION->tamper_data_addr + 10, __ORA_SESSION->tamper_data_size - 10);
							OraNet_DumpSql("__ORA_SESSION->enc_tamper_pkg_tail:%d\n",__ORA_SESSION->enc_tamper_pkg_tail);
							OraNet_DumpSql("rt_npc->cap_header->data_offset:%d\n",rt_npc->cap_header->data_offset);
							AES_KEY key;
							if(__ORA_SESSION->use_login_sess_key_flag == 1)
							{
								AES_set_encrypt_key(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_session_key, 256, &key);
							}
							else
							{
								AES_set_encrypt_key(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->enc_login_key, 256, &key);
							}
							
							int a = aes_256_cbc_encryp_pkg_with_checksum(&key,
							(u_char*)__ORA_SESSION->tamper_data_addr + 10
							,__ORA_SESSION->tamper_data_size - 10
							,(u_char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef + 10
							,__ORA_SESSION->tamper_data_size_enc - 10
							,__ORA_SESSION->pcsn, __ORA_SESSION->enc_tamper_pkg_tail);

							OraNet_DumpHex((char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset + decrpy_pack_len_bef,__ORA_SESSION->tamper_data_size_enc);


							OraNet_DumpSql("a:%d\n",a);
							ZFree(__ORA_SESSION->tamper_data_addr);
							__ORA_SESSION->tamper_data_size = 0;

							__ORA_SESSION->tamper_data_addr = __ORA_SESSION->tamper_data_addr_enc;
							__ORA_SESSION->tamper_data_size = __ORA_SESSION->tamper_data_size_enc;

							
							}

						}
                }
#endif	/* HAVE_CHERRY */
            }
        } while (rt_com->tns_package_size>0);
    }
	result = 0;	/* 继续后面的处理 */
	return result;
}

/*
	处理MSSQL通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/
int NPP_HandleMSSQLPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	int have_tns_data = 0;
	direction = rt_npc->parseresult.direction;
#ifdef ENABLE_MSSQL
#ifdef HAVE_CHERRY
    /* 检查是否是可篡改的通讯包，并设置会话级的可篡改标记 */
    if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper
#ifdef ENABLE_TLS  	
		&& __ORA_SESSION->tls_switch != 1 /*tls暂时不支持篡改*/ 
#endif
	)
    {
        /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
        __ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */
    }
    else
    {
        __ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
    }
#endif  /* HAVE_CHERRY */
#ifdef ENABLE_TLS  	
		//判断是否需要TLS解密
		OraNet_DumpSql("s_tls_switch=%d\n",__ORA_SESSION->tls_switch);
		if(__ORA_SESSION->tls_switch == 1 && (__ORA_SESSION->tls_conn_st.mt_stat & TLS_ST_OK))
		{
			rt_com->tcp_buffer_size = TLS_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);	 
		//OraNet_DumpSql("step[17.1] rt_com->tcp_buffer_size=%d\n",rt_com->tcp_buffer_size);
			have_tns_data = 0;
			do{
				
				rt_com->tns_pack_data = TLS_Package_PreProcess(rt_com->tcp_info,direction,(u_int*)&rt_com->tns_package_size);
				OraNet_DumpSql("rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				//协议解析		
				if(rt_com->tns_package_size>0)
				{
					parse_ret = TLS_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,direction,(void **)&rt_npc->parseresult.parse_data,&rt_npc->parseresult.data_size);
					ZFree(rt_com->tns_pack_data); 
   				    rt_com->tns_pack_data = NULL;
					if(parse_ret !=3)
					{
						OraNet_DumpSql("This is handshake, continue\n");
	//					return 0;	
					}else{
						OraNet_DumpSql("This is app data, add buffer\n");
						have_tns_data = 1;
						rt_com->tcp_buffer_size = MSTDS_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
					}
				}
			} while (rt_com->tns_package_size>0);
			//如果是data数据，继续处理，否则，return
				if(!have_tns_data)
				{
					OraNet_DumpSql("This is handshake, continue\n");
					return 0;	
				}
		}else{
			rt_com->tcp_buffer_size = MSTDS_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
		}
#else
		rt_com->tcp_buffer_size = MSTDS_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
#endif

    if(direction==USER2ORA)
    {
	    /* Client->Server */
	    do 
	    {
		    /* 进行TNS包的拆包、拼包和包解析处理 */
		    rt_com->tns_pack_data = MSTDS_Package_PreProcess(rt_com->tcp_info,USER2ORA,(u_int*)&rt_com->tns_package_size);
		    //OraNet_DumpSql("step[18.1] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
            /* 
                检查是否有包头，并设置 
                这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
                此时的结果会是help_parsesql_isover=1,have_package_header=1
                因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
            */
            if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
            {
                /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
                rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
                if(__ORA_SESSION->have_package_header==1)
                {
                    __ORA_SESSION->tamper_pack_type = 1;
                }                                    
            }
#endif
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
				if(__ORA_SESSION->protocol_type == 1 && __SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_SYBASEIQ)
				{
#ifdef ENABLE_SYBASEIQ
					parse_ret = IQ_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&rt_com->rewrite_packet);
#endif
				}
				else
				{
			        parse_ret = MSTDSPackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&rt_com->rewrite_packet,&rt_npc->release_pack_data);
				}
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
				if(rt_npc->release_pack_data)
					ZFree(rt_npc->release_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
                
#ifdef HAVE_CHERRY
                /* [C->S] MSSQL数据库阻断和拦截处理 */
                if(rt_com->rewrite_packet.is_switchoff==1)
                {
                    /*
                        阻断处理
                        1:先进行请求包的篡改
                        2：篡改应答包数据
                        3：发送reset
                    */
#ifdef DEBUG_CHERRY
                    printf("[C->S]MSTDSPackageParse result is switchoff\n");
#endif
					if(__ORA_SESSION->start_for_oneway_audit == 1)
					{
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
                    /* 步骤1：先篡改当前请求包 */
                    /* 由于目前MSSQL还没有完整的实现拦截应答包的篡改，所以这里强制tamper_pack_type为0 */

                    if(__ORA_SESSION->tamper_pack_type==1 && __ORA_SESSION->tamper_data_addr != NULL)
                    {
                        /* 
                            有包头，可以篡改 
                            篡改方法：将从第4字节(命令号)开始后面所有的数据替换为0xFF
                        */
                        rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_MSSQL;
                        rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ8BYTE_FF;
                        rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
                        parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
                                (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
                                rt_npc->cap_header->data_size,
                                sizeof(MSTDS_Packet_Header)
                                );
                        if(parse_ret>0)
                        {
                            /* 篡改成功 */
                            __ORA_SESSION->help_tamper_flag=DBFW_TAMPER_SWITCHOFF;
                            __ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
                        }
                        else
                        {
                            /* 篡改失败，直接发送reset请求 */
                            Dbfw_Switchoff_Immediately_ForHandleNpc();
                            continue;
// 							result = 1;	/* 进入下一轮 */
// 							return result;
                        }
                    }
                    else
                    {
                        /* 不可篡改，只能发送阻断包 */
                        Dbfw_Switchoff_Immediately_ForHandleNpc();
                        continue;
// 						result = 1;	/* 进入下一轮 */
// 						return result;
                    }
                }
                /* MSSQL目前只支持阻断，并且无法抛出异常 */
                else if(rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
                  )
                {
                    /* 
                        阻断或拦截
                        MSSQL目前只支持阻断
                    */
#ifdef DEBUG_CHERRY
                    printf("[CHERRY:MSSQL] rt_com->rewrite_packet.is_switchoff=%d,rt_com->rewrite_packet.packparse_result=%d\n",rt_com->rewrite_packet.is_switchoff,rt_com->rewrite_packet.packparse_result);
#endif
					if(__ORA_SESSION->start_for_oneway_audit == 1)
					{
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
                    //Dbfw_Switchoff_Immediately_ForHandleNpc();
                    if(__ORA_SESSION->tamper_pack_type==1 && __ORA_SESSION->tamper_data_addr != NULL)
                    {
                        /* 
                            有包头，可以篡改 
                            篡改方法：将从第4字节(命令号)开始后面所有的数据替换为0xFF
                        */
                        rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_MSSQL;
                        rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ8BYTE_FF;
                        rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
                        parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
                                (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
                                rt_npc->cap_header->data_size,
                                sizeof(MSTDS_Packet_Header)
                                );
                        if(parse_ret>0)
                        {
                            /* 篡改成功 */
                            __ORA_SESSION->help_tamper_flag=DBFW_TAMPER_THROW;
                            __ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
                        }
                        else
                        {
                            /* 篡改失败，直接发送reset请求 */
                            Dbfw_Switchoff_Immediately_ForHandleNpc();
                            continue;
// 							result = 1;	/* 进入下一轮 */
// 							return result;
                        }
                    }
                    else
                    {
                        /* 不可篡改，只能发送阻断包 */
                        Dbfw_Switchoff_Immediately_ForHandleNpc();
                        continue;
// 						result = 1;	/* 进入下一轮 */
// 						return result;
                    }
                    continue;
// 					result = 1;	/* 进入下一轮 */
// 					return result;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[18.3] OraTnsPackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
		    }
	    } while (rt_com->tns_package_size>0);
    }
    else
    {
	    /* Server->Client */
	    do 
	    {
		    rt_com->tns_pack_data = MSTDS_Package_PreProcess(rt_com->tcp_info,ORA2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[18.4] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.5] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
				if(__ORA_SESSION->protocol_type == 1 && __SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_SYBASEIQ)
				{
#ifdef ENABLE_SYBASEIQ
					parse_ret = IQ_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,&rt_com->rewrite_packet);
#endif
				}
				else
				{
			        parse_ret = MSTDSPackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,&rt_com->rewrite_packet,&rt_npc->release_pack_data);
				}
			    OraNet_DumpSql("step[18.6] ORA2USER : parse over return = %d\n",parse_ret);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
				if(rt_npc->release_pack_data)
					ZFree(rt_npc->release_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
				
#ifdef HAVE_CHERRY
                /* MSSQL目前只支持阻断，并且无法抛出异常 */
                if(rt_com->rewrite_packet.is_switchoff==1 ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
                  )
                {
                    /* 
                        阻断或拦截
                        MSSQL目前只支持阻断
                    */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
// 					result = 1;	/* 进入下一轮 */
// 					return result;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[18.7] OraTnsPackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
		    }
	    } while (rt_com->tns_package_size>0);
    }
#endif
    result = 0;	/* 继续后面的处理 */
	return result;
}



int NPP_HandleHbasePackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
    int direction = 0;
    int result = 0;	/* 返回结果 */
    int parse_ret = 0;	/* 解析结果 */
    direction = rt_npc->parseresult.direction;
#ifdef ENABLE_HBASE
    #ifdef HAVE_CHERRY
    /* 检查是否是可篡改的通讯包，并设置会话级的可篡改标记 */
    if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
    {
        /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
        __ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */
    }
    else
    {
        __ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
    }
#endif  /* HAVE_CHERRY */
    rt_com->tcp_buffer_size = HBASE_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
    if(direction==USER2ORA)
    {
	    /* Client->Server */
	    do
	    {
		    /* 进行TNS包的拆包、拼包和包解析处理 */
		    rt_com->tns_pack_data = HBASE_Package_PreProcess(rt_com->tcp_info,USER2ORA,(u_int*)&rt_com->tns_package_size);
		    //OraNet_DumpSql("step[18.1] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
            /*
                检查是否有包头，并设置
                这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
                此时的结果会是help_parsesql_isover=1,have_package_header=1
                因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
            */
            if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
            {
                /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
                rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
                if(__ORA_SESSION->have_package_header==1)
                {
                    __ORA_SESSION->tamper_pack_type = 1;
                }
            }
#endif
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
                Hbase_Parse_Result hb_parse_result;
                hb_init_parse_result(&hb_parse_result);
			    parse_ret = HBASE_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&hb_parse_result,&rt_com->rewrite_packet,&rt_npc->release_pack_data);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
				if(rt_npc->release_pack_data)
					ZFree(rt_npc->release_pack_data);

                OraNet_DumpSql("hbase package parse:parse_ret=%d,%d,is request = %d,is fecth=%d,stmt list size=%u,scanner_id=%llu\n",
                               parse_ret ,
                               hb_parse_result.parse_result,
                               hb_parse_result.is_request,
                               hb_parse_result.is_fetch,
                               hb_parse_result.stmt_list.size,
                               hb_parse_result.scanner_id
                              );

                if(parse_ret && hb_parse_result.parse_result >= HB_Success && hb_parse_result.is_request && hb_parse_result.is_fetch == 0)
                {
                    Dbfw_NoSQL_Dbfw_Stmt_List noSQL_dbfw_stmt_list;
                    Init_Dbfw_NoSQL_Dbfw_Stmt_List(&noSQL_dbfw_stmt_list);

                    Dbfw_NoSQL_Dbfw_Stmt_List* p_nosql_dbfw_stmt_list = NULL;
                    if(hb_parse_result.stmt_list.size > 1)
                    {
                        p_nosql_dbfw_stmt_list = &noSQL_dbfw_stmt_list;
                    }

                    //for (uint32_t i = 0; i < hb_parse_result.stmt_list.size; ++i)
                    Dbfw_NoSQL_Stmt *nosql_stmt = hb_parse_result.stmt_list.head;
                    while (nosql_stmt != NULL)
                    {

                        parse_ret = HBASE_STMT_session_proc(&hb_parse_result,nosql_stmt,p_nosql_dbfw_stmt_list,rt_com->tcp_info);
                        if(parse_ret < 0){ continue;}

                        //sleep(20);
                        parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet, __ORA_SESSION, direction);
#ifdef HAVE_CHERRY
						/* informix目前只支持阻断，并且无法抛出异常 */
						if(rt_com->rewrite_packet.is_switchoff==1 ||
						   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
						   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
						   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
						  )
						{
							/* 
								阻断或拦截
								MSSQL目前只支持阻断
							*/
							Dbfw_Switchoff_Immediately_ForHandleNpc();
							nosql_stmt = nosql_stmt->next;
							continue;
						}
						else
						{
							/* 放行 */
							OraNet_DumpSql("step[20.4] NPP_HandleDB2Package_ForHandleNpc result is pass\n");
						}
#endif  /* HAVE_CHERRY */

                        nosql_stmt = nosql_stmt->next;
                    }//for each stmt
                    //HBASE_STMT_session_proc 执行后 p_nosql_dbfw_stmt_list 保存了stmt 指针列表，
                    //ora_session->stmp_table_hash 中 保存了最后一个stmt
                    //所以要讲其他的stmt 拷贝到 最后一个stmt 的nosql_dbfw_stmt_list 中去
                    if(p_nosql_dbfw_stmt_list)
                    {
                        OraNet8_SqlStmtData *dbfw_sql_stmt = (OraNet8_SqlStmtData*)p_nosql_dbfw_stmt_list->tail->stmt_ptr;
                        if(dbfw_sql_stmt)
                        {
                            Init_Dbfw_NoSQL_Dbfw_Stmt_List(&dbfw_sql_stmt->nosql_dbfw_stmt_list);
                            Dbfw_Stmt_Ptr_Item * stmt_ptr_item = p_nosql_dbfw_stmt_list->head;
                            while (stmt_ptr_item)
                            {
                                Dbfw_Stmt_Ptr_Item * new_stmt_ptr_item = Append_Dbfw_Stmt_Ptr(&dbfw_sql_stmt->nosql_dbfw_stmt_list);
                                new_stmt_ptr_item->stmt_ptr = stmt_ptr_item->stmt_ptr;
                                OraNet_DumpSql("[debug:]copy stmt_item ptr:%p ,stmt ptr:%p \n",stmt_ptr_item,stmt_ptr_item->stmt_ptr);
                                stmt_ptr_item = stmt_ptr_item->next;
                            }
                        }
                    }
                    Release_Dbfw_NoSQL_Dbfw_Stmt_List(&noSQL_dbfw_stmt_list);//release nosql stmt list

                }//if parse ret && is request
                else if(hb_parse_result.is_request && hb_parse_result.is_fetch == 0)
                {
                    //HBASE_STMT_session_proc(&hb_parse_result,rt_com->tcp_info,0);
                }

                //clear result
                hb_release_parse_result(&hb_parse_result);
		    }
	    } while (rt_com->tns_package_size>0);
    }
    else
    {
	    /* Server->Client */
	    do
	    {
		    rt_com->tns_pack_data = HBASE_Package_PreProcess(rt_com->tcp_info,ORA2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[18.4] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.5] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
                Hbase_Parse_Result hb_parse_result;
                hb_init_parse_result(&hb_parse_result);
			    parse_ret = HBASE_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,
                                               &hb_parse_result,&rt_com->rewrite_packet,&rt_npc->release_pack_data);
			    OraNet_DumpSql("step[18.6] ORA2USER : parse over return = %d\n",parse_ret);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
				if(rt_npc->release_pack_data)
					ZFree(rt_npc->release_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);

//                if(__ORA_SESSION)
//                {
//                    //fetch over
//                    if(hb_parse_result.scanner_id  > 0 && hb_parse_result.is_has_more_result <= 0)
//                    {
//                        int ret = 0;
//                        ret = Copy_Stmt2TlogStmt(__ORA_SESSION);
//                        OraNet_DumpSql("hbase resonse fetch over Copy_Stmt2TlogStmt ret = %d \n", ret);
//                        ret = NPP_HandleTlog(rt_com->alive_time, __ORA_SESSION);\
//                        OraNet_DumpSql("hbase response fetch over NPP_HandleTlog ret = %d \n", ret);
//                    }
//                } else{OraNet_DumpSql("ora session is nil!\n");}

                hb_release_parse_result(&hb_parse_result);
                OraNet_DumpSql("debug:NPP_SqlProcess=%d\n",parse_ret);
#ifdef HAVE_CHERRY
			   if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[25.10] OraTnsPackageParse result is pass\n");
				}
#endif  /* HAVE_CHERRY */


		    }
	    } while (rt_com->tns_package_size>0);
    }
#endif	/* ENABLE_HBASE */
    result = 0;	/* 继续后面的处理 */
    return result;
}


int NPP_HandleMongoDBPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
    int direction = 0;
    int result = 0;	/* 返回结果 */
    int parse_ret = 0;	/* 解析结果 */
    direction = rt_npc->parseresult.direction;
#ifdef ENABLE_MONGODB
    #ifdef HAVE_CHERRY
    /* 检查是否是可篡改的通讯包，并设置会话级的可篡改标记 */
    if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
    {
        /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
        __ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */
    }
    else
    {
        __ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
    }
    #endif  /* HAVE_CHERRY */
    OraNet_DumpSql("Entry MongoDB fro handle npc:[%d]\n",rt_npc->parseresult.data_size);
    //dump_byte_stream(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info);
    rt_com->tcp_buffer_size = MONGODB_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
    if(direction==USER2ORA)
    {
	    /* Client->Server */
	    do
	    {
		    /* 进行TNS包的拆包、拼包和包解析处理 */
		    rt_com->tns_pack_data = MONGODB_Package_PreProcess(rt_com->tcp_info,USER2ORA,(u_int*)&rt_com->tns_package_size);
		    OraNet_DumpSql("step[18.1] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
            /*
                检查是否有包头，并设置
                这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
                此时的结果会是help_parsesql_isover=1,have_package_header=1
                因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
            */
            if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
            {
                /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
                rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
                if(__ORA_SESSION->have_package_header==1)
                {
                    __ORA_SESSION->tamper_pack_type = 1;
                }
            }
#endif
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
                MongoDB_Parse_Result mg_parse_result;
                Init_MGO_Parse_Result(&mg_parse_result);
			    parse_ret = MONGODB_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&mg_parse_result,&rt_com->rewrite_packet,&rt_npc->release_pack_data);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
				if(rt_npc->release_pack_data)
					ZFree(rt_npc->release_pack_data);

                OraNet_DumpSql("mongodb package parse:parse_ret=%d,%d,is request = %d,is fecth=%d,stmt list size=%u\n",
                               parse_ret ,
                               mg_parse_result.parse_result,
                               mg_parse_result.is_request,
                               mg_parse_result.is_fetch,
                               mg_parse_result.stmt_list.stmt_list.size
                              );

                if(parse_ret && mg_parse_result.parse_result >= MGO_Success && mg_parse_result.is_request && mg_parse_result.is_fetch == 0)
                {
                    Dbfw_NoSQL_Dbfw_Stmt_List noSQL_dbfw_stmt_list;
                    Init_Dbfw_NoSQL_Dbfw_Stmt_List(&noSQL_dbfw_stmt_list);

                    Dbfw_NoSQL_Dbfw_Stmt_List* p_nosql_dbfw_stmt_list = NULL;
                    if(mg_parse_result.stmt_list.stmt_list.size > 1)
                    {
                        p_nosql_dbfw_stmt_list = &noSQL_dbfw_stmt_list;
                    }

                    Dbfw_NoSQL_Stmt *mgdb_stmt = mg_parse_result.stmt_list.stmt_list.head;
                    while (mgdb_stmt != NULL)
                    {

                        parse_ret = MONGODB_STMT_session_proc(&mg_parse_result,mgdb_stmt,p_nosql_dbfw_stmt_list,rt_com->tcp_info);
                        if(parse_ret < 0){ continue;}

                        //sleep(20);
                        parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet, __ORA_SESSION, direction);
#ifdef HAVE_CHERRY
						/* informix目前只支持阻断，并且无法抛出异常 */
						if(rt_com->rewrite_packet.is_switchoff==1 ||
						   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
						   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
						   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
						  )
						{
							/* 
								阻断或拦截
								MSSQL目前只支持阻断
							*/
							Dbfw_Switchoff_Immediately_ForHandleNpc();
							mgdb_stmt = mgdb_stmt->next;
							continue;
						}
						else
						{
							/* 放行 */
							OraNet_DumpSql("step[20.4] NPP_HandleDB2Package_ForHandleNpc result is pass\n");
						}
#endif  /* HAVE_CHERRY */


                        mgdb_stmt = mgdb_stmt->next;
                    }//for each stmt

                    if(p_nosql_dbfw_stmt_list)
                    {
                        OraNet8_SqlStmtData *dbfw_sql_stmt = (OraNet8_SqlStmtData*)p_nosql_dbfw_stmt_list->tail->stmt_ptr;
                        if(dbfw_sql_stmt)
                        {
                            Init_Dbfw_NoSQL_Dbfw_Stmt_List(&dbfw_sql_stmt->nosql_dbfw_stmt_list);
                            Dbfw_Stmt_Ptr_Item * stmt_ptr_item = p_nosql_dbfw_stmt_list->head;
                            while (stmt_ptr_item)
                            {
                                Dbfw_Stmt_Ptr_Item * new_stmt_ptr_item = Append_Dbfw_Stmt_Ptr(&dbfw_sql_stmt->nosql_dbfw_stmt_list);
                                new_stmt_ptr_item->stmt_ptr = stmt_ptr_item->stmt_ptr;

                                stmt_ptr_item = stmt_ptr_item->next;
                            }
                        }
                    }
                    Release_Dbfw_NoSQL_Dbfw_Stmt_List(&noSQL_dbfw_stmt_list);//release nosql stmt list

                }//if parse ret && is request
                else if(mg_parse_result.is_request && mg_parse_result.is_fetch == 0)
                {
                    //HBASE_STMT_session_proc(&hb_parse_result,rt_com->tcp_info,0);
                }

                //clear result
                Release_MGO_Parse_Result(&mg_parse_result);
		    }
	    } while (rt_com->tns_package_size>0);
    }
    else
    {
	    /* Server->Client */
	    do
	    {
		    rt_com->tns_pack_data = MONGODB_Package_PreProcess(rt_com->tcp_info,ORA2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[18.4] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.5] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
                MongoDB_Parse_Result mg_parse_result;
                Init_MGO_Parse_Result(&mg_parse_result);
			    parse_ret = MONGODB_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,
                                               &mg_parse_result,&rt_com->rewrite_packet,&rt_npc->release_pack_data);
			    OraNet_DumpSql("step[18.6] ORA2USER : parse over return = %d\n",parse_ret);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
				if(rt_npc->release_pack_data)
					ZFree(rt_npc->release_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
                Release_MGO_Parse_Result(&mg_parse_result);
                OraNet_DumpSql("debug:NPP_SqlProcess=%d\n",parse_ret);
#ifdef HAVE_CHERRY
			   if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[25.10] OraTnsPackageParse result is pass\n");
				}
#endif  /* HAVE_CHERRY */

		    }
	    } while (rt_com->tns_package_size>0);
    }
#endif	/* ENABLE_MONGODB */
    result = 0;	/* 继续后面的处理 */
    return result;
}




/*
	处理MySQL/GBase通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/
int NPP_HandleMySQLPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	u_char  is_compress = 0;
	int have_tns_data = 0;
	direction = rt_npc->parseresult.direction;
#ifdef ENABLE_MYSQL
#ifdef HAVE_CHERRY
    if(__ORA_SESSION->mysql_capability_flag_1_client.client_ssl == 1 
        && __ORA_SESSION->mysql_capability_flag_1_server.client_ssl == 1)
    {
		if(__ORA_SESSION->log_flag == 0)
        {
            __ORA_SESSION->log_flag = 1;
        	Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__
        	    ,(char*)"find mysql ssl session,bypass");
    	}
        return 0;
    }
    /* 检查是否是可篡改的通讯包，并设置会话级的标记 */
    if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper
#ifdef ENABLE_TLS  	
		&& __ORA_SESSION->tls_switch != 1 /*tls暂时不支持篡改*/ 
#endif

	)
	{
		/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
		__ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */
		/* 在这里要判断SQL语句是否已经解析完成了，如没有完成，则肯定应该是当前包中会包含SQL语句的一部分 */
	}
    else
    {
        __ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
    }
#endif	/* HAVE_CHERRY */

#ifdef ENABLE_SSL_AUDIT
	result = 0;	//此处为ssl handshake包初始化压缩状态，状态为"未压缩"
	if(__ORA_SESSION->ssl_sess_de.ssl_session_status != SSL_SESSION_STATUS_HACK_WAIT_HANDSHAKE)
	{
#endif	
		if((__ORA_SESSION->help_session_state == DBFW_SESSION_STATE_NOCONNECT && __ORA_SESSION->finish_choose != 1)||( __ORA_SESSION->finish_choose == 0xFF))
		{
			result = MYSQL_Uncompress_Connectionless(rt_com->tcp_info,rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,direction);
			if(result == 0)
			{
				return 0;
			}
		}
#ifdef ENABLE_SSL_AUDIT		
	}
#endif

#ifdef ENABLE_TLS  		  
		//判断是否需要TLS解密
		OraNet_DumpSql("s_tls_switch=%d\n",__ORA_SESSION->tls_switch);
		if(__ORA_SESSION->tls_switch == 1 && __ORA_SESSION->mysql_help_islogined != 0x00)
		{
			rt_com->tcp_buffer_size = TLS_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);	 
		//OraNet_DumpSql("step[17.1] rt_com->tcp_buffer_size=%d\n",rt_com->tcp_buffer_size);
			have_tns_data = 0;
			do{
				
				rt_com->tns_pack_data = TLS_Package_PreProcess(rt_com->tcp_info,direction,(u_int*)&rt_com->tns_package_size);
				OraNet_DumpSql("rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				//协议解析		
				if(rt_com->tns_package_size>0)
				{
					parse_ret = TLS_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,direction,(void **)&rt_npc->parseresult.parse_data,&rt_npc->parseresult.data_size);
					ZFree(rt_com->tns_pack_data); 
   				    rt_com->tns_pack_data = NULL;
					if(parse_ret !=3)
					{
						OraNet_DumpSql("This is handshake, continue\n");
	//					return 0;	
					}else{
						if(__ORA_SESSION->mysql_tls_user_pack == 0 && __ORA_SESSION->mysql_help_islogined == 0x02)
						{
							__ORA_SESSION->mysql_tls_user_pack = 1;
							__ORA_SESSION->mysql_help_islogined = 0x00;
						}
						OraNet_DumpSql("This is app data, add buffer\n");
						have_tns_data = 1;
						result = MYSQL_Uncompress(rt_com->tcp_info,rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,direction);	

						if(result == -2)
						{
							return 0;
						}
						if(result == 0)
						{
							rt_com->tcp_buffer_size = MYSQL_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
						}
						else
						{
							if(result == 1)
							{
								is_compress = 1;
								rt_com->tcp_buffer_size = MYSQL_AddTcpPackageToBuffer(__ORA_SESSION->mysql_dyna_uncompress_buff,__ORA_SESSION->mysql_dyna_uncompress_buff_size,rt_com->tcp_info,direction);
								ZFree(__ORA_SESSION->mysql_dyna_uncompress_buff);
								__ORA_SESSION->mysql_dyna_uncompress_buff_size =0;
							}
						}		
					}
				}
			} while (rt_com->tns_package_size>0);
			//如果是data数据，继续处理，否则，return
				if(!have_tns_data)
				{
					OraNet_DumpSql("This is handshake, continue\n");
					return 0;	
				}
		}else{
#endif		
	result = MYSQL_Uncompress(rt_com->tcp_info,rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,direction);	

	if(result == -2)
	{
		return 0;
	}
	if(result == 0)
	{
		rt_com->tcp_buffer_size = MYSQL_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
	}
	else
	{
		if(result == 1)
		{
			is_compress = 1;
			rt_com->tcp_buffer_size = MYSQL_AddTcpPackageToBuffer(__ORA_SESSION->mysql_dyna_uncompress_buff,__ORA_SESSION->mysql_dyna_uncompress_buff_size,rt_com->tcp_info,direction);
			ZFree(__ORA_SESSION->mysql_dyna_uncompress_buff);
			__ORA_SESSION->mysql_dyna_uncompress_buff_size =0;
		}
	}
#ifdef ENABLE_TLS 
	}
#endif

	
	if(direction==USER2MYSQL)
	{
	  /* Client->Server */
        #ifdef ENABLE_SSL_AUDIT
   	    if(__ORA_SESSION->ssl_sess_de.ssl_session_status == SSL_SESSION_STATUS_HACK_WAIT_HANDSHAKE)
   	    {
   		    ssl_decrypt_info_init(__NPP_ALL_CONFIG->s_dbfw_home, (const char *)rt_com->tcp_info->oracle_server_ip_str, (unsigned short)rt_com->tcp_info->oracle_server_port);
   		    do
   		    {
   			    /* 进行SSL handshake包的拆包、拼包和包解析处理 */
   			    rt_com->tns_pack_data = SSL_Package_PreProcess_FromTcpBuf(rt_com->tcp_info, USER2MYSQL, &rt_com->tns_package_size);
   			    if(rt_com->tns_pack_data != NULL)
   			    {
                    //调用ssl解密套件中处理handshake的函数	  
   				    ssl_package_handle(rt_com->tns_pack_data, rt_com->tns_package_size, USER2MYSQL, NULL, NULL);
   	  
   				    ZFree(rt_com->tns_pack_data); 
   				    rt_com->tns_pack_data = NULL;
   			    }
   		    }while(rt_com->tns_package_size > 0);
   		    return 0;
   	    }
        #endif
		do 
		{
			/* 进行TNS包的拆包、拼包和包解析处理 */
			rt_com->tns_pack_data = MYSQL_Package_PreProcess(rt_com->tcp_info,USER2MYSQL,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[19.4] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
				/* 
					检查是否有包头，并设置 
					这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
					此时的结果会是help_parsesql_isover=1,have_package_header=1
					因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
				*/
				if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
				{
					/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
					rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
					if(__ORA_SESSION->have_package_header==1)
					{
						__ORA_SESSION->tamper_pack_type = 1;
					}                                    
				}
#endif
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[19.5] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				parse_ret = MYSQL_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2MYSQL,&rt_com->rewrite_packet);
				if(rt_com->tns_pack_data!=NULL)
				  ZFree(rt_com->tns_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
                
#ifdef HAVE_CHERRY
				/* [C->S] MySQL数据库阻断和拦截处理 */
				if(rt_com->rewrite_packet.is_switchoff==1)
				{
					/*
						阻断处理
						1:先进行请求包的篡改
						2：篡改应答包数据
						3：发送reset
					*/
#ifdef DEBUG_CHERRY
					printf("[C->S]MYSQL_PackageParse result is switchoff\n");
#endif
					if(__ORA_SESSION->start_for_oneway_audit == 1 || is_compress == 1)
					{
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
					/* 步骤1：先篡改当前请求包 */
					if(__ORA_SESSION->tamper_pack_type==1 && __ORA_SESSION->tamper_data_addr != NULL)
					{
						/* 
							有包头，可以篡改 
							篡改方法：将从第4字节(命令号)开始后面所有的数据替换为0xFF
						*/
						rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_MYSQL;
						rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_PACKALL_FF;
						rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
						parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
								(char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
								rt_npc->cap_header->data_size,
								4
								);
						if(parse_ret>0)
						{
							/* 篡改成功 */
							__ORA_SESSION->help_tamper_flag=DBFW_TAMPER_SWITCHOFF;
							__ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
						}
						else
						{
							/* 篡改失败，直接发送reset请求 */
							Dbfw_Switchoff_Immediately_ForHandleNpc();
							continue;
						}
					}
					else
					{
						/* 不可篡改，只能发送阻断包 */
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
				}
				else if(rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
						rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
						rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
				  )
				{
					/* 
					拦截,步骤
					1：篡改请求包数据
					2：篡改应答包数据
					*/
#ifdef DEBUG_CHERRY
						printf("[C->S]MYSQL_PackageParse result is blocking throw\n");
#endif
					if(__ORA_SESSION->start_for_oneway_audit == 1)
					{
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
					/* 步骤1：先篡改当前请求包 */
					if(__ORA_SESSION->tamper_pack_type==1 &&  __ORA_SESSION->tamper_data_addr != NULL)
					{
						/* 
							有包头，可以篡改 
							篡改方法：将从第4字节(命令号)开始后面所有的数据替换为0xFF
						*/
						rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_MYSQL;
						rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_PACKALL_FF;
						rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
						parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
								(char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
								rt_npc->cap_header->data_size,
								4
								);
						if(parse_ret>0)
						{
							/* 篡改成功 */
							__ORA_SESSION->help_tamper_flag=DBFW_TAMPER_THROW;
							__ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
						}
						else
						{
							/* 篡改失败，直接发送reset请求 */
							Dbfw_Switchoff_Immediately_ForHandleNpc();
							continue;
						}
					}
					else
					{
						/* 不可篡改，只能发送阻断包 */
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[19.6] [C->S]MYSQL_PackageParse result is pass\n");
				}
#endif  /* HAVE_CHERRY */
			}
		} while (rt_com->tns_package_size>0);
	}
	else
	{
		/* Server->Client */
	    #ifdef ENABLE_SSL_AUDIT
		if(__ORA_SESSION->ssl_sess_de.ssl_session_status == SSL_SESSION_STATUS_HACK_WAIT_HANDSHAKE)
		{
		    ssl_decrypt_info_init(__NPP_ALL_CONFIG->s_dbfw_home, (const char *)rt_com->tcp_info->oracle_server_ip_str, (unsigned short)rt_com->tcp_info->oracle_server_port);
			do
			{
				/* 进行SSL handshake包的拆包、拼包和包解析处理 */
				rt_com->tns_pack_data = SSL_Package_PreProcess_FromTcpBuf(rt_com->tcp_info,MYSQL2USER,(u_int*)&rt_com->tns_package_size);
				if(rt_com->tns_pack_data != NULL)
				{
					//调用ssl解密套件中处理handshake的函数
					u_char handshake_ok = 0;
					ssl_package_handle(rt_com->tns_pack_data, rt_com->tns_package_size, MYSQL2USER, NULL, &handshake_ok);
					if(handshake_ok == 0x01)
					{
						__ORA_SESSION->ssl_sess_de.ssl_session_status = SSL_SESSION_STATUS_HACK_SUCCESS;
					}

					ZFree(rt_com->tns_pack_data); 
					rt_com->tns_pack_data = NULL;
				}
			}while((rt_com->tns_package_size > 0));
			return 0;
		}
		#endif
		do 
		{
			rt_com->tns_pack_data = MYSQL_Package_PreProcess(rt_com->tcp_info,MYSQL2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[19.7] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			if(rt_com->tns_package_size>0)
			{
			  OraNet_DumpSql("step[19.8] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			  /* 测试时可以注释掉下面这句话不进行解析 */
			  parse_ret = MYSQL_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,MYSQL2USER,&rt_com->rewrite_packet);
			  OraNet_DumpSql("step[19.9] ORA2USER : parse over return = %d\n",parse_ret);
			  if(rt_com->tns_pack_data!=NULL)
				  ZFree(rt_com->tns_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
			    /* MSSQL目前只支持阻断，并且无法抛出异常 */
			    if(rt_com->rewrite_packet.is_switchoff==1 ||
			       rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
			       rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
			       rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
			       __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
			      )
			    {
			        /* 
			            阻断或拦截
			            MSSQL目前只支持阻断
			        */
#ifdef DEBUG_CHERRY
			        printf("[S->C]MYSQL_PackageParse result is switchoff or throw\n");
#endif
			        //Dbfw_Switchoff_Immediately_ForHandleNpc();
			        rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_MYSQL;
			        rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_PACKALL_00;
			        rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
			        parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
			            (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
			            rt_npc->cap_header->data_size,
			            0
			            );
			        if(parse_ret>0)
			        {
			            /* 篡改成功 */
			            //__ORA_SESSION->help_tamper_flag=DBFW_TAMPER_SWITCHOFF;
			            __ORA_SESSION->help_tamper_flag=DBFW_TAMPER_DORESET;
			            /* 发送篡改的通讯包 */
			            __ORA_SESSION->need_tamper = 1;
			        }
			        else
			        {
			            /* 篡改失败，直接发送reset请求 */
			            Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
			            /* 退出自己 */
#ifdef DUMP_MEMORY_LEAK
			            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
#else
			            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
#endif
			            continue;
			// 										result = 1;	/* 进入下一轮 */
			// 										return result;
			        }
			    }
			    else
			    {
			        /* 放行 */
			        OraNet_DumpSql("step[19.10] OraTnsPackageParse result is pass\n");
			    }
#endif  /* HAVE_CHERRY */
			}
		} while (rt_com->tns_package_size>0);
	}
#endif  /* ENABLE_MYSQL */
	result = 0;	/* 继续后面处理 */
	return result;
}

/*
	处理DB2通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/
int NPP_HandleDB2Package_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;
#ifdef ENABLE_DB2
    rt_com->tcp_buffer_size = DB2_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
    //OraNet_DumpSql("step[20.1] rt_com->tcp_buffer_size=%d\n",rt_com->tcp_buffer_size);
    if(direction==USER2DB2)
    {
        /* Client->Server */
        do 
        {
#ifdef HAVE_RSAS_COMPATIBLE
			if(__NPP_ALL_CONFIG->vulnerability_scan_compatible_flag==1)
			{
				if(rt_com->tcp_info->oracle_server_port == 523)
					rt_com->rewrite_packet.is_switchoff = 1;
			}
#endif
            /* 进行TNS包的拆包、拼包和包解析处理 */
            rt_com->tns_pack_data = DB2_Package_PreProcess(rt_com->tcp_info,USER2DB2,(u_int*)&rt_com->tns_package_size);
            //OraNet_DumpSql("step[20.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
            if(rt_com->tns_package_size>0)
            {
                OraNet_DumpSql("step[20.3] USER2DB2 : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
                /* 测试时可以注释掉下面这句话不进行解析 */
                parse_ret = DB2_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2DB2,&rt_com->rewrite_packet);
                if(rt_com->tns_pack_data!=NULL)
                    ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
				// /*test vulnerability_scan_compatible_flag */
                //#ifdef HAVE_RSAS_COMPATIBLE
				// if(__ORA_SESSION->respon_switchoff_moresql == NPP_RESULT_SWITCHOFF)
				// rt_com->rewrite_packet.is_switchoff=1;
                //#endif

#ifdef HAVE_CHERRY
                /* DB2目前只支持阻断，并且无法抛出异常 */
                if(rt_com->rewrite_packet.is_switchoff==1 ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
                  )
                {
                    /* 
                        阻断或拦截
                        MSSQL目前只支持阻断
                    */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[20.4] NPP_HandleDB2Package_ForHandleNpc result is pass\n");
                }
#endif  /* HAVE_CHERRY */
            }
        } while (rt_com->tns_package_size>0);
    }
    else
    {
        /* Server->Client */
        do 
        {
            rt_com->tns_pack_data = DB2_Package_PreProcess(rt_com->tcp_info,DB22USER,(u_int*)&rt_com->tns_package_size);
            //OraNet_DumpSql("step[20.5] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
            if(rt_com->tns_package_size>0)
            {
                OraNet_DumpSql("step[20.6] DB22USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
                /* 测试时可以注释掉下面这句话不进行解析 */
                parse_ret = DB2_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,DB22USER,&rt_com->rewrite_packet);
                OraNet_DumpSql("step[20.7] DB22USER : parse over return = %d\n",parse_ret);
                if(rt_com->tns_pack_data!=NULL)
                    ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
                /* DB2目前只支持阻断，并且无法抛出异常 */
                if(rt_com->rewrite_packet.is_switchoff==1 ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
                  )
                {
                    /* 
                        阻断或拦截
                        MSSQL目前只支持阻断
                    */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[20.8] NPP_HandleDB2Package_ForHandleNpc result is pass\n");
                }
#endif  /* HAVE_CHERRY */
            }
        } while (rt_com->tns_package_size>0);
    }
#endif
	result = 0;	/* 继续后面的处理 */
	return result;
}

/*
	处理DM(达梦)通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/
int NPP_HandleDMPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;
#ifdef ENABLE_DM
#ifdef HAVE_CHERRY
    /* 检查是否是可篡改的通讯包，并设置会话级的标记 */
    if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
    {
        /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
        __ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */

    }
    else
    {
        __ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
    }
#endif  /* HAVE_CHERRY */
    rt_com->tcp_buffer_size = DM_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
    OraNet_DumpSql("step[21.1] rt_npc->parseresult.data_size=%d\n",rt_npc->parseresult.data_size);
    //rt_com->tcp_buffer_size = OSCAR_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
    //OraNet_DumpSql("step[21.2] rt_com->tcp_buffer_size=%d\n",rt_com->tcp_buffer_size);
    if(direction==USER2DM)
    //if(direction==USER2OSCAR)
    {
        /* Client->Server */
        do 
        {
            /* 进行TNS包的拆包、拼包和包解析处理 */
            rt_com->tns_pack_data = DM_Package_PreProcess(rt_com->tcp_info,USER2DM,(u_int*)&rt_com->tns_package_size);
#ifdef HAVE_CHERRY
            /* 
                检查是否有包头，并设置 
                这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
                此时的结果会是help_parsesql_isover=1,have_package_header=1
                因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
            */
            if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
            {
                /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
                rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
                if(__ORA_SESSION->have_package_header==1)
                {
                    __ORA_SESSION->tamper_pack_type = 1;
                }                                    
            }
#endif
            //rt_com->tns_pack_data = OSCAR_Package_PreProcess(rt_com->tcp_info,USER2OSCAR,(u_int*)&rt_com->tns_package_size);
            //OraNet_DumpSql("step[21.3] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
            if(rt_com->tns_package_size>0)
            {
                OraNet_DumpSql("step[21.4] USER2DM : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
                /* 测试时可以注释掉下面这句话不进行解析 */
                parse_ret = DM_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2DM,&rt_com->rewrite_packet);
                //parse_ret = OSCAR_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2OSCAR,&rt_com->rewrite_packet);
                if(rt_com->tns_pack_data!=NULL)
                    ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
                /* 
                    [C->S] MSSQL数据库阻断和拦截处理 
                    注意：达梦数据库在DM_PackageParse函数中，对于拦截(NPP_RESULT_BLOCKING_THROW)也强制设置了is_switchoff=1
                    因为之前的代理和半透明网桥的版本中不支持拦截
                    为了保持兼容性，在DM_PackageParse函数中不做调整，而是在这里进行NPP_RESULT_SWITCHOFF判断
                */
                if(rt_com->rewrite_packet.is_switchoff==1 && rt_com->rewrite_packet.packparse_result==NPP_RESULT_SWITCHOFF)
                {
                    /*
                        阻断处理
                        1:先进行请求包的篡改
                        2：篡改应答包数据
                        3：发送reset
                    */
#ifdef DEBUG_CHERRY
                    printf("[C->S]DM_PackageParse result is switchoff\n");
#endif
					if(__ORA_SESSION->start_for_oneway_audit == 1)
					{
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
                    /* 步骤1：先篡改当前请求包 */
                    /* 由于目前MSSQL还没有完整的实现拦截应答包的篡改，所以这里强制tamper_pack_type为0 */
                    //__ORA_SESSION->tamper_pack_type = 0;
                    if(__ORA_SESSION->tamper_pack_type==1 && __ORA_SESSION->tamper_data_addr != NULL)
                    {
                        /* 
                            有包头，可以篡改 
                            篡改方法：将从第4字节(命令号)开始后面所有的数据替换为0xFF
                        */
                        rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_DM;
                        /* fix bug 2373 将篡改包头之后的数据改为篡改达梦数据库包头的包类型(第4字节)为0x00，同时重新计算CRC(偏移量是19)字节的值并篡改 */
                        //rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_PACKALL_00;
                        rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_DMHEADER;
                        rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
                        parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
                            (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
                            rt_npc->cap_header->data_size,
                            sizeof(DM_PacketHeader)
                            );
                        if(parse_ret>0)
                        {
                            /* 篡改成功 */
                            __ORA_SESSION->help_tamper_flag=DBFW_TAMPER_SWITCHOFF;
                            __ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
                        }
                        else
                        {
                            /* 篡改失败??直接发送reset请求 */
                            Dbfw_Switchoff_Immediately_ForHandleNpc();
                            continue;
                        }
                    }
                    else
                    {
                        /* 不可篡改，只能发送阻断包 */
                        Dbfw_Switchoff_Immediately_ForHandleNpc();
                        continue;
                    }
                }
                /* 达梦目前只支持阻断，并且无法抛出异常 */
                else if(rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
                  )
                {
                    /* 
                        阻断或拦截
                        MSSQL目前只支持阻断
                    */
                    if(__ORA_SESSION->start_for_oneway_audit == 1)
					{
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
                    OraNet_DumpSql("[C->S]DM_PackageParse result is blocking throw\n");
                    /* 由于目前MSSQL还没有完整的实现拦截应答包的篡改，所以这里强制tamper_pack_type为0 */
                    //__ORA_SESSION->tamper_pack_type = 0;
                    if(__ORA_SESSION->tamper_pack_type==1 && __ORA_SESSION->tamper_data_addr != NULL)
                    {
                        /* 
                            有包头，可以篡改 
                            篡改方法：将从第4字节(命令号)开始后面所有的数据替换为0xFF
                        */
                        rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_DM;
                        /* fix bug 2373 将篡改包头之后的数据改为篡改达梦数据库包头的包类型(第4字节)为0x00，同时重新计算CRC(偏移量是19)字节的值并篡改 */
                        //rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_PACKALL_00;
                        rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_DMHEADER;
                        rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
                        parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
                                (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
                                rt_npc->cap_header->data_size,
                                sizeof(DM_PacketHeader)
                                );
                        if(parse_ret>0)
                        {
                            /* 篡改成功 */
                            __ORA_SESSION->help_tamper_flag=DBFW_TAMPER_THROW;
                            __ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
                        }
                        else
                        {
                            /* 篡改失败，直接发送reset请求 */
                            Dbfw_Switchoff_Immediately_ForHandleNpc();
                            continue;
                        }
                    }
                    else
                    {
                        /* 不可篡改，只能发送阻断包 */
                        Dbfw_Switchoff_Immediately_ForHandleNpc();
                        continue;
                    }
                    //Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[21.5] [C->S]DM_PackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
            }
        } while (rt_com->tns_package_size>0);
    }
    else
    {
        /* Server->Client */
        do 
        {
            rt_com->tns_pack_data = DM_Package_PreProcess(rt_com->tcp_info,DM2USER,(u_int*)&rt_com->tns_package_size);
            //rt_com->tns_pack_data = OSCAR_Package_PreProcess(rt_com->tcp_info,OSCAR2USER,(u_int*)&rt_com->tns_package_size);
            //OraNet_DumpSql("step[21.6] DM2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
            if(rt_com->tns_package_size>0)
            {
                OraNet_DumpSql("DM2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
                /* 测试时可以注释掉下面这句话不进行解析 */
                parse_ret = DM_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,DM2USER,&rt_com->rewrite_packet);
                //parse_ret = OSCAR_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,OSCAR2USER,&rt_com->rewrite_packet);
                OraNet_DumpSql("step[21.7] DM2USER : parse over return = %d\n",parse_ret);
                if(rt_com->tns_pack_data!=NULL)
                    ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
                /* 达梦目前只支持阻断，并且无法抛出异常 */
                if(rt_com->rewrite_packet.is_switchoff==1 ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
                  )
                {
                    /* 
                        阻断或拦截
                        MSSQL目前只支持阻断
                    */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[21.8] OraTnsPackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
            }
        } while (rt_com->tns_package_size>0);
    }
#endif
	result = 0;	/* 继续后面的处理 */
	return result;
}

/*
	处理POSTGREE通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/
int NPP_HandlePostgrePackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;
#ifdef ENABLE_PGSQL
#ifdef HAVE_CHERRY
	/* 检查是否是可篡改的通讯包，并设置会话级的标记 */
	if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
	{
		/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
		__ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */
		/* 在这里要判断SQL语句是否已经解析完成了，如没有完成，则肯定应该是当前包中会包含SQL语句的一部分 */
	}
	else
	{
		__ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
	}
#endif  /* HAVE_CHERRY */

	rt_com->tcp_buffer_size = PG_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
	//OraNet_DumpSql("step[22.1] rt_com->tcp_buffer_size=%d\n",rt_com->tcp_buffer_size);
	if (direction == USER2PG)
	{
		//Client->Server
		do 
		{
			/* 进行TNS包的拆包、拼包和包解析处理 */
			rt_com->tns_pack_data = PG_Package_PreProcess(rt_com->tcp_info,USER2PG,(u_int*)&rt_com->tns_package_size);
#ifdef HAVE_CHERRY
				/* 检查是否有包头，并设置 */
				if(rt_npc->parseresult.parseresult_id == rt_cherry->last_parseresult_id_fortamper)
				{
					/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
					rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;

					if(__ORA_SESSION->have_package_header==1)
					{
						__ORA_SESSION->tamper_pack_type = 1;
					}
				}                                
#endif
			//OraNet_DumpSql("step[22.2] USER2PG: rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[22.3] USER2PG : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 测试时可以注释掉下面这句话不进行解析 */
				parse_ret = PG_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2PG,&rt_com->rewrite_packet);
				if(rt_com->tns_pack_data!=NULL)
					ZFree(rt_com->tns_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
				/* Postgre目前只支持阻断，并且无法抛出异常 [C->S] PGSQL数据库阻断处理 */
				if(rt_com->rewrite_packet.is_switchoff == 1)
				{
					/*
						阻断处理
						1:先进行请求包的篡改
						2：篡改应答包数据
						3：发送reset
					*/
#ifdef DEBUG_CHERRY
					printf("[C->S]MSTDSPackageParse result is switchoff\n");
#endif
					if(__ORA_SESSION->start_for_oneway_audit == 1)
					{
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
					/* 步骤1：先篡改当前请求包 */

					if(__ORA_SESSION->tamper_pack_type == 1 && __ORA_SESSION->tamper_data_addr != NULL)
					{
						/* 
							有包头，可以篡改 
							篡改方法：将从第5字节(包长度)开始后面所有的数据替换为0xFF
						*/
						rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_POSTGRE;
						rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ5BYTE_00;
						rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
						/*
						char *ppp =  (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset;
						for (int tt=0;tt<rt_npc->cap_header->data_size;tt++)
						{
								printf("%x,", ppp[tt]); 
						}
						printf("\n");
						*/

						parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
								(char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
								rt_npc->cap_header->data_size,
								sizeof(PG_Packet_CommonHead)
								);
						/* 
						ppp =  (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset;
						for (int tt=0;tt<rt_npc->cap_header->data_size;tt++)
						{
								printf("%x,", ppp[tt]); 
						}
						printf("\n"); 
						*/

						if(parse_ret>0)
						{
							/* 篡改成功 */
							__ORA_SESSION->help_tamper_flag=DBFW_TAMPER_SWITCHOFF;
							__ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
						}
						else
						{
							/* 篡改失败，直接发送reset请求 */
							Dbfw_Switchoff_Immediately_ForHandleNpc();
							continue;
						}
					}
					else
					{
						/* 不可篡改，只能发送阻断包 */
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}


				}
				/* PGSQL目前只支持阻断，并且无法抛出异常 */
				else if (rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
						 rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
						 rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
					  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
#ifdef DEBUG_CHERRY
					printf("[CHERRY:PGSQL] rt_com->rewrite_packet.is_switchoff=%d,rt_com->rewrite_packet.packparse_result=%d\n",rt_com->rewrite_packet.is_switchoff,rt_com->rewrite_packet.packparse_result);
#endif
					if(__ORA_SESSION->start_for_oneway_audit == 1)
					{
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
					//Dbfw_Switchoff_Immediately_ForHandleNpc();
					 if(__ORA_SESSION->tamper_pack_type==1 && __ORA_SESSION->tamper_data_addr != NULL)
					{
						/* 
							有包头，可以篡改 
							篡改方法：将从第4字节(命令号)开始后面所有的数据替换为0xFF
						*/
						rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_POSTGRE;
						rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ5BYTE_00; 
						rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
						parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
								(char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
								rt_npc->cap_header->data_size,
								sizeof(PG_Packet_CommonHead)
								);
						if(parse_ret>0)
						{
							/* 篡改成功 */
							__ORA_SESSION->help_tamper_flag=DBFW_TAMPER_THROW;
							__ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
						}
						else
						{
							/* 篡改失败，直接发送reset请求 */
							Dbfw_Switchoff_Immediately_ForHandleNpc();
							continue;
						}
					}
					else
					{
						/* 不可篡改，只能发送阻断包 */
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[22.4] OraTnsPackageParse result is pass\n");
				}
#endif  /* HAVE_CHERRY */
			}
		} while (rt_com->tns_package_size>0);
	}
	else 
	{
		//Server->Client
		do 
		{
			rt_com->tns_pack_data = PG_Package_PreProcess(rt_com->tcp_info,PG2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[22.5] PG2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[22.6] PG2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 测试时可以注释掉下面这句话不进行解析 */
				parse_ret = PG_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,PG2USER,&rt_com->rewrite_packet);
				OraNet_DumpSql("step[22.7] PG2USER : parse over return = %d\n",parse_ret);
				if(rt_com->tns_pack_data!=NULL)
					ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
				/* Postgre目前只支持阻断，并且无法抛出异常 */
				if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[22.9] OraTnsPackageParse result is pass\n");
				}
#endif  /* HAVE_CHERRY */
			}
		} while (rt_com->tns_package_size>0);
	}
#endif 
	result = 0;	/* 继续后面的处理 */
	return result;
}

/*
	处理Kingbase通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/
int NPP_HandleKingbasePackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;
#ifdef ENABLE_KINGBASE
#ifdef HAVE_CHERRY
	/* 检查是否是可篡改的通讯包，并设置会话级的标记 */
	if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
	{
		/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
		__ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */
	}
	else
	{
		__ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
	}
#endif  /* HAVE_CHERRY */
	rt_com->tcp_buffer_size = PG_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
	//OraNet_DumpSql("step[23.1] rt_com->tcp_buffer_size=%d\n",rt_com->tcp_buffer_size);
	if (direction == USER2PG)
	{
		//Client->Server
		do 
		{
			/* 进行TNS包的拆包、拼包和包解析处理 */
			rt_com->tns_pack_data = PG_Package_PreProcess(rt_com->tcp_info,USER2PG,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[23.2] USER2PG: rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
			/* 检查是否有包头，并设置 */
			if(rt_npc->parseresult.parseresult_id == rt_cherry->last_parseresult_id_fortamper)
			{
				/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
				rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
				if(__ORA_SESSION->have_package_header==1)
				{
					__ORA_SESSION->tamper_pack_type = 1;
				}
			}                                
#endif
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[23.3] USER2PG : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 测试时可以注释掉下面这句话不进行解析 */
				parse_ret = PG_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2PG,&rt_com->rewrite_packet);
				if(rt_com->tns_pack_data!=NULL)
					ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
				/* 金仓目前只支持阻断，并且无法抛出异常 */
				 /* [C->S] KINGBASE数据库阻断和拦截处理 */
				if(rt_com->rewrite_packet.is_switchoff == 1) 
				{
					/*
						阻断处理
						1:先进行请求包的篡改
						2：篡改应答包数据
						3：发送reset
					*/
	#ifdef DEBUG_CHERRY
					printf("[C->S]MSTDSPackageParse result is switchoff\n");
	#endif
					if(__ORA_SESSION->start_for_oneway_audit == 1)
					{
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
					/* 步骤1：先篡改当前请求包 */
					 if(__ORA_SESSION->tamper_pack_type==1 && __ORA_SESSION->tamper_data_addr != NULL)
					{
						/* 
							有包头，可以篡改 
							篡改方法：将从第5字节(包长度)开始后面所有的数据替换为0xFF
						*/
						rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_KINGBASE;
						rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ5BYTE_00;
						rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
						
// 						char *ppp =  (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset;
// 						for (int tt=0;tt<rt_npc->cap_header->data_size;tt++)
// 						{
// 								printf("%x,", ppp[tt]); 
// 						}
// 						printf("\n");						

						parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
								(char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
								rt_npc->cap_header->data_size,
								sizeof(PG_Packet_CommonHead)
								);
						if(parse_ret>0)
						{
// 							char *ppp =  (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset;
// 							for (int tt=0;tt<rt_npc->cap_header->data_size;tt++)
// 							{
// 								printf("%x,", ppp[tt]); 
// 							}
// 							printf("\n"); 

							/* 篡改成功 */
							__ORA_SESSION->help_tamper_flag=DBFW_TAMPER_SWITCHOFF;
							__ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
						}
						else
						{
							/* 篡改失败，直接发送reset请求 */
							Dbfw_Switchoff_Immediately_ForHandleNpc();
							continue;
						}
					}
					else
					{
						/* 不可篡改，只能发送阻断包 */
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
				}
				else if 
				   (rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
				  )
				{
					/* 
						阻断或拦截
						PGSQL目前只支持阻断
					*/
					//Dbfw_Switchoff_Immediately_ForHandleNpc();
	#ifdef DEBUG_CHERRY
					printf("[CHERRY:MSSQL] rt_com->rewrite_packet.is_switchoff=%d,rt_com->rewrite_packet.packparse_result=%d\n",rt_com->rewrite_packet.is_switchoff,rt_com->rewrite_packet.packparse_result);
	#endif
					if(__ORA_SESSION->start_for_oneway_audit == 1)
					{
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
					//Dbfw_Switchoff_Immediately_ForHandleNpc();
					if(__ORA_SESSION->tamper_pack_type==1 && __ORA_SESSION->tamper_data_addr != NULL)
					{
						/* 
							有包头，可以篡改 
							篡改方法：将从第4字节(命令号)开始后面所有的数据替换为0x00
						*/
						rt_cherry->tamper_dbtype = DBFW_TAMPER_TYPE_KINGBASE;
						rt_cherry->tamper_mode = DBFW_TAMPER_TYPE_REQ5BYTE_00;
						rt_cherry->tamper_type = rt_cherry->tamper_dbtype|rt_cherry->tamper_mode;
						parse_ret = Dbfw_Package_Tamper(rt_cherry->tamper_type,
								(char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
								rt_npc->cap_header->data_size,
								sizeof(PG_Packet_CommonHead)
								);
						if(parse_ret>0)
						{
							/* 篡改成功 */
							__ORA_SESSION->help_tamper_flag=DBFW_TAMPER_THROW;
							__ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
						}
						else
						{
							/* 篡改失败，直接发送reset请求 */
							Dbfw_Switchoff_Immediately_ForHandleNpc();
							continue;
						}
					}
					else
					{
						/* 不可篡改，只能发送阻断包 */
						Dbfw_Switchoff_Immediately_ForHandleNpc();
						continue;
					}
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[23.4] OraTnsPackageParse result is pass\n");
				}
#endif  /* HAVE_CHERRY */
			}
		} while (rt_com->tns_package_size>0);
	}
	else 
	{
		//Server->Client
		do 
		{
			rt_com->tns_pack_data = PG_Package_PreProcess(rt_com->tcp_info,PG2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[23.5] PG2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[23.6] PG2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 测试时可以注释掉下面这句话不进行解析 */
				parse_ret = PG_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,PG2USER,&rt_com->rewrite_packet);
				OraNet_DumpSql("step[23.7] PG2USER : parse over return = %d\n",parse_ret);
				if(rt_com->tns_pack_data!=NULL)
					ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
				/* 金仓目前只支持阻断，并且无法抛出异常 */
				if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[23.8] OraTnsPackageParse result is pass\n");
				}
#endif  /* HAVE_CHERRY */
			}
		} while (rt_com->tns_package_size>0);
	}
#endif 
	result = 0;	/* 继续后面的处理 */
	return result;
}

/*
	处理Oscar通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/
int NPP_HandleOscarPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;
#ifdef ENABLE_OSCAR
    rt_com->tcp_buffer_size = OSCAR_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
    //OraNet_DumpSql("step[24.1] rt_com->tcp_buffer_size=%d\n",rt_com->tcp_buffer_size);
    if(direction==USER2OSCAR)
    {
        /* Client->Server */
        do 
        {
            /* 进行TNS包的拆包、拼包和包解析处理 */
            rt_com->tns_pack_data = OSCAR_Package_PreProcess(rt_com->tcp_info,USER2OSCAR,(u_int*)&rt_com->tns_package_size);
            //OraNet_DumpSql("step[24.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
            if(rt_com->tns_package_size>0)
            {
                OraNet_DumpSql("step[24.3] USER2OSCAR : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
                /* 测试时可以注释掉下面这句话不进行解析 */
                parse_ret = OSCAR_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2OSCAR,&rt_com->rewrite_packet);
                if(rt_com->tns_pack_data!=NULL)
                    ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
                /* 神通OSCAR目前只支持阻断，并且无法抛出异常 */
                if(rt_com->rewrite_packet.is_switchoff==1 ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
                  )
                {
                    /* 
                        阻断或拦截
                        MSSQL目前只支持阻断
                    */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[24.4] OraTnsPackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
            }
        } while (rt_com->tns_package_size>0);
    }
    else
    {
        /* Server->Client */
        do 
        {
            rt_com->tns_pack_data = OSCAR_Package_PreProcess(rt_com->tcp_info,OSCAR2USER,(u_int*)&rt_com->tns_package_size);
            //OraNet_DumpSql("step[24.5] OSCAR2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
            if(rt_com->tns_package_size>0)
            {
                OraNet_DumpSql("step[24.6] OSCAR2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
                /* 测试时可以注释掉下面这句话不进行解析 */
                parse_ret = OSCAR_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,OSCAR2USER,&rt_com->rewrite_packet);
                OraNet_DumpSql("step[24.7] OSCAR2USER : parse over return = %d\n",parse_ret);
                if(rt_com->tns_pack_data!=NULL)
                    ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
                /* 神通OSCAR目前只支持阻断，并且无法抛出异常 */
                if(rt_com->rewrite_packet.is_switchoff==1 ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
                  )
                {
                    /* 
                        阻断或拦截
                        MSSQL目前只支持阻断
                    */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[24.8] OraTnsPackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
            }
        } while (rt_com->tns_package_size>0);
    }
#endif
	result = 0;	/* 继续后面处理 */
	return result;
}

/*
	处理Informix/GBase8T通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/
int NPP_HandleInformixPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;
#ifdef ENABLE_IIF
	rt_com->tcp_buffer_size = IFX_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
	//OraNet_DumpSql("step[25.1] rt_com->tcp_buffer_size=%d\n",rt_com->tcp_buffer_size);
	if(direction==USER2IIF)
	{
		/* Client->Server */
		do 
		{
			/* 进行TNS包的拆包、拼包和包解析处理 */
			rt_com->tns_pack_data = IFX_Package_PreProcess(rt_com->tcp_info,USER2IIF,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[25.2] USER2IIF : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
			if(rt_npc->parseresult.parseresult_id == rt_cherry->last_parseresult_id_fortamper)
			{
				/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
				rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
				if(__ORA_SESSION->have_package_header == 1)
				{
					__ORA_SESSION->tamper_pack_type = 1;
				}                                    
			}
#endif 
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[25.3] USER2IIF : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 测试时可以注释掉下面这句话不进行解析 */
				parse_ret = IFX_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2IIF,&rt_com->rewrite_packet);
				if(rt_com->tns_pack_data!=NULL)
					ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
				/* informix目前只支持阻断，并且无法抛出异常 */
				if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[20.4] NPP_HandleDB2Package_ForHandleNpc result is pass\n");
				}
#endif  /* HAVE_CHERRY */
			}
		} while (rt_com->tns_package_size>0);
	}
	else
	{
		/* Server->Client */
		do 
		{
			rt_com->tns_pack_data = IFX_Package_PreProcess(rt_com->tcp_info,IIF2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[25.7] IIF2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[25.8] IIF2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 测试时可以注释掉下面这句话不进行解析 */
				parse_ret = IFX_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,IIF2USER,&rt_com->rewrite_packet);
				OraNet_DumpSql("step[25.9] IIF2USER : parse over return = %d\n",parse_ret);
				if(rt_com->tns_pack_data!=NULL)
					ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
               if(rt_com->rewrite_packet.is_switchoff==1 ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
                  )
                {
                    /* 
                        阻断或拦截
                        MSSQL目前只支持阻断
                    */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[25.10] OraTnsPackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
			}
		} while (rt_com->tns_package_size>0);
	}
#endif
	result = 0;	/* 继续后面处理 */
	return result;
}

/*
	处理CacheDB通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/
int NPP_HandleCacheDBPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;
#ifdef ENABLE_CACHEDB
	rt_com->tcp_buffer_size = CacheDB_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
	__ORA_SESSION->direction = direction;
	//OraNet_DumpSql("step[26.1] rt_com->tcp_buffer_size=%d\n",rt_com->tcp_buffer_size);
	if(direction==USER2CACHEDB)
	{
		/* Client->Server */
		do 
		{
			/* 进行TNS包的拆包、拼包和包解析处理 */
			rt_com->tns_pack_data = CacheDB_Package_PreProcess(rt_com->tcp_info,USER2CACHEDB,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[26.2] USER2CACHEDB : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[26.3] USER2CACHEDB : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 测试时可以注释掉下面这句话不进行解析 */
				parse_ret = CacheDB_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2CACHEDB,&rt_com->rewrite_packet);
				if(rt_com->tns_pack_data!=NULL)
					ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
				/* informix目前只支持阻断，并且无法抛出异常 */
				if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[20.4] NPP_HandleDB2Package_ForHandleNpc result is pass\n");
				}
#endif  /* HAVE_CHERRY */

			}
		} while (rt_com->tns_package_size>0);
	}
	else
	{
		/* Server->Client */
		do 
		{
			rt_com->tns_pack_data = CacheDB_Package_PreProcess(rt_com->tcp_info,CACHEDB2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("CACHEDB2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[26.4] CACHEDB2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 测试时可以注释掉下面这句话不进行解析 */
				parse_ret = CacheDB_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,CACHEDB2USER,&rt_com->rewrite_packet);
				OraNet_DumpSql("step[26.5] CACHEDB2USER : parse over return = %d\n",parse_ret);
				if(rt_com->tns_pack_data!=NULL)
					ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
			   if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[25.10] OraTnsPackageParse result is pass\n");
				}
#endif  /* HAVE_CHERRY */

			}
		} while (rt_com->tns_package_size>0);
	}
#endif
	result = 0;	/* 继续后面处理 */
	return result;
}
/*
	处理Teradata通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/
int NPP_HandleTeradataPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;
#ifdef ENABLE_TERADATA
#ifdef HAVE_CHERRY
    /* 检查是否是可篡改的通讯包，并设置会话级的可篡改标记 */
    if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
    {
        /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
        __ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */
        /* 在这里要判断SQL语句是否已经解析完成了，如没有完成，则肯定应该是当前包中会包含SQL语句的一部分 */
    }
    else
    {
        __ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
    }
#endif  /* HAVE_CHERRY */
    rt_com->tcp_buffer_size = Tera_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
    if(direction==USER2ORA)
    {
	    /* Client->Server */
	    do 
	    {
		    /* 进行TNS包的拆包、拼包和包解析处理 */
		    rt_com->tns_pack_data = Tera_Package_PreProcess(rt_com->tcp_info,USER2ORA,(u_int*)&rt_com->tns_package_size);
		    //OraNet_DumpSql("step[18.1] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
            /* 
                检查是否有包头，并设置 
                这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
                此时的结果会是help_parsesql_isover=1,have_package_header=1
                因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
            */
            if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
            {
                /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
                rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
                if(__ORA_SESSION->have_package_header==1)
                {
                    __ORA_SESSION->tamper_pack_type = 1;
                }                                    
            }
#endif
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
			    parse_ret = Tera_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&rt_com->rewrite_packet,&rt_npc->release_pack_data);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
				if(rt_npc->release_pack_data)
					ZFree(rt_npc->release_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
                
#ifdef HAVE_CHERRY
                /* [C->S] MSSQL数据库阻断和拦截处理 */
                if(rt_com->rewrite_packet.is_switchoff==1)
                {
                    /*
                        阻断处理
                        1:先进行请求包的篡改
                        2：篡改应答包数据
                        3：发送reset
                    */
#ifdef DEBUG_CHERRY
                    printf("[C->S]MSTDSPackageParse result is switchoff\n");
#endif
                    /* 步骤1：先篡改当前请求包 */
                    /* 由于目前MSSQL还没有完整的实现拦截应答包的篡改，所以这里强制tamper_pack_type为0 */

                        /* 不可篡改，只能发送阻断包 */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                /* MSSQL目前只支持阻断，并且无法抛出异常 */
                else if(rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
                  )
                {

                    /* 不可篡改，只能发送阻断包 */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[18.3] OraTnsPackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
		    }
	    } while (rt_com->tns_package_size>0);
    }
    else
    {
	    /* Server->Client */
	    do 
	    {
		    rt_com->tns_pack_data = Tera_Package_PreProcess(rt_com->tcp_info,ORA2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[18.4] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.5] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
			    parse_ret = Tera_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,&rt_com->rewrite_packet,&rt_npc->release_pack_data);
			    OraNet_DumpSql("step[18.6] ORA2USER : parse over return = %d\n",parse_ret);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
				if(rt_npc->release_pack_data)
					ZFree(rt_npc->release_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
				
#ifdef HAVE_CHERRY
                /* MSSQL目前只支持阻断，并且无法抛出异常 */
                if(rt_com->rewrite_packet.is_switchoff==1 ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
                  )
                {
                    /* 
                        阻断或拦截
                        MSSQL目前只支持阻断
                    */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
// 					result = 1;	/* 进入下一轮 */
// 					return result;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[18.7] OraTnsPackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
		    }
	    } while (rt_com->tns_package_size>0);
    }
#endif	/* ENABLE_MSSQL */
	result = 0;	/* 继续后面的处理 */
	return result;
}
int NPP_HandleHanaPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;
#ifdef ENABLE_HANA
#ifdef HAVE_CHERRY
    /* 检查是否是可篡改的通讯包，并设置会话级的可篡改标记 */
    if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
    {
        /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
        __ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */
        /* 在这里要判断SQL语句是否已经解析完成了，如没有完成，则肯定应该是当前包中会包含SQL语句的一部分 */
    }
    else
    {
        __ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
    }
#endif  /* HAVE_CHERRY */
    rt_com->tcp_buffer_size = Hana_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
    if(direction==USER2HANA)
    {
	    /* Client->Server */
	    do 
	    {
		    /* 进行TNS包的拆包、拼包和包解析处理 */
		    rt_com->tns_pack_data = Hana_Package_PreProcess(rt_com->tcp_info,USER2ORA,(u_int*)&rt_com->tns_package_size);
		    //OraNet_DumpSql("step[18.1] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
            /* 
                检查是否有包头，并设置 
                这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
                此时的结果会是help_parsesql_isover=1,have_package_header=1
                因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
            */
            if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
            {
                /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
                rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
                if(__ORA_SESSION->have_package_header==1)
                {
                    __ORA_SESSION->tamper_pack_type = 1;
                }                                    
            }
#endif
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
			    parse_ret = Hana_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&rt_com->rewrite_packet,&rt_npc->release_pack_data);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
				if(rt_npc->release_pack_data)
					ZFree(rt_npc->release_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
                
#ifdef HAVE_CHERRY
                /* [C->S] MSSQL数据库阻断和拦截处理 */
                if(rt_com->rewrite_packet.is_switchoff==1)
                {
                    /*
                        阻断处理
                        1:先进行请求包的篡改
                        2：篡改应答包数据
                        3：发送reset
                    */
#ifdef DEBUG_CHERRY
                    printf("[C->S]MSTDSPackageParse result is switchoff\n");
#endif
                    /* 步骤1：先篡改当前请求包 */
                    /* 由于目前MSSQL还没有完整的实现拦截应答包的篡改，所以这里强制tamper_pack_type为0 */

                        /* 不可篡改，只能发送阻断包 */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                /* MSSQL目前只支持阻断，并且无法抛出异常 */
                else if(rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
                  )
                {

                    /* 不可篡改，只能发送阻断包 */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[18.3] OraTnsPackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
		    }
	    } while (rt_com->tns_package_size>0);
    }
    else
    {
	    /* Server->Client */
	    do 
	    {
		    rt_com->tns_pack_data = Hana_Package_PreProcess(rt_com->tcp_info,ORA2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[18.4] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.5] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
			    parse_ret = Hana_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,&rt_com->rewrite_packet,&rt_npc->release_pack_data);
			    OraNet_DumpSql("step[18.6] ORA2USER : parse over return = %d\n",parse_ret);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
				if(rt_npc->release_pack_data)
					ZFree(rt_npc->release_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
				
#ifdef HAVE_CHERRY
                /* MSSQL目前只支持阻断，并且无法抛出异常 */
                if(rt_com->rewrite_packet.is_switchoff==1 ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
                  )
                {
                    /* 
                        阻断或拦截
                        MSSQL目前只支持阻断
                    */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
// 					result = 1;	/* 进入下一轮 */
// 					return result;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[18.7] OraTnsPackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
		    }
	    } while (rt_com->tns_package_size>0);
    }
#endif	/* ENABLE_MSSQL */
	result = 0;	/* 继续后面?拇??? */
	return result;
}

int NPP_HandleGaussdbTPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;
#ifdef ENABLE_GAUSSDB_T
#ifdef HAVE_CHERRY
    /* 检查是否是可篡改的通讯包，并设置会话级的可篡改标记 */
    if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
    {
        /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
        __ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */
        /* 在这里要判断SQL语句是否已经解析完成了，如没有完成，则肯定应该是当前包中会包含SQL语句的一部分 */
    }
    else
    {
        __ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
    }
#endif  /* HAVE_CHERRY */
    rt_com->tcp_buffer_size = GaussdbT_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
    if(direction==USER2GAUSSDB)
    {
	    /* Client->Server */
	    do 
	    {
		    /* 进行TNS包的拆包、拼包和包解析处理 */
		    rt_com->tns_pack_data = GaussdbT_Package_PreProcess(rt_com->tcp_info,USER2ORA,(u_int*)&rt_com->tns_package_size);
		    //OraNet_DumpSql("step[18.1] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
            /* 
                检查是否有包头，并设置 
                这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
                此时的结果会是help_parsesql_isover=1,have_package_header=1
                因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
            */
            if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
            {
                /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
                rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
                if(__ORA_SESSION->have_package_header==1)
                {
                    __ORA_SESSION->tamper_pack_type = 1;
                }                                    
            }
#endif
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
			    parse_ret = GaussdbT_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&rt_com->rewrite_packet,&rt_npc->release_pack_data);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
				if(rt_npc->release_pack_data)
					ZFree(rt_npc->release_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
                
#ifdef HAVE_CHERRY
                /* [C->S] MSSQL数据库阻断和拦截处理 */
                if(rt_com->rewrite_packet.is_switchoff==1)
                {
                    /*
                        阻断处理
                        1:先进行请求包的篡改
                        2：篡改应答包数据
                        3：发送reset
                    */
#ifdef DEBUG_CHERRY
                    printf("[C->S]MSTDSPackageParse result is switchoff\n");
#endif
                    /* 步骤1：先篡改当前请求包 */
                    /* 由于目前MSSQL还没有完整的实现拦截应答包的篡改，所以这里强制tamper_pack_type为0 */

                        /* 不可篡改，只能发送阻断包 */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                /* MSSQL目前只支持阻断，并且无法抛出异常 */
                else if(rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
                  )
                {

                    /* 不可篡改，只能发送阻断包 */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[18.3] OraTnsPackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
		    }
	    } while (rt_com->tns_package_size>0);
    }
    else
    {
	    /* Server->Client */
	    do 
	    {
		    rt_com->tns_pack_data = GaussdbT_Package_PreProcess(rt_com->tcp_info,ORA2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[18.4] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.5] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
			    parse_ret = GaussdbT_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,&rt_com->rewrite_packet,&rt_npc->release_pack_data);
			    OraNet_DumpSql("step[18.6] ORA2USER : parse over return = %d\n",parse_ret);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
				if(rt_npc->release_pack_data)
					ZFree(rt_npc->release_pack_data);

                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
				
#ifdef HAVE_CHERRY
                /* MSSQL目前只支持阻断，并且无法抛出异常 */
                if(rt_com->rewrite_packet.is_switchoff==1 ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
                  )
                {
                    /* 
                        阻断或拦截
                        MSSQL目前只支持阻断
                    */
                    Dbfw_Switchoff_Immediately_ForHandleNpc();
                    continue;
// 					result = 1;	/* 进入下一轮 */
// 					return result;
                }
                else
                {
                    /* 放行 */
                    OraNet_DumpSql("step[18.7] OraTnsPackageParse result is pass\n");
                }
#endif  /* HAVE_CHERRY */
		    }
	    } while (rt_com->tns_package_size>0);
    }
#endif	/* ENABLE_MSSQL */
	result = 0;	/* 继续后面?拇??? */
	return result;
}

#ifdef ENABLE_HIVE
/*
	处理Hive通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/

int NPP_HandleHivePackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
    int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;

	
    OraNet_DumpSql("NPP_HandleHivePackage_ForHandleNpc Begin\n");
    //dump_byte_stream(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size);
#ifdef HAVE_CHERRY
		/* 检查是否是可篡改的通讯包，并设置会话级的可篡改标记 */
		if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
		{
			/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
			__ORA_SESSION->current_is_tamperable_pack = 1;	/* 是可篡改的通讯包 */
			/* 在这里要判断SQL语句是否已经解析完成了，如没有完成，则肯定应该是当前包中会包含SQL语句的一部分 */
		}
		else
		{
			__ORA_SESSION->current_is_tamperable_pack = 0;	/* 不是可篡改的通讯包 */
		}
#endif  /* HAVE_CHERRY */

    rt_com->tcp_buffer_size = Hive_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);

    //if(direction==USER2HIVE)
	//{
		/* Client->Server */
	do 
	{
		/* 进行TNS包的拆包、拼包和包解析处理 */
		rt_com->tns_pack_data = Hive_Package_PreProcess(rt_com->tcp_info,direction,(u_int*)&rt_com->tns_package_size);
		//OraNet_DumpSql("step[26.2] USER2CACHEDB : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
		/* 
			检查是否有包头，并设置 
			这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
			此时的结果会是help_parsesql_isover=1,have_package_header=1
			因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
		*/
		if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
		{
			/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
			rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
			if(__ORA_SESSION->have_package_header==1)
			{
				__ORA_SESSION->tamper_pack_type = 1;
			}									 
		}
#endif

		if(rt_com->tns_package_size>0)
		{
			OraNet_DumpSql("step[26.3] USER2HIVE : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			/* 测试时可以注释掉下面这句话不进行解析 */
			dump_byte_stream(rt_com->tns_pack_data,rt_com->tns_package_size);
			parse_ret = Hive_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,direction,&rt_com->rewrite_packet);
			if(rt_com->tns_pack_data!=NULL)
				ZFree(rt_com->tns_pack_data);
            parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
            /* [C->S] MSSQL数据库阻断和拦截处理 */
            if(rt_com->rewrite_packet.is_switchoff==1)
            {
                /*
                    阻断处理
                    1:先进行请求包的篡改
                    2：篡改应答包数据
                    3：发送reset
                */
#ifdef DEBUG_CHERRY
                printf("[C->S]MSTDSPackageParse result is switchoff\n");
#endif
                /* 步骤1：先篡改当前请求包 */
                /* 由于目前MSSQL还没有完整的实现拦截应答包的篡改，所以这里强制tamper_pack_type为0 */

                    /* 不可篡改，只能发送阻断包 */
                Dbfw_Switchoff_Immediately_ForHandleNpc();
                continue;
            }
            /* MSSQL目前只支持阻断，并且无法抛出异常 */
            else if(rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
               rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
               rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
               __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
              )
            {

                /* 不可篡改，只能发送阻断包 */
                Dbfw_Switchoff_Immediately_ForHandleNpc();
                continue;
            }
            else
            {
                /* 放行 */
                OraNet_DumpSql("step[18.3] OraTnsPackageParse result is pass\n");
            }
#endif  /* HAVE_CHERRY */

		}
	} while (rt_com->tns_package_size>0);
	//}

	result = 0;	/* 继续后面处理 */
	return result;
}
#endif
#ifdef ENABLE_HRPC
/*
	处理hdfs protobuf通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/

int NPP_HandleHdfsProtoPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
    int direction = 0;
    int result = 0;	/* 返回结果 */
    int parse_ret = 0;	/* 解析结果 */
    direction = rt_npc->parseresult.direction;
#ifdef ENABLE_HRPC
    #ifdef HAVE_CHERRY
    /* 检查是否是可篡改的通讯包，并设置会话级的可篡改标记 */
    if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
    {
        /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
        __ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */
    }
    else
    {
        __ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
    }
#endif  /* HAVE_CHERRY */
    rt_com->tcp_buffer_size = HdfsProto_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
    if(direction==USER2ORA)
    {
	    /* Client->Server */
	    do
	    {
		    /* 进行TNS包的拆包、拼包和包解析处理 */
		    rt_com->tns_pack_data = HdfsProto_Package_PreProcess(rt_com->tcp_info,USER2ORA,(u_int*)&rt_com->tns_package_size);
		    //OraNet_DumpSql("step[18.1] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
            /*
                检查是否有包头，并设置
                这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
                此时的结果会是help_parsesql_isover=1,have_package_header=1
                因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
            */
            if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
            {
                /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
                rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
                if(__ORA_SESSION->have_package_header==1)
                {
                    __ORA_SESSION->tamper_pack_type = 1;
                }
            }
#endif
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
			    parse_ret = HdfsProto_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&rt_com->rewrite_packet);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet, __ORA_SESSION, direction);
#ifdef HAVE_CHERRY
				/* informix目前只支持阻断，并且无法抛出异常 */
				if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[20.4] NPP_HandleHdfsProtoPackage_ForHandleNpc result is pass\n");
				}
#endif  /* HAVE_CHERRY */
            }
	    } while (rt_com->tns_package_size>0);
    }
    else
    {
	    /* Server->Client */
	    do
	    {
		    rt_com->tns_pack_data = HdfsProto_Package_PreProcess(rt_com->tcp_info,ORA2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[18.4] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.5] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
			    parse_ret = HdfsProto_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,&rt_com->rewrite_packet);
			    OraNet_DumpSql("step[18.6] ORA2USER : parse over return = %d\n",parse_ret);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
                OraNet_DumpSql("debug:NPP_SqlProcess=%d\n",parse_ret);
#ifdef HAVE_CHERRY
			   if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[25.10] OraTnsPackageParse result is pass\n");
				}
#endif  /* HAVE_CHERRY */
		    }
	    } while (rt_com->tns_package_size>0);
    }
#endif
    result = 0;	/* 继续后面的处理 */
    return result;
}
#endif
#ifdef ENABLE_SENTRY
int NPP_HandleSentryPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;
    OraNet_DumpSql("NPP_HandleSentryPackage_ForHandleNpc Begin\n");
#ifdef HAVE_CHERRY
		if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
		{
			__ORA_SESSION->current_is_tamperable_pack = 1;	/* 是可篡改的通讯包 */
		}
		else
		{
			__ORA_SESSION->current_is_tamperable_pack = 0;	/* 不是可篡改的通讯包 */
		}
#endif  /* HAVE_CHERRY */
    rt_com->tcp_buffer_size = Sentry_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
	do 
	{
		rt_com->tns_pack_data = Sentry_Package_PreProcess(rt_com->tcp_info,direction,(u_int*)&rt_com->tns_package_size);
#ifdef HAVE_CHERRY
		if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
		{
			rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
			if(__ORA_SESSION->have_package_header==1)
			{
				__ORA_SESSION->tamper_pack_type = 1;
			}									 
		}
#endif
		if(rt_com->tns_package_size>0)
		{
			OraNet_DumpSql("step[26.3] USER2SENTRY : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			dump_byte_stream(rt_com->tns_pack_data,rt_com->tns_package_size);
			rt_npc->release_pack_data = NULL;
			parse_ret = Sentry_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,direction,&rt_com->rewrite_packet);
			if(rt_com->tns_pack_data!=NULL)
				ZFree(rt_com->tns_pack_data);
			if(rt_npc->release_pack_data != NULL)
				ZFree(rt_npc->release_pack_data);
            parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
            if(rt_com->rewrite_packet.is_switchoff==1)
            {
#ifdef DEBUG_CHERRY
                printf("[C->S]SentryPackageParse result is switchoff\n");
#endif
                Dbfw_Switchoff_Immediately_ForHandleNpc();
                continue;
            }
            else if(rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
               rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
               rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
               __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
              )
            {
                Dbfw_Switchoff_Immediately_ForHandleNpc();
                continue;
            }
            else
            {
                OraNet_DumpSql("step[18.3] SentrysPackageParse result is pass\n");
            }
#endif  /* HAVE_CHERRY */
		}
	} while (rt_com->tns_package_size>0);
	result = 0;	/* 继续后面处理 */
	return result;
}
#endif

#ifdef ENABLE_REDIS
int NPP_HandleRedisPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0; /* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;

    OraNet_DumpSql("NPP_HandleRedisPackage_ForHandleNpc Begin\n");

#ifdef HAVE_CHERRY
	/* 检查是否是可篡改的通讯包，并设置会话级的可篡改标记 */
	if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
	{
		/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
		__ORA_SESSION->current_is_tamperable_pack = 1;	/* 是可篡改的通讯包 */
	}
	else
	{
		__ORA_SESSION->current_is_tamperable_pack = 0;	/* 不是可篡改的通讯包 */
	}
#endif  /* HAVE_CHERRY */
	rt_com->tcp_buffer_size = Redis_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
	if(direction==USER2ORA)
	{
		/* Client->Server */
		do
		{
			/* 进行TNS包的拆包、拼包和包解析处理 */
			rt_com->tns_pack_data = Redis_Package_PreProcess(rt_com->tcp_info,USER2ORA,(u_int*)&rt_com->tns_package_size);
#ifdef HAVE_CHERRY
			/*
				检查是否有包头，并设置
				这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
				此时的结果会是help_parsesql_isover=1,have_package_header=1
				因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
			*/
			if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
			{
				/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
				rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
				if(__ORA_SESSION->have_package_header==1)
				{
					__ORA_SESSION->tamper_pack_type = 1;
				}
			}
#endif
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[18.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
				parse_ret = Redis_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&rt_com->rewrite_packet);
				if(rt_com->tns_pack_data!=NULL)
					ZFree(rt_com->tns_pack_data);
				parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet, __ORA_SESSION, direction);
#ifdef HAVE_CHERRY
				if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[20.4] NPP_HandleRedisPackage_ForHandleNpc result is pass\n");
				}
#endif  /* HAVE_CHERRY */
			}
		} while (rt_com->tns_package_size>0);
	}
	else
	{
		/* Server->Client */
		do
		{
			rt_com->tns_pack_data = Redis_Package_PreProcess(rt_com->tcp_info,ORA2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[18.4] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[18.5] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
				parse_ret = Redis_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,&rt_com->rewrite_packet);
				OraNet_DumpSql("step[18.6] ORA2USER : parse over return = %d\n",parse_ret);
				if(rt_com->tns_pack_data!=NULL)
					ZFree(rt_com->tns_pack_data);
				parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
				OraNet_DumpSql("debug:NPP_SqlProcess=%d\n",parse_ret);
#ifdef HAVE_CHERRY
			   if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[25.10] OraTnsPackageParse result is pass\n");
				}
#endif  /* HAVE_CHERRY */
			}
		} while (rt_com->tns_package_size>0);
	}
	result = 0; /* 继续后面的处理 */
	return result;
}

#endif


int NPP_HandleTelnetPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
#ifdef ENABLE_TELNET
	direction = rt_npc->parseresult.direction;
    /* Oracle通讯协议处理 */
	/* 性能测试点3,持续占用1.3~1.7CPU */
	//break;
    rt_com->tcp_buffer_size = Telnet_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
    //OraNet_DumpSql("step[17.1] rt_com->tcp_buffer_size=%d\n",rt_com->tcp_buffer_size);
    if(direction==USER2ORA)
    {
        /* Client->Server */
        do 
        {
            /* 进行TNS包的拆包、拼包和包解析处理 */
            rt_com->tns_pack_data = Telnet_Package_PreProcess(rt_com->tcp_info,USER2ORA,(u_int*)&rt_com->tns_package_size);
            //OraNet_DumpSql("step[17.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
            if(rt_com->tns_package_size>0)
            {
                OraNet_DumpSql("step[17.3] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
                /* 性能测试点3.1 注释掉下面的解析函数调用,持续占用1.7CPU */
                parse_ret = TelnetPackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&rt_com->rewrite_packet);
                if(rt_com->tns_pack_data!=NULL)
                    ZFree(rt_com->tns_pack_data);
            }
        } while (rt_com->tns_package_size>0);
    }
    else
    {
        /* Server->Client */
        do 
        {
            rt_com->tns_pack_data = Telnet_Package_PreProcess(rt_com->tcp_info,ORA2USER,(u_int*)&rt_com->tns_package_size);
            if(rt_com->tns_package_size>0)
            {
                OraNet_DumpSql("step[17.6] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 性能测试点3.2 注释掉下面的解析函数调用,持续占用1.7CPU */
                parse_ret = TelnetPackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,&rt_com->rewrite_packet);
                //OraNet_DumpSql("step[17.7] ORA2USER : parse over return = %d\n",parse_ret);
                if(rt_com->tns_pack_data!=NULL)
                    ZFree(rt_com->tns_pack_data);

            }
        } while (rt_com->tns_package_size>0);
    }
#endif
	result = 0;	/* 继续后面的处理 */
	return result;
}
#ifdef ENABLE_IMPALA
int NPP_HandleImpalaPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
    int direction = 0;
	int result = 0;	/* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;
    OraNet_DumpSql("NPP_HandleImpalaPackage_ForHandleNpc Begin\n");
#ifdef HAVE_CHERRY
		if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
		{
			__ORA_SESSION->current_is_tamperable_pack = 1;	/* 是可篡改的通讯包 */
		}
		else
		{
			__ORA_SESSION->current_is_tamperable_pack = 0;	/* 不是可篡改的通讯包 */
		}
#endif  /* HAVE_CHERRY */
    rt_com->tcp_buffer_size = Impala_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
	do 
	{
		rt_com->tns_pack_data = Impala_Package_PreProcess(rt_com->tcp_info,direction,(u_int*)&rt_com->tns_package_size);
#ifdef HAVE_CHERRY
		if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
		{
			rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
			if(__ORA_SESSION->have_package_header==1)
			{
				__ORA_SESSION->tamper_pack_type = 1;
			}									 
		}
#endif
		if(rt_com->tns_package_size>0)
		{
			OraNet_DumpSql("step[26.3] USER2HIVE : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			//dump_byte_stream(rt_com->tns_pack_data,rt_com->tns_package_size);
			rt_npc->release_pack_data = NULL;
			parse_ret = Impala_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,direction,&rt_com->rewrite_packet);
			if(rt_com->tns_pack_data!=NULL)
				ZFree(rt_com->tns_pack_data);
            parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
#ifdef HAVE_CHERRY
            if(rt_com->rewrite_packet.is_switchoff==1)
            {
#ifdef DEBUG_CHERRY
                printf("[C->S]MSTDSPackageParse result is switchoff\n");
#endif
                Dbfw_Switchoff_Immediately_ForHandleNpc();
                continue;
            }
            else if(rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
               rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
               rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
               __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
                   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
              )
            {
                Dbfw_Switchoff_Immediately_ForHandleNpc();
                continue;
            }
            else
            {
                OraNet_DumpSql("step[18.3] OraTnsPackageParse result is pass\n");
            }
#endif  /* HAVE_CHERRY */
		}
	} while (rt_com->tns_package_size>0);
	result = 0;	/* 继续后面处理 */
	return result;
}
#endif

#ifdef ENABLE_ES
/*
	处理elasticsearch通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/

int NPP_HandleESPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
    int direction = 0;
    int result = 0;	/* 返回结果 */
    int parse_ret = 0;	/* 解析结果 */
    direction = rt_npc->parseresult.direction;
#ifdef ENABLE_ES
    #ifdef HAVE_CHERRY
    /* 检查是否是可篡改的通讯包，并设置会话级的可篡改标记 */
    if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
    {
        /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
        __ORA_SESSION->current_is_tamperable_pack = 1;  /* 是可篡改的通讯包 */
    }
    else
    {
        __ORA_SESSION->current_is_tamperable_pack = 0;  /* 不是可篡改的通讯包 */
    }
#endif  /* HAVE_CHERRY */
    rt_com->tcp_buffer_size = ES_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
    if(direction==USER2ORA)
    {
	    /* Client->Server */
	    do
	    {
		    /* 进行TNS包的拆包、拼包和包解析处理 */
		    rt_com->tns_pack_data = ES_Package_PreProcess(rt_com->tcp_info,USER2ORA,(u_int*)&rt_com->tns_package_size);
		    //OraNet_DumpSql("step[18.1] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
#ifdef HAVE_CHERRY
            /*
                检查是否有包头，并设置
                这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
                此时的结果会是help_parsesql_isover=1,have_package_header=1
                因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
            */
            if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
            {
                /* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
                rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
                if(__ORA_SESSION->have_package_header==1)
                {
                    __ORA_SESSION->tamper_pack_type = 1;
                }
            }
#endif
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
			    parse_ret = ES_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&rt_com->rewrite_packet);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet, __ORA_SESSION, direction);
#ifdef HAVE_CHERRY
				/* informix目前只支持阻断，并且无法抛出异常 */
				if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[20.4] NPP_HandleESPackage_ForHandleNpc result is pass\n");
				}
#endif  /* HAVE_CHERRY */
            }
	    } while (rt_com->tns_package_size>0);
    }
    else
    {
	    /* Server->Client */
	    do
	    {
		    rt_com->tns_pack_data = ES_Package_PreProcess(rt_com->tcp_info,ORA2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[18.4] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
		    if(rt_com->tns_package_size>0)
		    {
			    OraNet_DumpSql("step[18.5] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			    /* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
			    parse_ret = ES_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,&rt_com->rewrite_packet);
			    OraNet_DumpSql("step[18.6] ORA2USER : parse over return = %d\n",parse_ret);
			    if(rt_com->tns_pack_data!=NULL)
				    ZFree(rt_com->tns_pack_data);
                parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
                OraNet_DumpSql("debug:NPP_SqlProcess=%d\n",parse_ret);
#ifdef HAVE_CHERRY
			   if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[25.10] OraTnsPackageParse result is pass\n");
				}
#endif  /* HAVE_CHERRY */
		    }
	    } while (rt_com->tns_package_size>0);
    }
#endif
    result = 0;	/* 继续后面的处理 */
    return result;
}
#endif


#ifdef ENABLE_WEBHTTP
/*
	处理Hdfs http通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/

int NPP_HandleWebHttpPackage_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	int direction = 0;
	int result = 0; /* 返回结果 */
	int parse_ret = 0;	/* 解析结果 */
	direction = rt_npc->parseresult.direction;

#ifdef ENABLE_WEBHTTP
    OraNet_DumpSql("NPP_HandleWebhttpPackage_ForHandleNpc Begin\n");

#ifdef HAVE_CHERRY
	/* 检查是否是可篡改的通讯包，并设置会话级的可篡改标记 */
	if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
	{
		/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
		__ORA_SESSION->current_is_tamperable_pack = 1;	/* 是可篡改的通讯包 */
	}
	else
	{
		__ORA_SESSION->current_is_tamperable_pack = 0;	/* 不是可篡改的通讯包 */
	}
#endif  /* HAVE_CHERRY */
	rt_com->tcp_buffer_size = WebHttp_AddTcpPackageToBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_com->tcp_info,direction);
	if(direction==USER2ORA)
	{
		/* Client->Server */
		do
		{
			/* 进行TNS包的拆包、拼包和包解析处理 */
			rt_com->tns_pack_data = WebHttp_Package_PreProcess(rt_com->tcp_info,USER2ORA,(u_int*)&rt_com->tns_package_size);
#ifdef HAVE_CHERRY
			/*
				检查是否有包头，并设置
				这里需要注意的是由于使用了do..while,在解析完全不通讯包后，仍然会执行一次do，
				此时的结果会是help_parsesql_isover=1,have_package_header=1
				因此基于help_parsesql_isover的判断应该在OraTnsPackageParse函数之后立即进行，不能在执行了最后一次do之后
			*/
			if(rt_npc->parseresult.parseresult_id==rt_cherry->last_parseresult_id_fortamper)
			{
				/* 当前的rt_npc->parseresult是最后一个，而不是乱序缓冲区中其他的rt_npc->parseresult */
				rt_npc->parseresult.have_packheader = __ORA_SESSION->have_package_header;
				if(__ORA_SESSION->have_package_header==1)
				{
					__ORA_SESSION->tamper_pack_type = 1;
				}
			}
#endif
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[18.2] USER2ORA : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
				parse_ret = WebHttp_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,USER2ORA,&rt_com->rewrite_packet);
				if(rt_com->tns_pack_data!=NULL)
					ZFree(rt_com->tns_pack_data);
				parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet, __ORA_SESSION, direction);
#ifdef HAVE_CHERRY
				if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[20.4] NPP_HandleWebHttpPackage_ForHandleNpc result is pass\n");
				}
#endif  /* HAVE_CHERRY */
			}
		} while (rt_com->tns_package_size>0);
	}
	else
	{
		/* Server->Client */
		do
		{
			rt_com->tns_pack_data = WebHttp_Package_PreProcess(rt_com->tcp_info,ORA2USER,(u_int*)&rt_com->tns_package_size);
			//OraNet_DumpSql("step[18.4] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
			if(rt_com->tns_package_size>0)
			{
				OraNet_DumpSql("step[18.5] ORA2USER : rt_com->tns_package_size=%d\n",rt_com->tns_package_size);
				/* 测试时可以注释掉下面这句话不进行解析 */
				rt_npc->release_pack_data = NULL;
				parse_ret = WebHttp_PackageParse(rt_com->tns_pack_data,rt_com->tns_package_size,0,0,rt_com->tcp_info,ORA2USER,&rt_com->rewrite_packet);
				OraNet_DumpSql("step[18.6] ORA2USER : parse over return = %d\n",parse_ret);
				if(rt_com->tns_pack_data!=NULL)
					ZFree(rt_com->tns_pack_data);
				parse_ret = NPP_SqlProcess(&rt_com->rewrite_packet,__ORA_SESSION,direction);
				OraNet_DumpSql("debug:NPP_SqlProcess=%d\n",parse_ret);
#ifdef HAVE_CHERRY
			   if(rt_com->rewrite_packet.is_switchoff==1 ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
				   rt_com->rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF ||
				   __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW
				  )
				{
					/* 
						阻断或拦截
						MSSQL目前只支持阻断
					*/
					Dbfw_Switchoff_Immediately_ForHandleNpc();
					continue;
				}
				else
				{
					/* 放行 */
					OraNet_DumpSql("step[25.10] OraTnsPackageParse result is pass\n");
				}
#endif  /* HAVE_CHERRY */
			}
		} while (rt_com->tns_package_size>0);
	}
#endif
	result = 0; /* 继续后面的处理 */
	return result;
}

#endif


/*
	从乱序缓冲区获取下一个顺序包
	返回值
		1 - continue loop(失败),继续外层的while循环
		0 - 离开外层的while循环
*/
int NPP_GetNextReorderPackFromBuffer_ForHandleNpc(Npp_Runtime_Common *rt_com, Npp_Runtime_HandleNpc *rt_npc, Npp_Runtime_ForCherry *rt_cherry)
{
	u_int	direction = 0;				/* 通讯的方向 */
	int ret = 0;
	int result = 0;	/* 返回结果0或1 */
	direction = rt_npc->parseresult.direction;
	/* 取得下一个hash表中的通讯包 */
#ifdef NEW_TCP_REORDER
	/* 从乱序包缓冲区中取出下一个连续的通讯包 */
	if(Dbfw_TcpReorder_GetOutOfOrderPackCount(&rt_npc->new_tcpreorder_buffer)>0)
	{
		do 
		{
			rt_npc->tcp_nextorder_result = Dbfw_TcpReorder_GetNextReorderPack(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult);
			if(rt_npc->tcp_nextorder_result==0)
			{
				/* 没有匹配的，重新开始 */
				break;  /* 从这里离开 */
			}
			else if(rt_npc->tcp_nextorder_result==-1)
			{
				/* 没有匹配的，重新开始 */
				//OraNet_DumpSql("step[28.1] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_GetNextReorderPack] no match pack, continue\n");
				continue;
			}
			else if(rt_npc->tcp_nextorder_result==1)
			{
				/* 找到匹配的 */
				break;
			}
		} while (1==1);

		if(rt_npc->tcp_nextorder_result==0)
		{
			/* 没有匹配的，重新开始(跳出while) */
			OraNet_DumpSql("step[28.2] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_GetNextReorderPack] no match pack, continue\n");
			return 0;	/* 跳出外层的while循环 */
		}
		else if(rt_npc->tcp_nextorder_result==1)
		{
			/* 找到匹配的，继续解析(不跳出while) */
            OraNet_DumpSql("step[28.3] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_GetNextReorderPack] match ok,"
                           "begin parse, [sec=%u , ack=%u, size=%u, direction = %s]\n"
                           , rt_npc->parseresult.tcp_header.sequence, rt_npc->parseresult.tcp_header.acknowledge
                           , rt_npc->parseresult.data_size, (rt_npc->parseresult.direction == USER2ORA ? "Request" : "Response"));
			ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,rt_npc->parseresult.direction,rt_com->alive_time);
			__ORA_SESSION->tamper_data_addr = NULL;
			direction = rt_npc->parseresult.direction;
			return 1;	/* 跳出外层的while循环 */
		}
		else
		{
			/* 未知情况，跳出while */
			OraNet_DumpSql("step[28.4] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_GetNextReorderPack] unknown continue\n");
			//break;
			return 0;	/* 跳出外层的while循环 */
		}
	}                    
	else
	{
		//break;
		return 0;	/* 跳出外层的while循环 */
	}
#else   /* NEW_TCP_REORDER */
	/* 下面删除了已经不再使用的HAVE_TCP_RECORDER相关程序 */
	return 0;	/* 跳出外层的while循环 */
#endif  /* NEW_TCP_REORDER */
}

/*
** 登录规则校验、登录频次校验
** 函数内部需要判断是登录频次校验，还是登录规则校验
** 
*/
int NPP_ConnectFilter(OraNet8_Session * ora_session,Npp_RewriteNetPacket*rewrite_packet)
{
	int ret = 0,s=0, i = 0;
	int login_status = -1;
	Dbfw_SqlCommon  sql_common;
	Dbfw_AcEngine_ObjectParams_new ac_param;
	Dbfw_FilterSqlCommon filter_sqlcommon;
	Web_Client_Info* web_clint_info = NULL;
	char lua_path[256];
	memset(lua_path,0x00,sizeof(lua_path));
	struct ac_ukey_info  * ukey_info = NULL;
	char find_db_web = 0;   /* 0- 未开启web认证， 1 开启 未认证成功， 2 开启 认证成功 */
	char find_db_ukey = 0;
	char  web_user[65] = {0};
	char  ukey_user[65] = {0};


	if(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->udmp_stat == 2)
	{
		NPP_MakeSessInsert_Data(ora_session);
		ora_session->ac_service_conn_handle = -3;
		if(ora_session->record_status == SESS_RECORD_STATUS_FINISH_LOG)
		{
			ora_session->record_status = SESS_RECORD_STATUS_NEED_UPDATE;
		}
		((SessBuf_SessionData_Ora *)(ora_session->sessdata))->udmp_stat = 3;
	}

	if(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->mdmp_stat == 2)
	{
		NPP_MakeSessInsert_AppData(ora_session);
		//ora_session->ac_service_conn_handle = -3;
		//if(ora_session->record_status == SESS_RECORD_STATUS_FINISH_LOG)
		//{
		//	ora_session->record_status = SESS_RECORD_STATUS_NEED_UPDATE;
		//}
	//	((SessBuf_SessionData_Ora *)(ora_session->sessdata))->mdmp_stat = 3;
	}

	/* 会话找回 */
	
	if((__NPP_ALL_CONFIG->s_sessinfo_replace_switch == DBFW_SWITCH_ON)&&((ora_session->login_frequency == 1)||ora_session->ac_service_conn_handle == -3 || ora_session->sessCommon.error_code != 0))
	{
	    /* "数据库帐户自动填写":3.2.2.1 会话信息保存到SGA区 */
	    if(ora_session->help_session_state == DBFW_SESSION_STATE_NORMAL && ora_session->unconn_savesga_flag == 0 && ora_session->sessCommon.error_code != 18456)
	    {
	    	if(ora_session->sessCommon.user_name.value.length>0)
	    	{
	        	Unconn_CompareAndAddIdenConnectInfo(ora_session,(void*)__SGA_RTBUF.data.ora_unconnect_protocol_data);
	        }	
	    }    
		if(ora_session->unconn_have_conninfo_fromsga == 0 && ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->udmp_stat !=3 && ((SessBuf_SessionData_Ora *)(ora_session->sessdata))->udmp_stat != 2 &&
		(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->username[0]==0x00 ||strcmp((char*)((SessBuf_SessionData_Ora *)(ora_session->sessdata))->username,"未知用户")==0))
		{
			ret = Dbfw_SessInfoFindFromSga(ora_session);
			if(ret == 1)
			{
				((SessBuf_SessionData_Ora *)(ora_session->sessdata))->udmp_stat = 3;
				NPP_MakeSessInsert_Data(ora_session);
				if(ora_session->ac_service_conn_handle == -1)
					ora_session->ac_service_conn_handle = -3;
			}
		}
	}

	if((ora_session->login_frequency == 1)
	    ||(ora_session->ac_service_conn_handle == -3 && ora_session->sessCommon.error_code == 0)
	    ||(ora_session->connect_step == 1))
	{
		OraNet_DumpSql("===========================NPP_ConnectFilter\n");
		OraNet_DumpSql("ora_session->login_frequency:%d  ora_session->ac_service_conn_handle:%d connect_step = %d\n"
		    ,ora_session->login_frequency
		    ,ora_session->ac_service_conn_handle
		    ,ora_session->connect_step);
		OraNet_DumpSql("client_ip:%llu,%llu\n",ora_session->sessCommon.client_ip[0],ora_session->sessCommon.client_ip[1]);
	}
	else
	{
		return 1;
	}
	
	Dbfw_Rule_InitParams(&ac_param);
	memset(&sql_common,0, sizeof(sql_common));
	Dbfw_SqlCommon_Init(&sql_common);
	/* 需要写初始化函数 */
	Dbfw_FilterSqlCommon_Init(&filter_sqlcommon);

	if(ora_session->connect_step == 1)
	{
		DBFW_Filter_VPatch_Connect(&(ora_session->sessCommon),&sql_common,&(ora_session->filter_sesscommon));
		ora_session->connect_step++;
	}
	if(ora_session->login_frequency == 1 || ora_session->ac_service_conn_handle == -3)
	{
		/* 密码桥用户 */
#ifdef DBFW_PASSWD_BRIDGE
		if(strlen((char*)ora_session->passwd_bridge.web_name) > 0)
		{
			memset(ora_session->filter_sesscommon.auth_webuser, 0x00, sizeof(ora_session->filter_sesscommon.auth_webuser));
			copy_web_user(ora_session, (char*)ora_session->passwd_bridge.web_name, strlen((char*)ora_session->passwd_bridge.web_name), (char*)ora_session->filter_sesscommon.auth_webuser);
			//memcpy(ora_session->filter_sesscommon.auth_webuser, ora_session->passwd_bridge.web_name, strlen((char*)ora_session->passwd_bridge.web_name));
			//Dbfw_TypedVarData_Assign(&sql_common.approval_web_user, (u_char *)ora_session->filter_sesscommon.auth_webuser,strlen((const char*)ora_session->filter_sesscommon.auth_webuser),LOG_DATA_APPROVAL_WEB_USER);
			copy_approval_web_user(&sql_common, &ora_session->filter_sesscommon);
			//ora_session->sessCommon.authen_type = OPERATION_TYPE_BRIDGE;
			Dbfw_TypedVarData_Assign(&ora_session->sessCommon.authen_type, (u_char*)operation_type_bridge,strlen(operation_type_bridge),LOG_DATA_APPROVAL_OPERATOR_TYPE);
			Dbfw_TypedVarData_Assign(&ora_session->sessCommon.operation_name, (u_char *)ora_session->filter_sesscommon.auth_webuser,strlen((const char*)ora_session->filter_sesscommon.auth_webuser),LOG_DATA_APPROVAL_WEB_USER);
		}
#endif
		/* 查找ip，未找到阻断，找到ip没有用户也阻断 */
		if(ora_session->filter_sesscommon.s_webauth == 1)
		{
			find_db_web = 1; 
			if(web_clint_info == NULL)
			{
				web_clint_info = Get_Web_Client_Info_By_Key(&__SGA_ACBUF,(u_char *)((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip_str);
				if(web_clint_info != NULL)
				{
					if(web_clint_info->db_count > 0)
					{
						for(i = 0; i < web_clint_info->db_count; i++)
						{
							if((short)web_clint_info->db_values[i*2] == ora_session->sessCommon.database_id)
							{
								find_db_web = 2;
								break;
							}
						}
					}
					if(find_db_web == 2)
					{
						OraNet_DumpSql("web_clint_info->auth_user:%s\n",web_clint_info->auth_user);
						memcpy(web_user, web_clint_info->auth_user, strlen((char*)web_clint_info->auth_user));
						//memcpy(ora_session->filter_sesscommon.auth_webuser,web_clint_info->auth_user,strlen((char*)web_clint_info->auth_user));
						//Dbfw_TypedVarData_Assign(&sql_common.approval_web_user, (u_char *)ora_session->filter_sesscommon.auth_webuser,strlen((const char*)ora_session->filter_sesscommon.auth_webuser),LOG_DATA_APPROVAL_WEB_USER);
					}
	        	}
        	}
        }
		if(find_db_web == 1)
		{
			/* web 开启 未验证通过，不用在看ukey了 */
			sql_common.result_audit=1;
			sql_common.rule_id = 9999997;
			sql_common.baseline_id = 1;
			sql_common.result_control = 1;
			sql_common.result_delevery = 1;
			sql_common.threat_level = 5;
#ifdef HAVE_RISK_LEVEL_BMJ
			sql_common.threat_level_bmj= '8';
#endif
			sql_common.blackorwhite = DBFW_RISK_CONNECT_ACCESS;
		}
		else
		{
			if(__ORA_SESSION->filter_sesscommon.s_usbkeyauth == 1)
			{
				/* web 没找到，找ukey */
				find_db_ukey = 1;
				u_int64 usb_key = 0;
				if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip[1] > 0)
				{
					usb_key = ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip[0] ^ ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip[1];
				}
				else
				{
					usb_key = ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip[0];
				}
				OraNet_DumpSql("usb_key:%llu\n",usb_key);
				ukey_info = (struct ac_ukey_info *)HashMap_Find((struct Hash_map*)__SGA_ACBUF.data.ac_usb_key->data_values, usb_key);
				if(ukey_info != NULL)
				{
					if(ukey_info->db_id[ora_session->sessCommon.database_id] == 1)
					{
						find_db_ukey = 2;
						OraNet_DumpSql("ukey_info->web_user:%s\n", ukey_info->web_user);
						OraNet_DumpSql("ukey_info->os_user:%s\n", ukey_info->os_user);
						OraNet_DumpSql("ukey_info->mac:%s\n", ukey_info->mac);
						OraNet_DumpSql("ukey_info->ip[0]:%u\n", ukey_info->ip.u32[0]);
						OraNet_DumpSql("ukey_info->ip[1]:%u\n", ukey_info->ip.u32[1]);
						OraNet_DumpSql("ukey_info->ip[2]:%u\n", ukey_info->ip.u32[2]);
						OraNet_DumpSql("ukey_info->ip[3]:%u\n", ukey_info->ip.u32[3]);
						memcpy(ukey_user, ukey_info->web_user,strlen((char*)ukey_info->web_user));

						//memcpy(ora_session->filter_sesscommon.auth_webuser,ukey_info->web_user,strlen((char*)ukey_info->web_user));
						//Dbfw_TypedVarData_Assign(&sql_common.approval_web_user, (u_char *)ora_session->filter_sesscommon.auth_webuser,strlen((const char*)ora_session->filter_sesscommon.auth_webuser),LOG_DATA_APPROVAL_WEB_USER);
						if(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_mac[0]  == '\0')
							memcpy(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->client_mac, ukey_info->mac, strlen((char*)ukey_info->mac));
						if(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->auth_sid[0]  == '\0')
							memcpy(((SessBuf_SessionData_Ora *)(ora_session->sessdata))->auth_sid, ukey_info->os_user, strlen((char*)ukey_info->os_user));
					}
					else
					{
						find_db_ukey = 1;
					}
				}
			}
			if(find_db_web == 0)
			{
				if(find_db_ukey == 1)
				{
					sql_common.result_audit=1;
					sql_common.rule_id = 9999997;
					sql_common.baseline_id = 1;
					sql_common.result_control = 1;
					sql_common.result_delevery = 1;
					sql_common.threat_level = 5;
		#ifdef HAVE_RISK_LEVEL_BMJ
					sql_common.threat_level_bmj= '8';
		#endif
					sql_common.blackorwhite = DBFW_RISK_CONNECT_ACCESS;
				}
				else if(find_db_ukey == 2)
				{
					memset(ora_session->filter_sesscommon.auth_webuser, 0x00, sizeof(ora_session->filter_sesscommon.auth_webuser));
					copy_web_user(ora_session, (char*)ukey_user, strlen((char*)ukey_user), (char*)ora_session->filter_sesscommon.auth_webuser);
					//memcpy(ora_session->filter_sesscommon.auth_webuser, ukey_user, strlen((char*)ukey_user));
					//Dbfw_TypedVarData_Assign(&sql_common.approval_web_user, (u_char *)ora_session->filter_sesscommon.auth_webuser,strlen((const char*)ora_session->filter_sesscommon.auth_webuser),LOG_DATA_APPROVAL_WEB_USER);
					copy_approval_web_user(&sql_common, &ora_session->filter_sesscommon);
					//ora_session->sessCommon.authen_type = OPERATION_TYPE_UKEY;
					Dbfw_TypedVarData_Assign(&ora_session->sessCommon.authen_type, (u_char*)operation_type_ukey,strlen(operation_type_ukey),LOG_DATA_APPROVAL_OPERATOR_TYPE);
					Dbfw_TypedVarData_Assign(&ora_session->sessCommon.operation_name, (u_char *)ora_session->filter_sesscommon.auth_webuser,strlen((const char*)ora_session->filter_sesscommon.auth_webuser),LOG_DATA_APPROVAL_WEB_USER);
				}
			}
			else
			{
				if(find_db_ukey == 1)
				{
					sql_common.result_audit=1;
					sql_common.rule_id = 9999997;
					sql_common.baseline_id = 1;
					sql_common.result_control = 1;
					sql_common.result_delevery = 1;
					sql_common.threat_level = 5;
		#ifdef HAVE_RISK_LEVEL_BMJ
					sql_common.threat_level_bmj= '8';
		#endif
					sql_common.blackorwhite = DBFW_RISK_CONNECT_ACCESS;
				}
				else if(find_db_ukey == 2)
				{
					if((strlen((char*)web_user) == strlen((char*)ukey_user)) && (memcmp(web_user, ukey_user, strlen((char*)ukey_user)) == 0))
					{
						memset(ora_session->filter_sesscommon.auth_webuser, 0x00, sizeof(ora_session->filter_sesscommon.auth_webuser));
						copy_web_user(ora_session, (char*)web_user, strlen((char*)web_user), (char*)ora_session->filter_sesscommon.auth_webuser);
						//memcpy(ora_session->filter_sesscommon.auth_webuser, web_user, strlen((char*)web_user));
						//Dbfw_TypedVarData_Assign(&sql_common.approval_web_user, (u_char *)ora_session->filter_sesscommon.auth_webuser,strlen((const char*)ora_session->filter_sesscommon.auth_webuser),LOG_DATA_APPROVAL_WEB_USER);
						copy_approval_web_user(&sql_common, &ora_session->filter_sesscommon);
						//ora_session->sessCommon.authen_type = OPERATION_TYPE_UKEY;
						Dbfw_TypedVarData_Assign(&ora_session->sessCommon.authen_type, (u_char*)operation_type_ukey,strlen(operation_type_ukey),LOG_DATA_APPROVAL_OPERATOR_TYPE);
						Dbfw_TypedVarData_Assign(&ora_session->sessCommon.operation_name, (u_char *)ora_session->filter_sesscommon.auth_webuser,strlen((const char*)ora_session->filter_sesscommon.auth_webuser),LOG_DATA_APPROVAL_WEB_USER);
					}
					else
					{
						sql_common.result_audit=1;
						sql_common.rule_id = 9999997;
						sql_common.baseline_id = 1;
						sql_common.result_control = 1;
						sql_common.result_delevery = 1;
						sql_common.threat_level = 5;
			#ifdef HAVE_RISK_LEVEL_BMJ
						sql_common.threat_level_bmj= '8';
			#endif
						sql_common.blackorwhite = DBFW_RISK_CONNECT_ACCESS;
					}
				}
				else
				{
					memset(ora_session->filter_sesscommon.auth_webuser, 0x00, sizeof(ora_session->filter_sesscommon.auth_webuser));
					copy_web_user(ora_session, (char*)web_user, strlen((char*)web_user), (char*)ora_session->filter_sesscommon.auth_webuser);
					//memcpy(ora_session->filter_sesscommon.auth_webuser, web_user, strlen((char*)web_user));
					//Dbfw_TypedVarData_Assign(&sql_common.approval_web_user, (u_char *)ora_session->filter_sesscommon.auth_webuser,strlen((const char*)ora_session->filter_sesscommon.auth_webuser),LOG_DATA_APPROVAL_WEB_USER);
					copy_approval_web_user(&sql_common, &ora_session->filter_sesscommon);
					//ora_session->sessCommon.authen_type = OPERATION_TYPE_WEB;
					Dbfw_TypedVarData_Assign(&ora_session->sessCommon.authen_type, (u_char*)operation_type_web,strlen(operation_type_web),LOG_DATA_APPROVAL_OPERATOR_TYPE);
					Dbfw_TypedVarData_Assign(&ora_session->sessCommon.operation_name, (u_char *)ora_session->filter_sesscommon.auth_webuser,strlen((const char*)ora_session->filter_sesscommon.auth_webuser),LOG_DATA_APPROVAL_WEB_USER);
				}
			}
		}
	}
	if(ora_session->login_frequency == 1)
	{
		if(ora_session->help_login_state== 0x01)
			login_status = 1;
		else if(ora_session->help_login_state== 0x02)
			login_status = 2;
		if(__NPP_ALL_CONFIG->global_change_count_forrule%2 == 0)
		{
			ora_session->filter_sesscommon.g_sga_login_rwLock = &((__SGA_ACBUF).data.acbuf_locks->rwlock_66);
			ora_session->filter_sesscommon.g_sga_login = (u_char*)((__SGA_ACBUF).data.ac_login_frequency_buff0->acserver_buf); //A/B区最后的8M内存空间
		}
		else
		{
			ora_session->filter_sesscommon.g_sga_login_rwLock = &((__SGA_ACBUF).data.acbuf_locks->rwlock_67);
			ora_session->filter_sesscommon.g_sga_login = (u_char*)((__SGA_ACBUF).data.ac_login_frequency_buff1->acserver_buf); //A/B区最后的8M内存空间
		}

        ret = Dynamic_Rules_Engine_LOGIN(&sql_common,
                                         &(ora_session->sessCommon),
                                         &(ora_session->filter_sesscommon),
                                         &filter_sqlcommon,&ac_param,
                                         login_status);
		
		ora_session->login_frequency = 2;
	}
	if(ora_session->ac_service_conn_handle == -3 && ora_session->sessCommon.error_code == 0)
    {
#ifdef HAVE_APPROVAL
		GetLocalTime_Now(&(ora_session->filter_sesscommon.code_login_time));
#endif
        ora_session->ac_service_conn_handle = -1;
        ora_session->filter_sesscommon.ac_service_conn_handle = ora_session->ac_service_conn_handle;

        sql_common.threat_level_bmj = 8;
        OraNet_DumpSql("NppMain Dynamic_Rules_Engine ABNum = %d\n ",__NPP_ALL_CONFIG->global_change_count_forrule);
#ifdef HAVE_LUA
		if(__NPP_ALL_CONFIG->s_lua_rule_switch == 1)
		{
			if(ora_session->filter_sesscommon.lua_session_init == 0)
			{
				L = lua_open();
				luaL_openlibs(L);
				SessionData_register(L);
				StatementData_register(L);
				lua_pop(L,1);

				__SessionData_Ptr = &(ora_session->sessCommon);
				memset(lua_path,0x00,sizeof(lua_path));
				z_strcpy(lua_path,__NPP_ALL_CONFIG->s_lua_init, __FILE__, __LINE__, Smem_LogError_Format);
				strcat(lua_path,(char*)"SessionInit.lua");
				s = luaL_loadfile(L,lua_path);
				stackDumpsql(L);
				s = lua_pcall(L, 0, LUA_MULTRET, 0);
				stackDumpsql(L);
				if(s!=0)
				{
					Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"load SessionInit.lua:%s",luaL_checkstring(L,-1));
				}
				ora_session->filter_sesscommon.lua_session_init = 1;
				ora_session->filter_sesscommon.L = L;
			}
		}
#endif
		
		if(sql_common.blackorwhite != DBFW_RISK_CONNECT_ACCESS)
        {
	        ret = Dynamic_Rules_Engine(&sql_common,
                           &(ora_session->sessCommon),
                           &(ora_session->filter_sesscommon),
                           &filter_sqlcommon,&ac_param);
        }
    }
        /* 将引擎返回的信息转给session */
    filter_result_change(&sql_common);
    ora_session->sessCommon.baseline_id = sql_common.baseline_id;
    ora_session->sessCommon.rule_id = sql_common.rule_id;
    ora_session->sessCommon.result_audit = sql_common.result_audit;
    ora_session->sessCommon.result_control = sql_common.result_control;
    ora_session->sessCommon.result_delevery = sql_common.result_delevery;
    ora_session->sessCommon.threat_level = sql_common.threat_level;
    ora_session->sessCommon.threat_level_bmj = sql_common.threat_level_bmj;
    ora_session->sessCommon.rule_type_category = sql_common.blackorwhite;
    OraNet_DumpSql("ac_param.connect_rule_str.length:%d\n",ac_param.connect_rule_str.length);
	/* ?§?°??????????????  */
	DBFW_DYNAMIC_STR  rule_id_str;
	Dbfw_Init_Dynamic_String(&rule_id_str, "",128,128);
	if(sql_common.rule_id_str.value.length> 0)
	{
		/* ???÷????????°?±? */
		Dbfw_DynStr_Append_Mem(&rule_id_str,(char*)sql_common.rule_id_str.value.str+sizeof(Dbfw_TypedVarDataItem),sql_common.rule_id_str.value.length-sizeof(Dbfw_TypedVarDataItem));
	}
	if(ac_param.connect_rule_str.length >0)
	{
		if(rule_id_str.length == 0)
			Dbfw_DynStr_Append_Mem(&rule_id_str, (char*)&__NPP_ALL_CONFIG->learn_version, sizeof(int));
		Dbfw_DynStr_Append_Mem(&rule_id_str,(char*)ac_param.connect_rule_str.str,ac_param.connect_rule_str.length);
	}
	
    if(rule_id_str.length> 0)
    {
        Dbfw_TypedVarData_Dyna_Append (&ora_session->sessCommon.rule_id_str,(u_char*)rule_id_str.str,rule_id_str.length, LOG_DATA_RULEID_STR,0);
	}
	Dbfw_DynStr_Free(&rule_id_str);

	OraNet_DumpSql("ret:%d\n",ret);
    OraNet_DumpSql("rule_id:%d\n",sql_common.rule_id);
    OraNet_DumpSql("result_audit:%c\n",sql_common.result_audit);
    OraNet_DumpSql("result_control:%c\n",sql_common.result_control);
    OraNet_DumpSql("threat_level:%c\n",sql_common.threat_level);
    OraNet_DumpSql("baseline_id:%d\n",sql_common.baseline_id);
    OraNet_DumpSql("rule_type_category:%d\n",sql_common.blackorwhite);
    OraNet_DumpSql("result_delevery:%c\n",sql_common.result_delevery);
    if(ora_session->sessCommon.threat_level > '0' || ora_session->sessCommon.rule_id_str.value.length>0)
    {
    	if(ora_session->record_status == SESS_RECORD_STATUS_FINISH_LOG)
		{
			ora_session->record_status = SESS_RECORD_STATUS_NEED_UPDATE;
		}
		else if(ora_session->record_status == SESS_RECORD_STATUS_INIT)
		{
    		ora_session->record_status = SESS_RECORD_STATUS_NEED_INSERT;
    	}
    	NPP_MakeSessInsert_Data(ora_session);
    }
    if(ora_session->sessCommon.result_control == DBFW_SWITCHOFF_CHAR || ora_session->sessCommon.result_control == DBFW_BLOCKING_THROW_CHAR)
	{
		rewrite_packet->is_switchoff = 1;
		rewrite_packet->packparse_result = NPP_RESULT_SWITCHOFF;
	}
#ifdef HAVE_CHERRY
	if(__NPP_PROCESS_TYPE == NPP_PROCESS_TYPE_TRANSPARENT || __NPP_PROCESS_TYPE == NPP_PROCESS_TYPE_NPC)
	{
		if(rewrite_packet->is_switchoff==1 || rewrite_packet->packparse_result == NPP_RESULT_SWITCHOFF ||
			rewrite_packet->packparse_result == NPP_RESULT_BLOCKING_THROW)
		{
			Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
#ifdef DUMP_MEMORY_LEAK
			__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
#else
			__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
#endif
		}
	}
#endif
    Dbfw_Rule_UnInitParams(&ac_param);
    Dbfw_FilterSqlCommon_Release(&filter_sqlcommon);
    Dbfw_SqlCommon_Release(&sql_common);
    
	return ret;
}

/*
	处理Oracle通讯包，用于HandleNPC
	返回值
		1 - continue loop(失败)
		0 - 继续后面的处理(匹配成功)
*/






void handle_npc(Npp_ProcessParam p_processParam)
{
#ifdef USE_NPC
	Npp_Runtime_Common		*rt_com = NULL;
	Npp_Runtime_HandleNpc	*rt_npc = NULL;
	Npp_Runtime_ForCherry	*rt_cherry = NULL;
    u_int i = 0;
    int ret = 0;
    FILE        *dump_tcpdata    = NULL;
	int		parse_ret = 0;				/* 协议解析结果 默认值=0 */
	u_int	direction = 0;				/* 通讯的方向 */
	//u_char* capbuf_addr = NULL;			/* capbuf区的地址 */
	//char errbuf[256];					/* API调用返回的错误信息 */
	Dspr_MemQueue_Err queue_err ;
	memset(&queue_err, 0, sizeof(Dspr_MemQueue_Err));

	rt_com = (Npp_Runtime_Common *)ZMalloc(sizeof(Npp_Runtime_Common));
	rt_npc = (Npp_Runtime_HandleNpc *)ZMalloc(sizeof(Npp_Runtime_HandleNpc));
	rt_cherry = (Npp_Runtime_ForCherry *)ZMalloc(sizeof(Npp_Runtime_ForCherry));	

	/* 初始化CHERRY防火墙 : 发送队列初始化 */
    memset(&__NPP_ALL_CONFIG->nfw_memqueue_node,0x00,sizeof(Dspr_MemQueue_Node));
    __NPP_ALL_CONFIG->memqueue = (Dspr_MemQueue_t *)(__SGA_RTBUF.data.npp2nfw);

	ret = Init_HandleNpc_Variable(rt_com,rt_npc,rt_cherry,p_processParam);
	if(ret<0)
	{
		/* 初始化变量异常 */
		/* 此处不能直接return，这样有些申请的内存不会被释放，且session的槽位也不会释放 */
		goto handle_npc_quit_real;
	}

#ifdef ENABLE_TLS
	if(__ORA_SESSION->tls_switch == 1)
		OPENSSL_add_all_algorithms_noconf();
#endif  

    
#ifdef HAVE_CHERRY
    /* 初始化timestamp_fin为0 */
    __ORA_SESSION->timestamp_fin = 0;
#endif

	OraNet_DumpSql("cherry step[1] : init nfw_memqueue_node,memqueue ok\n");  

	/*陈寿仓添加*/
#ifdef DUMP_TCPDATA
	/* 不建议开放：dump tcp包数据到acp文件，已经几乎不被使用了,并且声称的acp文件中的TCP头信息是不正确的 */
	if(!dump_tcpdata)
	{
		u_char npc_data_filename[128];
		time_t log_time;
		u_char cur_time[32];
		time(&log_time);
		strftime((char*)cur_time, 32, "%Y%m%d%H%M%S", localtime(&log_time));
		sprintf((char*)npc_data_filename, "./dump_tcpdata_npc_%s_%s(%u)_%s(%u).cap", cur_time,rt_com->tcp_info->client_ip,rt_com->tcp_info->client_port,rt_com->tcp_info->oracle_server_ip,rt_com->tcp_info->oracle_server_port);
		dump_tcpdata = fopen((char*)npc_data_filename,"wb");                    
	}
	if(dump_tcpdata)
	{
		create_acp(dump_tcpdata);
	}
#endif
	/*陈寿仓添加结束*/	

  
handle_npc_start_loop:
	OraNet_DumpSql("step[3] enter handle_npc_start_loop\n ");
    for(;;)
    {
		/************************************************************************/
		/* 循环的起始位置先处理防火墙通讯包修改逻辑(for cherry)                       */
		/************************************************************************/
		ret = Npp_Cherry_DoTamper_ForHandleNpc(rt_com,rt_npc,rt_cherry);
		/************************************************************************/
		/* [结束 for cherry]防火墙通讯包修改逻辑                                          */
		/************************************************************************/

		/************************************************************************/
		/* 在每次循环开始时，进行进程状态和信号量检查和处理，包括如下：
		   进程DBFW_HANDLEEXIT_FORMEMCHECK退出标记的检查
		   信号量超时
		   DBFW_HANDLEEXIT_FORREORDER检查
		   并进行相应处理  */
		/************************************************************************/
		ret = NPP_SemwaitAndExitFlag_ForHandleNpc(rt_com,rt_npc,rt_cherry);
		switch (ret)
		{
		case -2:
			goto handle_npc_quit;
		case -1:
			goto handle_npc_quit_real;
		case 1:
			continue;
			break;
		case 0:	/* 继续后面的处理 */
			break;
		case 2:
			/* 
				丢包和包乱序的超时处理 
				1：旧的丢包排序算法，使用原有的逻辑(已经删除该部分代码)
				2：NEW_TCP_REORDER排序算法
				处理后 continue
			*/
			/* 2016-04-12 这里删除了已经不再使用的HAVE_TCP_RECORDER算法相关的代码 */
#ifdef NEW_TCP_REORDER
			if(rt_npc->timeout_recorder>=3 || __NPP_ALL_CONFIG->process_exit_flag == DBFW_HANDLEEXIT_FORREORDER)
			{
				/* 当rt_npc->timeout_recorder记录了最近3秒都没有包 */
				//Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"exit_flag is DBFW_HANDLEEXIT_FORREORDER enter into NEW_TCP_REORDER");
				if(Dbfw_TcpReorder_GetOutOfOrderPackCount(&rt_npc->new_tcpreorder_buffer)>0)
				{
					/* 
						在rt_npc->new_tcpreorder_buffer包乱序缓冲区中有通讯包，表示存在乱序的通讯包,并且在最近3秒内都没有新的通讯包被收到，认为出现了异常
						丢包处理 ：
						如果发生丢包，则将session下所有的stmt都要释放，同时将缓冲区清除
					*/
					OraNet_DumpSql("step[4.21] exception clear session for losepack with 3 sec of DBFW_HANDLEEXIT_FORREORDER no pack\n");
					Ora_ClearTcpPackageBuffer(rt_com->tcp_info);
					ClearSession_ForLosePack(__ORA_SESSION);
					rt_npc->isReleaseAllStmtForNpcLossPack_flag = 1;	/* 设置rt_npc->isReleaseAllStmtForNpcLossPack_flag标记 */
					/* 修复天翼爱音乐现场出现的MySQL丢包引起的SGA乱问题 */
					if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL || __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG)
					{
						if(MYSQL_LoginOver(__ORA_SESSION)==0)
						{
							/* 没有登录完成，需要按照无连接会话处理 */
							OraNet_DumpSql("step[4.22] NPP_SetSessionForHandlePcap for mysql not login\n");
							NPP_SetSessionForHandlePcap(__ORA_SESSION);
						}
					}
					/* 
						fix bug 2103
						丢包后:
						1:先将当前通讯包加入到乱序缓冲区中，因为当前通讯包可能是缓冲区中最“前”的通讯包(废弃，原因看下面的注释)
						2:从缓冲区中取出第一个通讯包作为丢包后的第一个处理的通讯包
					*/
					/* 1:将乱序包加入到乱序包缓冲区(强制填充)注意：这里不能加入缓冲区，会造成死循环 */
					//ret = Dbfw_TcpReorder_AddOutOfOrderPackToBuffer(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,1);
					/* 2:从乱序缓冲区中获取第一个通讯包 */
					ret = Dbfw_TcpReorder_UseFirstOutOfReorderPack(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult);
					if(ret>0)
					{
						if(__ORA_SESSION)
						{
							__ORA_SESSION->loss_count++;
						}
						/* 成功,使用获取的第一个通讯包作为新的“开始” */
						OraNet_DumpSql("step[4.23] exception timeout 3 sec of DBFW_HANDLEEXIT_FORREORDER [DBFW_TCPPACKAGE_LOSS:Dbfw_TcpReorder_UseFirstOutOfReorderPack] have match pack\n");
						rt_npc->tcpsecquence_error_flag = 0;
						ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,rt_npc->parseresult.direction,rt_com->alive_time);
						__ORA_SESSION->tamper_data_addr = NULL;
						direction = rt_npc->parseresult.direction;
						if(rt_npc->timeout_recorder>=3)
							rt_npc->timeout_recorder = 0;
						OraNet_DumpSql("step[4.24] goto handle_npc_parsedata[sec=%u , ack=%u, size=%u]\n",
								rt_npc->parseresult.tcp_header.sequence,
								rt_npc->parseresult.tcp_header.acknowledge,
								rt_npc->parseresult.data_size);
                        OraNet_DumpSql("step[14.20] [DBFW_TCPPACKAGE_OUTOFORDER:Dbfw_TcpReorder_UseFirstOutOfReorderPack] match ok,"
                                       "begin parse, [sec=%u , ack=%u, size=%u, direction = %s]\n"
                                       , rt_npc->parseresult.tcp_header.sequence, rt_npc->parseresult.tcp_header.acknowledge
                                       , rt_npc->parseresult.data_size, (rt_npc->parseresult.direction == USER2ORA ? "Request" : "Response"));
						goto handle_npc_parsedata;    /* 进入通讯包的协议解析 */
					}
					else
					{
						/* 
							获取第一个通讯包失败，重新开始下一轮解析
							后面有统一的continue处理，不应在这里continue
						*/
						//continue;
					}
				}
				if(__NPP_ALL_CONFIG->process_exit_flag == DBFW_HANDLEEXIT_FORREORDER)
				{
					//Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"change process_exit_flag from DBFW_HANDLEEXIT_FORREORDER to DBFW_HANDLEEXIT_NORMAL");
					OraNet_DumpSql("step[4.25] exception for DBFW_HANDLEEXIT_FORREORDER\n");
#ifndef DUMP_MEMORY_LEAK
//#ifdef HAVE_CHERRY
					/* guoxw 20160113 支持cherry npp进程池模式 */
					//__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
					__NPP_ALL_CONFIG->process_exit_flag = 0;
					goto handle_npc_quit;
//#else	/* HAVE_CHERRY */
//					__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
//#endif	/* HAVE_CHERRY */
#else	/* DUMP_MEMORY_LEAK */
					__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
#endif	/* DUMP_MEMORY_LEAK */
				}
			}
#endif	/* NEW_TCP_REORDER */
			continue;
			break;
		default:
			break;
		}
		/************************************************************************/
		/* [结束] 信号量超时，和DBFW_HANDLEEXIT_FORREORDER的处理程序                    */
		/************************************************************************/

		/* 进程挂起状态检查，如果是挂起的进程则continue */
		/* 处理退出标记 */
		process_exit_forflag();	
		
		/************************************************************************/
		/* 
			step5 各种异常状态的检查和处理:包括IP全0，内存超限,退出标记检查
		*/
		/************************************************************************/
		/* step 5 */
		ret = NPP_ProcessException_ForHandleNpc(rt_com,rt_npc,rt_cherry);
		switch (ret)
		{
			case -2:
				goto handle_npc_quit;
			case -1:
				goto handle_npc_quit_real;
			case 1:
				continue;
				break;
			case 0:	/* 继续后面的处理 */
				break;
			default:
				break;
		}

        rt_npc->timeout_recorder = 0;       /* 清持续时间 */

        /************************************************************************/
		/*  前台页面引起的配置变更检查
			如果有配置变更，则Npp_CheckChangeAndReloadAllConfig函数内部将刷新缓冲区，并重置参数和计数值                                                                   
		*/
		/************************************************************************/
		Npp_CheckChangeAndReloadAllConfig(__NPP_ALL_CONFIG);
		if(__DB_ISFIND == 0 && __NPP_ALL_CONFIG->has_inst == 0)
			goto handle_npc_quit_real;

		/************************************************************************/
		/* NPP进程心跳处理：刷新Alivetime                                         */
		/************************************************************************/
        NPP_Alivetime_ForHandleNpc(rt_com,rt_npc,rt_cherry);

		/************************************************************************/
		/* 
			2014-05-12 检查并初始化包乱序缓冲区
			这里删除了已经不再使用的HAVE_TCP_RECORDER处理程序
		*/
		/************************************************************************/
#ifdef NEW_TCP_REORDER

        if(rt_npc->new_tcpreorder_buffer.out_of_order_buff==NULL)
        {
        	rt_npc->new_tcpreorder_buffer.out_of_order_buff = (Dbfw_OutOfOrderBuffer*)ZMalloc(sizeof(Dbfw_OutOfOrderBuffer));
        }
#endif

		/************************************************************************/
		/* step 8 开始从capbuf区获取可用的通讯包,并检查获取是否出现异常                  */
		/************************************************************************/
		ret = NPP_ReadTisHeaderFromCapbuf_ForHandleNpc(rt_com,rt_npc,rt_cherry);
		switch (ret)
		{
			case -2:
				goto handle_npc_quit;
			case -1:
				goto handle_npc_quit_real;
			case 1:
				continue;
				break;
			case 0:	/* 继续后面的处理 */
				break;
			default:
				break;
		}
		/************************************************************************/
		/* [结束]从capbuf区获取可用的通讯包                                                  */
		/************************************************************************/

		/* 性能测试点1,占用1.0~1.3CPU */
		//continue;		

		/************************************************************************/
		/* 下面开始了正式处理数据包的逻辑，是最复杂的逻辑                                  */
		/************************************************************************/
		if(rt_npc->cap_header->data_size>0)
        {
#ifdef HAVE_CHERRY
            /* 设置被篡改数据的指针和数据尺寸 */
            if(__ORA_SESSION)
            {
                __ORA_SESSION->tamper_data_addr = (u_char*)Dbfw_Package_TamperGetDataAddr(
                        (char*)rt_npc->loop_data->capbuf_addr+rt_npc->cap_header->data_offset,
                        rt_npc->cap_header->data_size,
                        (u_int*)&__ORA_SESSION->tamper_data_size
                        );
                __ORA_SESSION->tamper_pack_type = 0;    /* 包状态设置为“未知” */
            }
#endif
			/************************************************************************/
			/* step 9 拷贝TIS区的通讯包数据并解析出数据包，保存到rt_npc->parseresult      */
			/************************************************************************/
			ret = NPP_ReadTisDataFromCapbuf_ForHandleNpc(rt_com,rt_npc,rt_cherry);

		
			if(Tis_Content_Type(rt_npc->tis) == 1)				          // tis content block模式
			{
				if(__NPP_ALL_CONFIG->start_for_transparent==0)  /* nfw旁路模式和新版tis的npc模式 */
				{
					__NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_MIRROR_TYPE_NORMAL;
	            	__NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
				
					dspr_memqueue_put(__NPP_ALL_CONFIG->memqueue,(Dspr_MemQueue_Node*)&__NPP_ALL_CONFIG->nfw_memqueue_node, &queue_err);
					if((queue_err.err_no&DSPR_MQ_FULL_1) || (queue_err.err_no&DSPR_MQ_FULL_2))
					{
						Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" memqueue put generate ERR ,_iSend:%llud, irecv:%llud , errno:%d", queue_err.iSend, queue_err.iRecv, queue_err.err_no);
					}
				}
			}

			switch (ret)
			{
				case 2:
					goto handle_fin_packet;
					break;
				case 1:
					continue;
					break;
				case 0:	/* 继续后面的处理 */
					break;
				default:
					break;
			}
// #if (defined HAVE_CHERRY) && (defined USE_RUNTIME_OVERRUN_OPER)
#if defined USE_RUNTIME_OVERRUN_OPER
			if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_BYPASS
				&& rt_cherry->retrans_bypass_flag == 1)
			{
				if(rt_npc->parseresult.tcp_header.fin==1 || rt_npc->parseresult.tcp_header.rst==1)
				{
					goto handle_fin_packet;
				}
				else
				{
					if(__NPP_ALL_CONFIG->start_for_transparent==1)        // 网桥模式
					{
						struct timeval tv;
						gettimeofday(&tv, NULL);
						
						if(tv.tv_sec * 1000000 + tv.tv_usec - rt_cherry->retrans_bypass_time < rt_cherry->retrans_bypass_dura * 1000000)
						{
							continue;
						}
						else
						{
							rt_cherry->retrans_bypass_flag = 0;
							rt_cherry->retrans_bypass_time = 0;
							//Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"bypass packet in this period is over.");
						}
					}
				}
			}		
			else if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_BYPASS
				&& __sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_discard, 0) == DBF_RUNTIME_OPER_DISCARD_PKT)  // 放行模式下丢包
			{
				if(rt_npc->parseresult.tcp_header.fin==1 || rt_npc->parseresult.tcp_header.rst==1)
				{
					goto handle_fin_packet;
				}
				else
				{
					continue;
				}
			}
			else if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON
				&& __sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_discard, 0) == DBF_RUNTIME_OPER_DISCARD_PKT)  // 坚守模式下丢包
			{
				if(__SGA_RTBUF.data.perform_control->npp_nextsec_pkt > 0)
				{
					__SGA_RTBUF.data.perform_control->npp_total_pkt++;
					__SGA_RTBUF.data.perform_control->npp_nextsec_pkt--;
				}
				else
				{
					if(rt_npc->parseresult.tcp_header.fin==1 || rt_npc->parseresult.tcp_header.rst==1)
					{
						goto handle_fin_packet;
					}
					else
					{
						if(__NPP_ALL_CONFIG->start_for_transparent==1)    // 网桥模式
						{
							__ORA_SESSION->help_tamper_flag = DBFW_TAMPER_TYPE_DISCARD;
						}
						continue;
					}
				}
			}
			else
			{
				__SGA_RTBUF.data.perform_control->npp_total_pkt++;
			}
#endif

#ifdef HAVE_CHERRY
            /* 在DPDK透明网桥模式下，不会出现大连的丢包问题，因此这里可以直接设置is_last_pack标记 */
            if(__NPP_ALL_CONFIG->start_for_transparent==1)
            {
                /* 记录当前rt_npc->parseresult的顺序id号，先加1，再赋值 */
                rt_cherry->last_parseresult_id_fortamper = rt_cherry->last_parseresult_id_fortamper + 1;
                rt_npc->parseresult.parseresult_id = rt_cherry->last_parseresult_id_fortamper;
                rt_npc->parseresult.have_packheader = 0;    /* 先设置为没有包头数据 */
            }
#endif
			/************************************************************************/
			/*  
				step 10 通讯包冗余过滤
			    修复大连农商行多交换机进行引起的10.8.144.225请求无法审计问题(sec+ack匹配方法) 
				具体算法：
				首先找到第一个SYN+ACK可以匹配的请求包和应答包，并记录相应的请求包的DB MAC地址和应答包的DB MAC地址
				然后使用下来的全部DB MAC地址进行后续通讯包的过滤
				在成功匹配请求和应答包之前，不对通讯包进行解析，而是加入到一个buffer缓冲区中,但如果是SYN+ACK包则放行
				注意：当成功匹配后，需要重置客户端和服务器的MAC地址
				已支持的场景：正常的单链路，RAC下的双链路，RAC下的双链路+上下行网卡			*/
			/************************************************************************/
			ret = NPP_RedundantPackageFilter_ForHandleNpc(rt_com,rt_npc,rt_cherry);
			switch (ret)
			{
				case 1:
					continue;
					break;
				case 0:	/* 继续后面的处理 */
					break;
				default:
					break;
			}
            /************************************************************************/
			/* [结束]大连农商行协议处理                                                        */
            /************************************************************************/

			/************************************************************************/
			/* 
				处理佛山现场无连接会话小包问题 
				记录rt_com->total_pack_size是否超出了1510字节，这个数值是一个经验性的值
			*/
			/************************************************************************/
            if(rt_com->total_pack_size<1510)
                rt_com->total_pack_size = rt_com->total_pack_size + rt_npc->parseresult.data_size;
            
			/************************************************************************/
			/* 
				2016-04-13
				step 11 将IP和端口是否是本会话匹配的检查转移到这里，不要在后面进行多次检查了
			*/
			/************************************************************************/
			ret = NPP_MatchPackageAddress_ForHandleNpc(rt_com,rt_npc,rt_cherry);
			switch (ret)
			{
				case 1:
					continue;
					break;
				case 0:	/* 继续后面的处理 */
					direction = rt_npc->parseresult.direction;
					break;
				default:
					break;
			}
			direction = rt_npc->parseresult.direction;
			/* [结束]IP和端口是否匹配检查 */

			/* 性能测试点2.2 持续1.3 CPU */
			//continue;
            OraNet_DumpSql("current package[sec=%u , ack=%u, size=%u, direction = %s]\n",
                    rt_npc->parseresult.tcp_header.sequence,
                    rt_npc->parseresult.tcp_header.acknowledge,
                    rt_npc->parseresult.data_size,
                    ((rt_npc->parseresult.direction == USER2ORA) ? "Request" : "Response"));
			/************************************************************************/
			/* 开始处理rt_npc->parseresult中解析到的数据库包数据了                          */
			/************************************************************************/			
            if(rt_npc->parseresult.data_size>0 || (rt_npc->full_dir_mac_idx<PCAP_ETH_ADDR_ARRAY && rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].dyna_tcpdata_buf.length>0))
            {
                //测试：不做处理，测试NPC丢包率
                //continue;

				/************************************************************************/
				/*  step 13
					2014-04-06 增加无连接会话审计能力 
					应对场景：
					1：连接池环境下没有捕获到创建连接的通讯包
					2:由于丢包引起的创建连接的包没有获得
				*/
				/************************************************************************/
				if(rt_npc->npc_is_connect_syn==0)
                {
					/* 之前没有创建过连接,属于无连接的会话 */
					ret = NPP_UnConnectSession_ForHandleNpc(rt_com,rt_npc,rt_cherry,p_processParam);
					switch (ret)
					{
						case 1:
							continue;
							break;
						case 0:	/* 继续后面的处理 */
							break;
						default:
							break;
					}
                }
				/* [结束]无连接会话审计处理 */

				/************************************************************************/
				/* 开始处理协议数据包                                                               */
				/************************************************************************/
				if(rt_npc->npc_is_connect_syn == 1)
				{
					/* 有Net8数据 */
					/************************************************************************/
					/* step 14 包乱序，丢包，重传，KeepAlive检查和处理                               */
					/************************************************************************/
					if(rt_npc->full_dir_mac_idx<PCAP_ETH_ADDR_ARRAY && rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].dyna_tcpdata_buf.length>0)
					{
					}
					else
					{
						ret = NPP_CheckAndProcess_LoseOrReorderPack_ForHandleNpc(rt_com,rt_npc,rt_cherry);
						switch (ret)
						{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								direction = rt_npc->parseresult.direction;
								break;
							default:
								break;
						}
						direction = rt_npc->parseresult.direction;
					}
					/************************************************************************/
					/* 下面正式进入通讯包协议解析                                                       */
					/************************************************************************/
handle_npc_parsedata:
					while (rt_npc->tcpsecquence_error_flag==0)
					{
						/* 
							step 15 补丁
							需要在这里处理大连通讯包问题:
							将dyna_tcpdata_buf缓冲区的数据加入到 buffer_tcppackage
							并将当前的rt_npc->parseresult进行备份到rt_npc->buf_parseresult,然后制造一个空的rt_npc->parseresult
						*/
						if((rt_npc->full_dir_mac_idx<PCAP_ETH_ADDR_ARRAY)
						    && (rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].dyna_tcpdata_buf.length>0))
						{
							
							/* 备份rt_npc->parseresult到rt_npc->buf_parseresult */
							if(rt_npc->buf_parseresult!=NULL)
							{
								ZFree(rt_npc->buf_parseresult);
							}
							rt_npc->buf_parseresult = (Dbfw_EthernetParseResult*)ZMalloc(sizeof(Dbfw_EthernetParseResult));
							z_memcpy(rt_npc->buf_parseresult,&rt_npc->parseresult,sizeof(Dbfw_EthernetParseResult), __FILE__, __LINE__, Smem_LogError_Format);
							if(rt_npc->parseresult.data_size>0)
							{
								rt_npc->buf_parseresult->parse_data = (u_char *)ZMalloc(rt_npc->parseresult.data_size);
								z_memcpy(rt_npc->buf_parseresult->parse_data,rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size, __FILE__, __LINE__, Smem_LogError_Format);
							}
							rt_npc->buf_parseresult->data_size = rt_npc->parseresult.data_size;
							/* 清理rt_npc->parseresult */
							if(rt_npc->parseresult.data_size>0)
							{
								ZFree(rt_npc->parseresult.parse_data);
								rt_npc->parseresult.data_size = 0;
							}
							rt_npc->parseresult.direction = rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].last_direct;
							direction = rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].last_direct;

							rt_npc->parseresult.tcp_header.sequence = rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].secquence;
							rt_npc->parseresult.tcp_header.acknowledge = rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].ack ;
							rt_npc->parseresult.data_size = rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].data_size;
#ifdef NEW_TCP_REORDER
                            /* 设置乱序缓冲区的统计信息 */
                            ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,rt_npc->parseresult.direction,rt_com->alive_time);
                            __ORA_SESSION->tamper_data_addr = NULL;
#endif
                            rt_npc->parseresult.data_size = rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].dyna_tcpdata_buf.length;
							rt_npc->parseresult.parse_data = (u_char*)ZMalloc(rt_npc->parseresult.data_size);
                            z_memcpy(rt_npc->parseresult.parse_data
                                ,(u_char *)rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].dyna_tcpdata_buf.str
                                ,rt_npc->parseresult.data_size
                                , __FILE__, __LINE__, Smem_LogError_Format);
                            OraNet_DumpSql("step[15.1] add tcppack_data(%d) to parseresult->parse_data\n"
                                ,rt_npc->parseresult.data_size );
							
							
						}
						else
						{
							/* 不是大连农商行问题引起的通讯包缓冲区的解析,而是正常的通讯包处理 */
							/* 如果发现已经进行了ReleaseAllStmt_ForNpcLossPack,并且都是服务器向客户端的通讯包，则不进行处理 */
							if(rt_npc->isReleaseAllStmtForNpcLossPack_flag==1)
							{
                    			if(direction!=USER2ORA)
                    			{
                    				/* 不进行处理 */
                    				//printf("skip process\n");
                    			}
                    			else
                    			{
                    				/* 出现了第一个USER->ORA的通讯包 */
                    				rt_npc->isReleaseAllStmtForNpcLossPack_flag = 0;
                    			}
							}
						}
						/************************************************************************/
						/* 开始处理各种协议的数据包                                                        */
						/************************************************************************/
						//对ssl加密的数据包进行拼包和解密
						#if defined ENABLE_MYSQL && defined ENABLE_SSL_AUDIT
						if(__ORA_SESSION->ssl_sess_de.ssl_session_status == SSL_SESSION_STATUS_HACK_SUCCESS)
						{
							u_int	ssl_buffer_size = 0;
							u_int	ssl_pack_size = 0;
							int		ssl_plaint_size = 0;
							int		ssl_decrypt_ret = 0;
							u_char *ssl_pack_data = NULL;
							
							ssl_buffer_size = SSL_AddTcpPackageToSslBuffer(rt_npc->parseresult.parse_data,rt_npc->parseresult.data_size,rt_npc->parseresult.direction);
							do{
								ssl_pack_data = SSL_Package_PreProcess_FromSslBuf(rt_npc->parseresult.direction, &ssl_pack_size);
								if(ssl_pack_data != NULL)
								{
									//拼好一个ssl包后调用解密，由于ssl内部可能发送其它数据，多个ssl包还原成一个数据库包
									ssl_decrypt_ret = ssl_package_handle(ssl_pack_data, ssl_pack_size, rt_npc->parseresult.direction, &ssl_plaint_size, NULL);
									if(ssl_decrypt_ret < 0)
									{
										//do clear job 解密出错，解密下一个包或更改状态清理缓冲区数据
										ssl_plaint_size = 0;
										OraNet_DumpSql("[decode_ssl error] decrypt error for appdata\n");
                                        //ZFree(ssl_pack_data);
										//break;
									}
									else if(ssl_decrypt_ret == 0 && ssl_plaint_size == 0)
									{
									    //收到的ssl包不完整、不足以解出数据包
										ssl_plaint_size = 0;
									}
									else
									{
										//解密成功，添加到解密缓冲区
										SSL_AddPlaintPackageToBuffer(ssl_pack_data+5, ssl_plaint_size);	//5 is tls header
									}
									ZFree(ssl_pack_data);
								}
							}while(ssl_pack_size>0);

							//交换ssl_plaint_buffer中的数据到rt_npc->parseresult.parse_data
							SSL_ExchangePlaintBufferToRtnpcParseresult(&rt_npc->parseresult.parse_data, &rt_npc->parseresult.data_size);

							//此处不能调用release释放，因为在上面的exchange函数中已经把buffer的指针赋给了rt_npc->parseresult.parse_data
							//且在exchange函数中会将ssl_plaint_buffer中的size置0
							//SSL_ReleasePlaintPackageBuffer

							/*置此，ssl包已经解密完成，后面走原有的包解析逻辑即可。一般来说两个tls包才能解密成一个数据包*/
						}
						#endif
#ifdef HAVE_SQL_MODIFY_ENGINE 
						__ORA_SESSION->rewrite_net_packet = &(rt_com->rewrite_packet);
#endif
						if(rt_npc->isReleaseAllStmtForNpcLossPack_flag==1)
						{
                    		/* do nothing */
                    		OraNet_DumpSql("step[16.2] do nothing for rt_npc->isReleaseAllStmtForNpcLossPack_flag\n");
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_ORACLE)
						{
							/************************************************************************/
							/*  step 17 Oracle通讯协议处理                                                   */
							/************************************************************************/
							/* 性能测试点3,持续占用1.3~1.7CPU */
							//break;
							ret = NPP_HandleOraclePackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
								case 1:
									continue;
									break;
								case 0:	/* 继续后面的处理 */
									break;
								default:
									break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MSSQL || __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SYBASE
							|| __SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_SYBASEIQ)
						{
							/************************************************************************/
							/*  step 18 MSSQL/Sybase通讯协议处理                                            */
							/************************************************************************/
							ret = NPP_HandleMSSQLPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
								case 1:
									continue;
									break;
								case 0:	/* 继续后面的处理 */
									break;
								default:
									break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL || __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG)
						{
							/************************************************************************/
							/*  step 19 MySQL/GBase8g通讯协议处理                                            */
							/************************************************************************/
							ret = NPP_HandleMySQLPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								break;
							default:
								break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_DB2)
						{
							/************************************************************************/
							/*  step 20 DB2通讯协议处理												*/
							/************************************************************************/
							ret = NPP_HandleDB2Package_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								break;
							default:
								break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_DM)
						{
							/************************************************************************/
							/*  step 21 达梦通讯协议处理												*/
							/************************************************************************/
							ret = NPP_HandleDMPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								break;
							default:
								break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_POSTGREE)
						{
							/************************************************************************/
							/*  step 22 Postgre通讯协议处理											*/
							/************************************************************************/
							ret = NPP_HandlePostgrePackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								break;
							default:
								break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_KINGBASE)
						{
							/************************************************************************/
							/*  step 23 Kingbase通讯协议处理											*/
							/************************************************************************/
							ret = NPP_HandleKingbasePackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
								case 1:
									continue;
									break;
								case 0:	/* 继续后面的处理 */
									break;
								default:
									break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_OSCAR)
						{
							/************************************************************************/
							/*  step 24 神通OSCAR通讯协议处理											*/
							/************************************************************************/
							ret = NPP_HandleOscarPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
								case 1:
									continue;
									break;
								case 0:	/* 继续后面的处理 */
									break;
								default:
									break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_IFX || __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_GBASE8T)
						{
							/************************************************************************/
							/*  step 25 IBM Informix/Gbase8T通讯协议处理								*/
							/************************************************************************/
							ret = NPP_HandleInformixPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
								case 1:
									continue;
									break;
								case 0:	/* 继续后面的处理 */
									break;
								default:
									break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_CACHEDB)
						{
							/************************************************************************/
							/*  step 26 InterSystem Cachedb通讯协议处理								*/
							/************************************************************************/
							ret = NPP_HandleCacheDBPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
								case 1:
									continue;
									break;
								case 0:	/* 继续后面的处理 */
									break;
								default:
									break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_HBASE)
						{
							/************************************************************************/
							/*  step 18 Hbase通讯协议处理                                            */
							/************************************************************************/
							ret = NPP_HandleHbasePackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
								case 1:
									continue;
									break;
								case 0:	/* 继续后面的处理 */
									break;
								default:
									break;
							}
						}
						else if (__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_MONGODB)
						{
							/************************************************************************/
							/*  step 18 MongoDB通讯协议处理                                            */
							/************************************************************************/
							ret = NPP_HandleMongoDBPackage_ForHandleNpc(rt_com, rt_npc, rt_cherry);
							switch (ret)
							{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								break;
							default:
								break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_TERADATA)
						{
							/************************************************************************/
							/*  step 18 TERADATA通讯协议处理                                            */
							/************************************************************************/
							ret = NPP_HandleTeradataPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
								case 1:
									continue;
									break;
								case 0:	/* 继续后面的处理 */
									break;
								default:
									break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_HANA)
						{
							/************************************************************************/
							/*  step 18 HANA通讯协议处理                                            */
							/************************************************************************/
							ret = NPP_HandleHanaPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
								case 1:
									continue;
									break;
								case 0:	/* 继续后面的处理 */
									break;
								default:
									break;
							}
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_GAUSSDBT)
						{
							ret = NPP_HandleGaussdbTPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
								case 1:
									continue;
									break;
								case 0:	/* 继续后面的处理 */
									break;
								default:
									break;
							}
						}
						else if (__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_HIVE)
						{
					    	#ifdef ENABLE_HIVE
						    ret = NPP_HandleHivePackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
                            switch (ret)
							{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								break;
							default:
								break;
							}
							#endif
						}
						else if (__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_SENTRY)
						{
					    	#ifdef ENABLE_SENTRY
						    ret = NPP_HandleSentryPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
                            switch (ret)
							{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								break;
							default:
								break;
							}
							#endif
						}
						else if (__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_REDIS)
						{
					    	#ifdef ENABLE_REDIS
						    ret = NPP_HandleRedisPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
                            switch (ret)
							{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								break;
							default:
								break;
							}
							#endif
						}
						else if (__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_ES)
						{
					    	#ifdef ENABLE_ES
						    ret = NPP_HandleESPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
                            switch (ret)
							{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								break;
							default:
								break;
							}
							#endif
						}
						else if (__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_TELNET)
						{
							ret = NPP_HandleTelnetPackage_ForHandleNpc(rt_com, rt_npc, rt_cherry);
							switch (ret)
							{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								break;
							default:
								break;
							}
						}
						else if (__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_IMPALA)
						{
						#ifdef ENABLE_IMPALA
							/************************************************************************/
							/*  step 20 IMPALA通讯协议处理                                            */
							/************************************************************************/
							ret = NPP_HandleImpalaPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
							switch (ret)
							{
								case 1:
									continue;
									break;
								case 0:	/* 继续后面的处理 */
									break;
								default:
									break;
							}
						#endif
						}
						else if(__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_HRPC)
						{
							#ifdef ENABLE_HRPC
							ret = NPP_HandleHdfsProtoPackage_ForHandleNpc(rt_com, rt_npc, rt_cherry);
							switch (ret)
							{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								break;
							default:
								break;
							}
							#endif
						}
						else if (__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_WEBHTTP)
						{
					    	#ifdef ENABLE_WEBHTTP
						    ret = NPP_HandleWebHttpPackage_ForHandleNpc(rt_com,rt_npc,rt_cherry);
                            switch (ret)
							{
							case 1:
								continue;
								break;
							case 0:	/* 继续后面的处理 */
								break;
							default:
								break;
							}
							#endif
						}
						else
						{
							/* 其他类型的DB通讯协议的处理,都不支持 */
							OraNet_DumpSql("unsupport db type\n");
							//continue;
						}
						/************************************************************************/
						/* [结束]数据协议解析处理完成                                                      */
						/************************************************************************/
						/* TODO 登陆风险校验*/
						ret = NPP_ConnectFilter(__ORA_SESSION,&(rt_com->rewrite_packet));
						
						/* 传入标记:登陆校验、
							传出:
						*/

						/* 处理tlog*/
						ret = NPP_HandleTlog(rt_com->alive_time,__ORA_SESSION);
						
//    						if(rt_com->rewrite_packet.is_switchoff==1 || rt_com->rewrite_packet.packparse_result == NPP_RESULT_SWITCHOFF ||
//    						rt_com->rewrite_packet.packparse_result == NPP_RESULT_BLOCKING_THROW)
//    						{
//    							Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
//    #ifdef DUMP_MEMORY_LEAK
//                        		__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORMEMCHECK;
//    #else
//                       			 __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
//    #endif
//    						}
						/************************************************************************/
						/*  
							大连农商行通讯包的处理逻辑:这里需要将当前的通讯包加入
							step 27
						*/
						/************************************************************************/
						if(rt_npc->full_dir_mac_idx<PCAP_ETH_ADDR_ARRAY 
						    && rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].dyna_tcpdata_buf.length>0 
						    && rt_npc->buf_parseresult!=NULL)
						{
							{
								/* 注意：必须在这里清理dyna_tcpdata_buf */
								Dbfw_DynStr_Free(&rt_npc->tcp_secandack[rt_npc->full_dir_mac_idx].dyna_tcpdata_buf);
							}
							/* 备份rt_npc->parseresult->rt_npc->buf_parseresult */
							if(rt_npc->buf_parseresult==NULL)
							{
								/* 不符合逻辑了 */
								break;
							}
							/* 从rt_npc->buf_parseresult备份将数据还原到rt_npc->parseresult，然后继续解析 */
							rt_npc->parseresult.direction = rt_npc->buf_parseresult->direction;
							if(rt_npc->parseresult.data_size>0)
							{
								ZFree(rt_npc->parseresult.parse_data);
								rt_npc->parseresult.data_size = 0;
							}
							if(rt_npc->buf_parseresult->data_size>0)
							{
								rt_npc->parseresult.parse_data = (u_char *)ZMalloc(rt_npc->buf_parseresult->data_size);
								z_memcpy(rt_npc->parseresult.parse_data,rt_npc->buf_parseresult->parse_data,rt_npc->buf_parseresult->data_size, __FILE__, __LINE__, Smem_LogError_Format);
								rt_npc->parseresult.data_size = rt_npc->buf_parseresult->data_size;
							}
							rt_npc->parseresult.tcp_header.sequence = rt_npc->buf_parseresult->tcp_header.sequence;
							rt_npc->parseresult.tcp_header.acknowledge =  rt_npc->buf_parseresult->tcp_header.acknowledge;
							/* 清理rt_npc->parseresult */
							if(rt_npc->buf_parseresult->data_size>0)
							{
								ZFree(rt_npc->buf_parseresult->parse_data);
								rt_npc->buf_parseresult->data_size = 0;
							}
							ZFree(rt_npc->buf_parseresult);
							direction = rt_npc->parseresult.direction;
							OraNet_DumpSql("step[27.1] continue parse for dalian buffer size=%d\n",rt_npc->parseresult.data_size);
#ifdef NEW_TCP_REORDER
							/* 设置乱序缓冲区的统计信息 */
							ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,rt_npc->parseresult.direction,rt_com->alive_time);
							__ORA_SESSION->tamper_data_addr = NULL;
#endif
							continue;   /* 继续下一次解析 */
						}
						/************************************************************************/
						/*  [结束]大连农商行通讯包的处理逻辑                                               */
						/************************************************************************/

						/************************************************************************/
						/* 
							检查乱序缓冲区是否仍有未处理的包，并按照顺序取出进行处理
							step 28
						*/
						/************************************************************************/
						ret = NPP_GetNextReorderPackFromBuffer_ForHandleNpc(rt_com,rt_npc,rt_cherry);
						if(ret==1)
						{
							direction = rt_npc->parseresult.direction;
							__ORA_SESSION->tamper_data_addr = NULL;
							continue;	/* 继续while循环 */
						}
						else
						{
							break;		/* 跳出while循环 */
						}
					}   /* end while(rt_npc->tcpsecquence_error_flag==0) */
				}   /* end if(rt_npc->npc_is_connect_syn == 1)  */
				else
				{
                   /*没有建连接，例如：客户端没有通过防火墙已经连接到数据库了，在把防火墙设置成旁路模式，就会存在此问题*/
					continue;
                }                
            }
            /* 
                在网神合作伙伴的黑龙江测试项目中发现出现来自10.117.202.67的只有SYN的通讯包(单向)，并且量很大，应该是一个监控设备发出的，会造成创建大量的NPP 
                因此，对NPC和NPP都进行了调整，原来是在只有SYN，无ACK时创建NPP，改为同时有SYN和ACK时创建NPP，也就是服务器进行了应答
            */
#ifdef NPC_USE_SYNANDACK_START
            /* SYN+ACK创建NPP模式 */
            else if(rt_npc->parseresult.tcp_header.syn==1 && rt_npc->parseresult.tcp_header.ack==1)
#else
            /* SYN创建NPP模式 */
            else if(rt_npc->parseresult.tcp_header.syn==1 && rt_npc->parseresult.tcp_header.ack==0)
#endif            
            {
				/* step 29 */
				/************************************************************************/
				/*  处理SYN+ACK三次握手包                                                         */
				/************************************************************************/
                /* 对于SYN包，首先要检查是否是“挂起”的会话，如果是则需要立即唤醒，否则无法正确匹配上clientip和port */
				/*添加是否建连接的判断*/
				rt_npc->npc_is_connect_syn = 1;  //说明有连接要建立
				if(__ORA_SESSION)
				{
					__ORA_SESSION->have_syn = 1;
				}
                /* 客户端创建连接 */
				OraNet_DumpSql("step[29.2]\n");
                OraNet_DumpSql("****************new tcp connect request****************\n");
                OraNet_DumpSql("****client_ip=%u   client_port=%u****\n",rt_npc->parseresult.ipv4_header.ip_srcaddr,rt_npc->parseresult.tcp_header.source_port);
                OraNet_DumpSql("*******************************************************\n");
                /* 判断是否是已经处理过连接的进程 */
                if(rt_npc->new_connect==1)
                {
                    /* 之前没有处理过，不需要理会，将rt_npc->new_connect置为0即可 */
                    rt_npc->new_connect = 0;
                }
                else
                {
                    /* 
                        是已经处理过连接的进程，需要进行清理资源的处理
                        理论上，应该永远不会进入到这个逻辑，一旦进入，肯定就是出现了异常了
                        但这里不会影响到NPP进程池的逻辑,原因是OraNet8_CloseSessionForNPC不会调用Npp_Sga_FreeSession
                    */
					OraNet8_CloseSession(rt_com->tcp_info);
					__ORA_SESSION = NULL;
					
				/* 20151216 guoxw */    

					Init_Session_Global(rt_com->tcp_info,p_processParam.init_session,SOURCECODE,__LINE__);
                }
            }/* SYN+ACK处理 */
            else if(rt_npc->parseresult.tcp_header.fin==1 || rt_npc->parseresult.tcp_header.rst==1)
            {
				/************************************************************************/
				/*  处理FIN握手包															*/
				/************************************************************************/

handle_fin_packet:

                /* 关闭连接请求 */
                OraNet_DumpSql("step[29.3] receive fin\n");
#ifdef HAVE_CHERRY
                /* 功能 3.2.3 NPP将会话结束的FIN，FIN+ACK，ACK包返回 */
                /* 接收到第一个FIN包后，需要设置fin的时间戳。并且不退出不挂起，等待1秒，并将其他的包也发出 */
                if(__NPP_ALL_CONFIG->start_for_transparent==1)
                {
                    /* 启动方式为DPDK全透明网桥时 */
                    if(__ORA_SESSION->timestamp_fin==0)
                    {
                        __ORA_SESSION->timestamp_fin = Npp_GetEpochTime_MicroSecond();
                        continue;
                    }
                    else
                    {
                        if((Npp_GetEpochTime_MicroSecond()-__ORA_SESSION->timestamp_fin)<1000000)
                        {
                            continue;
                        }
                    }
                    /* 其他逻辑进入后面的挂起和关闭处理 */
                }                
#endif
				/*退出之前需要处理REORDER缓冲buff的数据*/
				//Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"set_flag DBFW_HANDLEEXIT_FORREORDER ");
				__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_FORREORDER;
				continue;
            } /* FIN处理 */
#ifdef NEW_TCP_REORDER

				/* 2016-08-20,alter by liyanjun,修正回归包中bug_0630/bug8112-tianyiaiyinyue_3306-modify.pcap中的问题，将第一个syn+ack包作为应答方向的第一个有序包记录sequence信息*/
            if(rt_npc->parseresult.tcp_header.syn==1 
            	&& rt_npc->parseresult.tcp_header.ack==1 
            	&& rt_npc->parseresult.data_size == 0 
            	&& rt_npc->npc_is_connect_syn == 1 
            	&& rt_npc->parseresult.direction == ORA2USER
            	&& rt_npc->new_tcpreorder_buffer.ep_ora2user.pknum == 0 
            	&& rt_npc->isReleaseAllStmtForNpcLossPack_flag != 1)
            {

				/* 设置乱序缓冲区的统计信息 */
				rt_npc->parseresult.tcp_header.sequence = rt_npc->parseresult.tcp_header.sequence +1 ;
				ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,rt_npc->parseresult.direction,rt_com->alive_time);
            }
            
			/* 2016-08-20,alter by liyanjun,修正回归包中bug_0630/bug8112-tianyiaiyinyue_3306-modify.pcap中的问题，将第一个ack包作为请求方向的第一个有序包记录sequence信息*/
            if(rt_npc->parseresult.tcp_header.syn==0 
            	&& rt_npc->parseresult.tcp_header.ack==1 
            	&& rt_npc->parseresult.data_size == 0 
            	&& rt_npc->npc_is_connect_syn == 1
            	&& rt_npc->parseresult.direction ==  USER2ORA 
            	&& rt_npc->new_tcpreorder_buffer.ep_user2ora.pknum == 0
            	&& rt_npc->isReleaseAllStmtForNpcLossPack_flag != 1
            	&& rt_npc->record_ack_flag == 0)
            {
				/* 设置乱序缓冲区的统计信息 */
				//ret = Dbfw_TcpReorder_ResetOrderBufferUseOrderedPackage(&rt_npc->new_tcpreorder_buffer,&rt_npc->parseresult,rt_npc->parseresult.direction,rt_com->alive_time);
				NPP_CheckAndProcess_LoseOrReorderPack_ForHandleNpc(rt_com,rt_npc,rt_cherry);
				rt_npc->record_ack_flag = 1;

            }
#endif

        }
    }
handle_npc_quit:

#ifdef HAVE_CHERRY
    /* 如果有需要DPDK的NFW发送的通讯包则立即请求发送 */
    Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_NORMAL);
#endif

    /* 进行NPP进程池睡眠的处理 */
	/************************************************************************/
	/* 退出函数处理(handle_npc_quit_real)                                    */
	/************************************************************************/
handle_npc_quit_real:
    /* 将没有发送的数据包发送 */

	if(Tis_Content_Type(rt_npc->tis) == 1)				          // tis content block模式
	{
		if(__NPP_ALL_CONFIG->start_for_transparent==1)
		{
		    /* 如果有需要DPDK的NFW发送的通讯包则立即请求发送 */
		    Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_NORMAL);
		    /* 发送crash */
		    Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_EXIT);
		}
		else if(__NPP_ALL_CONFIG->start_for_transparent==0)  /* nfw旁路模式 */
		{
			__NPP_ALL_CONFIG->nfw_memqueue_node.value = 0;
			__NPP_ALL_CONFIG->nfw_memqueue_node.flag = DBFW_MIRROR_TYPE_EXIT;
	    	__NPP_ALL_CONFIG->nfw_memqueue_node.id = __NPP_ALL_CONFIG->sessionid_fornpc;
			dspr_memqueue_put(__NPP_ALL_CONFIG->memqueue,(Dspr_MemQueue_Node*)&__NPP_ALL_CONFIG->nfw_memqueue_node, &queue_err);
			if((queue_err.err_no&DSPR_MQ_FULL_1) || (queue_err.err_no&DSPR_MQ_FULL_2))
			{
				Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" memqueue put generate ERR ,_iSend:%llud, irecv:%llud , errno:%d", queue_err.iSend, queue_err.iRecv, queue_err.err_no);
			}

		}
	}

    /* 清理tcp包的hash表数据 */
#ifdef NEW_TCP_REORDER
    Dbfw_TcpReorder_ResetAll(&rt_npc->new_tcpreorder_buffer); 
    if(rt_npc->new_tcpreorder_buffer.out_of_order_buff)
    {
    	ZFree(rt_npc->new_tcpreorder_buffer.out_of_order_buff);
    }
#else
    
	/* 下面删除了不再使用的HAVE_TCP_RECORDER程序 */
#endif  /* NEW_TCP_REORDER */
    /* 清理大连农商行问题处理的TCP缓冲区，并重置rt_npc->full_dir_mac_idx */
    for(i=0;i<PCAP_ETH_ADDR_ARRAY;i++)
    {
        if(rt_npc->tcp_secandack[i].dyna_tcpdata_buf.length>0)
        {
            Dbfw_DynStr_Free(&rt_npc->tcp_secandack[i].dyna_tcpdata_buf);
        }                
    }
    memset(&rt_npc->tcp_secandack,0x00,sizeof(rt_npc->tcp_secandack));
    rt_npc->full_dir_mac_idx = 0xFF;        /* 重置TCP包检查的初始值标记 */
    /* 保存会话找回信息处理 */
#ifdef CONNECTREBUILD
    if(rt_npc->save_session_for_drawback==1)
    {
        /* 保存会话信息用于会话找回 */
        Npp_SaveSessionInfo_ForDrawBack();
    }
    else
    {
        /* 
            不需要保存会话信息，这时需要清理之前保存的会话信息 
            包括：会话正常退出
        */
        sprintf(rt_npc->ip_port,"%u%d%u%d",rt_npc->parseresult.ipv4_header.ip_destaddr,rt_npc->parseresult.tcp_header.dest_port,rt_npc->parseresult.ipv4_header.ip_srcaddr,rt_npc->parseresult.tcp_header.source_port);
        rt_npc->ip_port_key = GetTextHashRebuildSess((u_char*)rt_npc->ip_port,strlen(rt_npc->ip_port));
        Rslist_Delete((Rslist_t*)__SGA_SESSBUF->block_36,rt_npc->ip_port_key);
    }
#endif
    /* 关闭所有的log文件 */
	/*陈寿仓*/
#ifdef HAVE_LUA
	if(L)
		lua_close(L);
#endif
	if(rt_npc->cap_header)
	{
		ZFree(rt_npc->cap_header);
	}
	if(dump_tcpdata)
	{
		fclose(dump_tcpdata);
	}

	OraNet8_CloseSession(rt_com->tcp_info);
    if(rt_com->tcp_info)
        ZFree(rt_com->tcp_info);
    ZFree(rt_npc->loop_data);
    if(rt_npc->ethernetframe.max_ip_fragment_size>0)
    {
        ZFree(rt_npc->ethernetframe.ip_fragment_data);
        rt_npc->ethernetframe.max_ip_fragment_size = 0;
    }
    if(rt_npc->ethernetframe.max_frame_size>0)
    {
        ZFree(rt_npc->ethernetframe.frame_data);
        rt_npc->ethernetframe.max_frame_size = 0;
    }
    if(rt_npc->parseresult.data_size>0)
    {
        ZFree(rt_npc->parseresult.parse_data);
        rt_npc->parseresult.data_size = 0;
    }
    Npp_CloseAllLog();
    

	ZFree(rt_com);
	ZFree(rt_npc);
	ZFree(rt_cherry);
#if defined ENABLE_MYSQL && defined ENABLE_SSL_AUDIT
	ssl_decrypt_info_free();
#endif

#endif
    return;
}



void usage(char * myname)
{    
    fprintf(stderr, "\n"            
        "Usage: %s process_type shmid dbclient_ip dbclient_port dbclient_mac dbserver_ip dbserver_port dbserver_mac sessionid initsesion [shmid_proxy client_socket server_socket]\n"
        "\n"            
        "process_type    NPP process type; 2-for NPC's SharedMemory 5-fox Nfw DPDA 6- for threeway-proxy\n"
        "shmid           shmid for dbfw's SGA\n"
        "dbclient_ip     database client ip address; sample:192.168.1.1\n"            
        "dbclient_port   database client port; sample:1234\n"            
        "dbclient_mac    database client mac address; sample:ABABAB010203\n"            
        "dbserver_ip     database server ip address; sample:192.168.1.1\n"            
        "dbserver_port   database server port; sample:1521\n"            
        "dbserver_mac    database server mac address; sample:ABABAB010203\n"      
        "sessionid       this param is sessionid in sga sessionbuf\n "
        "initsesion      this param initsession in cherry-NPC/cherry- Nfw DPDA, else no use \n "
        "[shmid_proxy    proxy shmid;this param is only for threeway-proxy]\n "
        "[client_socket  this param is only for threeway-proxy]\n "
        "[server_socket  this param is only for threeway-proxy]\n "
        "sample : %s 1 123456 192.168.1.1 7788 AB-AB-AB-01-02-03 192.168.1.24 1521 AB-AB-AB-01-02-03 4"
        "         \n\n\n", myname, myname);
}







void subst(unsigned char *data, int len) {
    int         slen1,
                slen2;
    unsigned char          *limit,
                *p;

    slen1 = strlen((char*)subst1);
    slen2 = strlen((char*)subst2);
    limit = data + len - ((slen1 > slen2) ? slen1 : slen2);

    for(p = data; p < limit; p++) {
        if(!memcmp(p, subst1, slen1)) z_memcpy(p, subst2, slen2, __FILE__, __LINE__, Smem_LogError_Format);
    }
}



int mysend(SSL *ssl_sd, int sd, unsigned char *data, int datasz) {
    int sent_bytes = 0,len = datasz, bytes = 0;
    do {
        if(ssl_sd) 
            bytes = SSL_write(ssl_sd, data+sent_bytes, len);
        else
            bytes = send(sd, (char *)data+sent_bytes, len, 0);
        if(bytes < 0)
            return bytes;
        len -= bytes;
        sent_bytes += bytes;
    } while(len > 0);
    return sent_bytes;
}



int myrecv(SSL *ssl_sd, int sd, unsigned char *data, int datasz) {
    if(ssl_sd) return(SSL_read(ssl_sd, data, datasz));
    return(recv(sd, (char *)data, datasz, 0));
}

int myrecv_safe(SSL *ssl_sd, int sd, unsigned char *data, int datasz)
{
	int bytes_read = 0;
	int bytes_ready_read = 0;
	int total_readed = 0;

	for(;;)
	{
		bytes_ready_read = datasz - total_readed;
		if(ssl_sd){
			do{
				bytes_read = SSL_read(ssl_sd, data + total_readed,bytes_ready_read);
			}while(bytes_read < 0 && errno == EINTR);			
		}
		else{
			do{
				bytes_read = recv(sd, data + total_readed,bytes_ready_read,0);
			}while(bytes_read < 0 && errno == EINTR);
		}
		if(bytes_read > 0)
			total_readed += bytes_read;
		if(bytes_read <= 0)
			return -1;
		if(total_readed >= datasz)
		{
			return total_readed;
		}
	}
	return 0;
}

int pem_passwd_cb(char *buf, int num, int rwflag, void *userdata) {
    return(sprintf(buf, "%s", ssl_cert_pass));
}

//int nppproxy_free_tis(Tis_Manager *tis,unsigned int slot_id)
//{
//	int ret, send_ret, free_ret;
//	char errbuf[256];
//	Tis_Index   cap_header;
//
//	do {
//		ret = Tis_Content_Read(tis,slot_id,&cap_header,errbuf);
//		if(ret <= 0)
//		{
//		    free_ret = Tis_Content_Free(tis,&cap_header);		    
//		    break;
//		}
//	    send_ret = Tis_Content_Send(tis,slot_id,&cap_header,errbuf);
//	    free_ret = Tis_Content_Free(tis,&cap_header);
//	} while(ret > 0);
//	return 1;
//}
//




int nppproxy_register(unsigned int slot_id,unsigned char *val)
{
	if(Dbfw_AddAndFetch(&val[slot_id],0) == 0)
		return Dbfw_AddAndFetch(&val[slot_id],1);
	return 0;
}

int nppproxy_unregister(unsigned int slot_id,unsigned char *val)
{
	if(Dbfw_AddAndFetch(&val[slot_id],0) == 1)
		return Dbfw_SubAndFetch(&val[slot_id],1);
	return 0;
}

int nppproxy_unregister_with_freetis(Tis_Manager *tis,unsigned int slot_id,unsigned char *val)
{
	int ret, send_ret, free_ret;
	char errbuf[256];
	Tis_Index   cap_header;

	do {
		ret = Tis_Content_Read(tis,slot_id,&cap_header,errbuf);
		if(ret <= 0)
			break;
	    send_ret = Tis_Content_Send(tis,slot_id,&cap_header,errbuf);
	    free_ret = Tis_Content_Free(tis,&cap_header);
	} while(ret > 0);
	nppproxy_unregister(slot_id, val);
	return 1;
}

#if defined ENABLE_MYSQL and defined ENABLE_SSL
static unsigned char dh2048_p[]=
{
  0x8A, 0x5D, 0xFA, 0xC0, 0x66, 0x76, 0x4E, 0x61, 0xFA, 0xCA, 0xC0, 0x37,
  0x57, 0x5C, 0x6D, 0x3F, 0x83, 0x0A, 0xA1, 0xF5, 0xF1, 0xE6, 0x7F, 0x3C,
  0xC6, 0xAF, 0xDA, 0x8B, 0x26, 0xE6, 0x1A, 0x74, 0x5E, 0x64, 0xCB, 0xE2,
  0x08, 0xF1, 0x09, 0xE3, 0xAF, 0xBB, 0x54, 0x29, 0x2D, 0x97, 0xF4, 0x59,
  0xE6, 0x26, 0x83, 0x1F, 0x55, 0xCD, 0x1B, 0x57, 0x55, 0x42, 0x6C, 0xE7,
  0xB7, 0xDA, 0x6E, 0xD8, 0x6D, 0xEE, 0xB1, 0x4F, 0xA4, 0xD7, 0xF5, 0x41,
  0xE1, 0xB4, 0x0B, 0xE1, 0x98, 0x16, 0xE2, 0xED, 0x16, 0xCF, 0x18, 0x7D,
  0x3F, 0x25, 0xC3, 0x82, 0x59, 0xBD, 0xF4, 0x8F, 0x57, 0xCA, 0x3E, 0x19,
  0xE4, 0xF5, 0x44, 0xE0, 0xCC, 0x80, 0xB3, 0x10, 0x91, 0x18, 0x0D, 0x64,
  0x59, 0x0A, 0x43, 0xF7, 0xFC, 0xCA, 0x01, 0xE8, 0x14, 0x04, 0xF2, 0xCD,
  0xA9, 0x2A, 0x3C, 0xF3, 0xA5, 0x2A, 0x83, 0xD8, 0x66, 0x9F, 0xC9, 0x2C,
  0xC9, 0x4F, 0x44, 0x05, 0x5E, 0x5E, 0x00, 0x47, 0x22, 0x0A, 0xE6, 0xB0,
  0x87, 0xA5, 0x74, 0x3B, 0xE4, 0xA3, 0xFC, 0x2D, 0xDC, 0x49, 0xF2, 0xE1,
  0x80, 0x0D, 0x06, 0x71, 0x7A, 0x77, 0x3A, 0xA9, 0x66, 0x70, 0x3B, 0xBA,
  0x8D, 0x2E, 0x60, 0x5A, 0x39, 0xF7, 0x2D, 0xD3, 0xF5, 0x53, 0x47, 0x6E,
  0x57, 0x13, 0x01, 0x87, 0xF9, 0xDE, 0x4D, 0x20, 0x92, 0xBE, 0xD7, 0x1E,
  0xE0, 0x20, 0x0C, 0x60, 0xC8, 0xCA, 0x35, 0x58, 0x7D, 0x3F, 0x59, 0xEE,
  0xFB, 0x67, 0x7D, 0x64, 0x7D, 0x8E, 0x77, 0x6C, 0x61, 0x44, 0x8A, 0x8C,
  0x4D, 0xF0, 0x12, 0xD4, 0xA4, 0xEA, 0x17, 0x75, 0x66, 0x49, 0x6C, 0xCF,
  0x14, 0x28, 0xC6, 0x9A, 0x3C, 0x71, 0xFD, 0xB8, 0x3A, 0x6C, 0xE3, 0xA3,
  0xA6, 0x06, 0x5A, 0xA6, 0xF0, 0x7A, 0x00, 0x15, 0xA5, 0x5A, 0x64, 0x66,
  0x00, 0x05, 0x85, 0xB7,
};
static unsigned char dh2048_g[]={
  0x05,
};
static DH *get_dh2048(void)
{
  DH *dh;
  if ((dh=DH_new()))
  {
    dh->p=BN_bin2bn(dh2048_p,sizeof(dh2048_p),NULL);
    dh->g=BN_bin2bn(dh2048_g,sizeof(dh2048_g),NULL);
    if (! dh->p || ! dh->g)
    {
      DH_free(dh);
      dh=0;
    }
  }
  return(dh);
}
#endif
#define MAX_PROXY_SERVER    4
#define SSL_STATE_READY    1
#define SSL_STATE_CTX_FAIL   2
#define SSL_STATE_HANDSHAKE_OK   3
#define SSL_STATE_HANDSHAKE_FAIL   4
void handle_connections(int sock, int sd_one, int *sd_array, int ha, char *client_mac_str,char *oracle_server_mac_str,char *oracle_server_ip_str, u_short init_session) {
#define MULTI_SKIP_QUIT \
                { \
                    if(multi_skip) { \
                        multi_skip[i] = 1; \
                        for(j = 0; j < socks; j++) { \
                            if(!multi_skip[j]) break; \
                        } \
                        if(j < socks) continue; \
                    } \
                    goto quit; \
                }

#ifdef ENABLE_SSL
    SSL_CTX    *ctx_2server[MAX_PROXY_SERVER] ;
    SSL_CTX    *ctx_sock   = NULL;
	long ssl_ctx_options= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
	char ca_file[256],cert_file[256],key_file[256],cipher_name[64];
	DH *dh;
	int ssl_server_verify= SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
	int ssl_client_verify= SSL_VERIFY_NONE;
#endif
    SSL         *ssl_sd[MAX_PROXY_SERVER],
                *ssl_sock   = NULL;
    FILE        *dump_fd    = NULL;
    FILE        *dump_tcpdata    = NULL;
    fd_set      rset;
    fd_set      rset_server;
    in_addr_all   clientip,
                serverip,
                sip,
                dip,
				sip_dbfw;
    u32         seq1,
                seq2,
                ack1,
                ack2;
    int         selsock,
                i,
                j,
                len,
                *sd         = NULL,
                select_ret = 0,
                ret = 0,
				ret_compress_for_mysql = 2, /* 压缩函数返回值，返回-2断包 返回 0 非压缩协议 返回1 压缩协议 刘思成添加*/
                socks       = 0;
    u16         sport,
                dport,
				sport_dbfw,
                port_proxy;
    unsigned char          dumpfile[64],
                *buff       = NULL,
                *add,
                *multi_skip = NULL;
    u_int       buff_cursor = 0;
    u_int       send_len = 0;
    Npp_RewriteNetPacket    rewrite_packet;
    int32_t     parse_ret = 0;
    u_char      *tns_pack_data = NULL;              /* TNS Package data */
    u16         package_size = 0;
    u_int       tns_package_size = 0;               /* tns package size from tns header */
    u16         tcp_buffer_size = 0;
    
    int         session_id;
    OraTNS_Header ora_tns_header;
    OraTNS_TCPInfo *tcp_info = (OraTNS_TCPInfo*)ZMalloc(sizeof(OraTNS_TCPInfo));    /* 80 Byte */
    u_char      *error_package = NULL;
    u_int       error_package_len = 0;
    int         conf_change = 0;
    u_int64     alive_time = 0;
    u_int64     last_alive_time = 0;        /* 2014-09-11 增加变量:最后一次设置到fixarea的alivetime时间 */
    u_int64     tlog_timeout_us = 0;
    /* 通讯包异常的校验次数 */
    u_int       fail_tcp_count = 0;
    u_int       fail_tcp_count_s2c = 0;         /* server->client fail tcp count */
    u_int   total_pack_size = 0;                /* 处理“佛山现场问题”的变量 */
    u_int   timeout_recorder = 0;               /* 发呆总时长 */
	Tis_Manager *tis = NULL;
	char errbuf[256];
	Tis_Index   cap_header;
	u_char *sga_proxy_flag;
#ifndef WIN32
    struct timeval select_tv;                   /* Linux下采用select超时处理 */
    struct tm tm_current;
#endif
    /* NEW_TAMPER_FORPROXY变量 */
    u_short tamper_type = 0;        /* 篡改类型 */
    u_short tamper_dbtype = 0;
    u_short tamper_mode = 0;
    u_int address_value = 0;
    u_int64 key=0;
	
	u_int   send_packet_flag = 0;			/* 是否发送包到server的标记,准备发包之前置1,发包之后置0 */
	u_int   send_packet_direct = 0;			/* select超时将检测send_packet_flag标记是否为1,若为1则认为上一次循环中有包应该发但是没有发  */
											/* 则将send_packet_direct置1,直接跳转到发包,将缓冲区中的包都发出                            */
	u_int   send_packet_delay_count = 0;	/* select超时检测次数send_packet_flag为1的次数,若达到次数一定次数,则将send_packet_direct置1 */
	u_int   send_packet_delay_max = 1;      /* select超时最大的检测次数 */
    u_int   __packet_bypass_state = 0;      /* 包因非超时原因引起的转发的当前状态 0 为不转发，1为转发状态*/
	u_int   krb_enc_buff_size = 0;
	int   krb_enc_buff_len = 0;
	u_char  *krb_enc_buff = NULL;
#ifdef HAVE_CHERRY
	//add by luhao for oracle spy sql ATTENTION PACKAGE when input a wrong sql
#ifdef HAVE_SQL_MODIFY_ENGINE
#ifdef HAVE_SQL_SPY
	int attention_cnt = 0;
	u_char * attention_content;
#endif	
#endif
    if(sd_one > 0) {
        //sd = (int*)malloc(sizeof(int));
        sd = (int*)ZMalloc(sizeof(int));        /* 8 Byte */
        if(!sd) std_err();
        sd[0] = sd_one;
        socks = 1;
    } else if(sd_array) {
        sd = sd_array;
        for(i = 0; sd[i] > 0; i++);
        socks = i;
        multi_skip = (unsigned char *)calloc(socks, 1);  // autoreset to 0
    } else {
        goto quit;
    }

	memset(ssl_sd,0,MAX_PROXY_SERVER * sizeof(SSL*));
#ifdef ENABLE_SSL
     SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
	memset(ctx_2server,0,MAX_PROXY_SERVER * sizeof(SSL_CTX*));
	#endif


    if(dump) {
        get_sock_ip_port(sock, &sport, &sip);
        get_peer_ip_port(sd[0], &dport, &dip);  // in case of multihost only the first one is dumped

        add = dumpfile;
        add += sprintf((char*)add, "%s.%hu-", inet_ntoa(*(struct in_addr *)&sip), sport);
        add += sprintf((char*)add, "%s.%hu_", inet_ntoa(*(struct in_addr *)&dip), dport);

        for(i = 1; ; i++) {
            sprintf((char*)add, "%d.acp", i);
            dump_fd = fopen((char*)dumpfile, "rb");
            if(!dump_fd) break;
            fclose(dump_fd);
        }
        dump_fd = fopen((char*)dumpfile, "wb");
        if(!dump_fd) std_err();

        create_acp(dump_fd);
		// TODO:暂时不支持ipv6包输出

//        acp_dump_handshake(dump_fd, SOCK_STREAM, IPPROTO_TCP, sip, htons(sport), dip, htons(dport), NULL, 0, &seq1, &ack1, &seq2, &ack2);
    }
    if(cleardump)
    {
        /* 输出裸包 */
        get_sock_ip_port(sock, &sport, &sip);
        get_peer_ip_port(sd[0], &dport, &dip);  // in case of multihost only the first one is dumped

        add = dumpfile;
        add += sprintf((char*)add, "%s.%hu-", inet_ntoa(*(struct in_addr *)&sip), sport);
        add += sprintf((char*)add, "%s.%hu_", inet_ntoa(*(struct in_addr *)&dip), dport);

        for(i = 1; ; i++) {
            sprintf((char*)add, "%d.tcpdata", i);
            dump_fd = fopen((char*)dumpfile, "rb");
            if(!dump_fd) break;
            fclose(dump_fd);
        }
        dump_fd = fopen((char*)dumpfile, "wb");
        if(!dump_fd) std_err();
    }

	if(ha)
	{
		sga_proxy_flag = (u_char *)(__SGA_SESSBUF->proxy_flag_head);

		memset(errbuf,0,sizeof(errbuf));
		tis = Tis_Get((u_char*)__SGA_CAPBUF.tis,errbuf);
		if(tis == NULL)
		{
			Npp_LogError((u_char*)errbuf,-1,0,__FILE__, __LINE__, __FUNCTION__);
			/* 此处不能直接return，这样有些申请的内存不会被释放，且session的槽位也不会释放 */
			goto quit;
		}

		ret = Tis_Slot_Invalid(tis,(u_int)__NPP_ALL_CONFIG->sessionid_fornpc);
		if(ret < 0)
		{
			sprintf(errbuf,"Tis_Slot_Invalid failed. session id:%d return:%d clientip:%s client_port:%llu",__NPP_ALL_CONFIG->sessionid_fornpc,ret,tcp_info->client_ip_str,tcp_info->client_port);
			Npp_LogError((u_char*)errbuf,-1,0,__FILE__, __LINE__, __FUNCTION__);
			/* 此处不能直接return，这样有些申请的内存不会被释放，且session的槽位也不会释放 */
			goto quit;
		}

	}
	// TODO: 有待确认，此处在threeway中已经初始化，在此不再进行初始化
	get_sock_ip_port(sd[0], &sport_dbfw, &sip_dbfw);

    /* add by yanghaifeng@schina.cn : get ip and port*/
    /* get client and server's ip:port */    
    get_peer_ip_port(sock, &sport, &clientip);
    get_peer_ip_port(sd[0], &dport, &serverip);  // in case of multihost only the first one is dumped

	if(AF_INET6 == __SOCK_TYPE)	
	{
		z_memcpy(&tcp_info->client_ip, &(clientip.in6.s6_addr), sizeof(clientip.in6.s6_addr), __FILE__, __LINE__, Smem_LogError_Format);
		Dwbf_common_ipv6_array_2_string((u_char *)&tcp_info->client_ip, (char*)tcp_info->client_ip_str);
	}else{    	
		tcp_info->client_ip[0] = (u_int64)DBFW_HTON32((u_int64)clientip.in.s_addr);		
		tcp_info->client_ip[1] = 0;	
		z_strcpy((char*)tcp_info->client_ip_str,inet_ntoa(*(struct in_addr *)&clientip.in.s_addr), __FILE__, __LINE__, Smem_LogError_Format);
	}

	if(AF_INET6 == __SOCK_TYPE)	{
		Dbfw_common_ipv6_string_2_array((char *)oracle_server_ip_str,(u_char *)tcp_info->oracle_server_ip);
		z_strcpy((char*)tcp_info->oracle_server_ip_str,oracle_server_ip_str, __FILE__, __LINE__, Smem_LogError_Format);
	}else{
		tcp_info->oracle_server_ip[0] = __DB_ADDRESS;		
		tcp_info->oracle_server_ip[1] = 0;	
		z_strcpy((char*)tcp_info->oracle_server_ip_str,oracle_server_ip_str, __FILE__, __LINE__, Smem_LogError_Format);
	}
	/* 支持域名整改，用上边这种 */
	// if(AF_INET6 == __SOCK_TYPE)	
	// {
	// 	z_memcpy(&tcp_info->oracle_server_ip, &(serverip.in6.s6_addr), sizeof(serverip.in6.s6_addr), __FILE__, __LINE__, Smem_LogError_Format);	
	// 	Dwbf_common_ipv6_array_2_string((u_char *)&tcp_info->oracle_server_ip, (char*)tcp_info->oracle_server_ip_str);
	// }else{    	
	// 	tcp_info->oracle_server_ip[0] = (u_int64)DBFW_HTON32((u_int64)serverip.in.s_addr);		
	// 	tcp_info->oracle_server_ip[1] = 0;	
	// 	z_strcpy((char*)tcp_info->oracle_server_ip_str,inet_ntoa(*(struct in_addr *)&serverip.in.s_addr), __FILE__, __LINE__, Smem_LogError_Format);
	// }

	if(AF_INET6 == __SOCK_TYPE)	
	{
		z_memcpy(&tcp_info->dbfw_ip, &(sip_dbfw.in6.s6_addr), sizeof(sip_dbfw.in6.s6_addr), __FILE__, __LINE__, Smem_LogError_Format);	
	}else{    	
		tcp_info->dbfw_ip[0] = (u_int64)DBFW_HTON32((u_int64)sip_dbfw.in.s_addr);		
		tcp_info->dbfw_ip[1] = 0;	
	}
    
    tcp_info->client_port = sport;
    tcp_info->oracle_server_port = dport;
	tcp_info->dbfw_port = sport_dbfw;
    tcp_info->tcp_secquence = 0;
    tcp_info->tcp_ack = 0;
    z_strcpy((char*)tcp_info->client_mac_str,client_mac_str, __FILE__, __LINE__, Smem_LogError_Format);
    z_strcpy((char*)tcp_info->oracle_server_mac_str,oracle_server_mac_str, __FILE__, __LINE__, Smem_LogError_Format);
	Init_Session_Global(tcp_info,init_session,SOURCECODE,__LINE__);

	#ifdef ENABLE_WHITE_IPADDR
	if(dbsc_sga_whiteipaddr_find(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip[0]))
	{
		Npp_LogInfo_Format(__FILE__, __LINE__, __FUNCTION__,"one saas client. ipaddr: %s",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip_str);
		__ORA_SESSION->sessCommon.white_ipaddr = 1;
	}
	else
	{
		Npp_LogInfo_Format(__FILE__, __LINE__, __FUNCTION__,"one dbctrl client. ipaddr: %s",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_ip_str);
		__ORA_SESSION->sessCommon.white_ipaddr = 0;
	}
	#ifdef ENABLE_LOGIN_BRIDGE
	if(__ORA_SESSION->sessCommon.white_ipaddr == 1)
	{
		__NPP_ALL_CONFIG->login_bridge = 0;
	}
	#endif
	#endif
#ifdef HAVE_DYNAPORT
    /* 
        设置proxy_port: 
        本地代理模式：是代理网卡的端口
        半透明网桥模式：是Oracle的端口
    */

        /* 半透明网桥模式 */
    {
        /* 本地代理或其他模式 */
        get_sock_ip_port(sock, &port_proxy, NULL); /* 代理端口 */
        __ORA_SESSION->help_dynaport_env.proxy_port = port_proxy;
	}
#endif	
	if(ha)
	{
		//restort session info
		Dbfw_Sga_Proxy_SessionInfo *tmp_sessinfo;
		if(AF_INET6 == __SOCK_TYPE)
    	{
    		address_value = Dbfw_hash_xor_key16((void *)&tcp_info->dbfw_ip);
    		key = Dbfw_common_get_db_hashkey(address_value, sport_dbfw, 1);
    	}else{
    		address_value =  Dbfw_hash_xor_key16((void *)&tcp_info->dbfw_ip);
    		key = Dbfw_common_get_db_hashkey(address_value, sport_dbfw, 0);
    	}
// 		tmp_sessinfo = (Dbfw_Sga_Proxy_SessionInfo *)Bslhash_Find((Bslhash_t *)__SGA_SESSBUF->proxy_session_info,key);
// 		__ORA_SESSION->sessioninfo = (u_char *)tmp_sessinfo;
// 		if(tmp_sessinfo != NULL)
// 		{
// 			if(tmp_sessinfo->flag == 1)
// 			{
// 				//参考SessBuf_SessionData_Ora结构的解释(dbfwsga_session.h)
// 				((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_os = tmp_sessinfo->sessdata.client_os;
// 				((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_os_ori = tmp_sessinfo->sessdata.client_os_ori;
// 				((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_os_bit = tmp_sessinfo->sessdata.client_os_bit;
// 				((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->server_os = tmp_sessinfo->sessdata.server_os;
// 				((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->server_os_ori = tmp_sessinfo->sessdata.server_os_ori;
// 				((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->server_os_bit = tmp_sessinfo->sessdata.server_os_bit;
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->auth_session_id,tmp_sessinfo->sessdata.auth_session_id,sizeof(tmp_sessinfo->sessdata.auth_session_id));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->auth_serial_num,tmp_sessinfo->sessdata.auth_serial_num,sizeof(tmp_sessinfo->sessdata.auth_serial_num));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->auth_sc_instance_name,tmp_sessinfo->sessdata.auth_sc_instance_name,sizeof(tmp_sessinfo->sessdata.auth_sc_instance_name));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->auth_sc_service_name,tmp_sessinfo->sessdata.auth_sc_service_name,sizeof(tmp_sessinfo->sessdata.auth_sc_service_name));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->auth_instance_name,tmp_sessinfo->sessdata.auth_instance_name,sizeof(tmp_sessinfo->sessdata.auth_instance_name));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->auth_version_sql,tmp_sessinfo->sessdata.auth_version_sql,sizeof(tmp_sessinfo->sessdata.auth_version_sql));
// 				((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->tx_type = tmp_sessinfo->sessdata.tx_type;
// 				memcpy(&(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->tns_connect_header),&(tmp_sessinfo->sessdata.tns_connect_header),sizeof(tmp_sessinfo->sessdata.tns_connect_header));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->conn_str,tmp_sessinfo->sessdata.conn_str,sizeof(tmp_sessinfo->sessdata.conn_str));
// 				memcpy(&(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->tns_accept_header),&(tmp_sessinfo->sessdata.tns_accept_header),sizeof(tmp_sessinfo->sessdata.tns_accept_header));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->username,tmp_sessinfo->sessdata.username,sizeof(tmp_sessinfo->sessdata.username));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->auth_terminal,tmp_sessinfo->sessdata.auth_terminal,sizeof(tmp_sessinfo->sessdata.auth_terminal));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->auth_program_nm,tmp_sessinfo->sessdata.auth_program_nm,sizeof(tmp_sessinfo->sessdata.auth_program_nm));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->auth_machine,tmp_sessinfo->sessdata.auth_machine,sizeof(tmp_sessinfo->sessdata.auth_machine));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->auth_pid,tmp_sessinfo->sessdata.auth_pid,sizeof(tmp_sessinfo->sessdata.auth_pid));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->auth_sid,tmp_sessinfo->sessdata.auth_sid,sizeof(tmp_sessinfo->sessdata.auth_sid));
// 				memcpy(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->default_schema,tmp_sessinfo->sessdata.default_schema,sizeof(tmp_sessinfo->sessdata.default_schema));
// 				((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->help_start_timestamp = tmp_sessinfo->sessdata.help_start_timestamp;
// 				((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->unique_session_id = tmp_sessinfo->sessdata.unique_session_id;
// #ifdef ENABLE_MYSQL
// 				if(__SGA_AC_XSEC_DATABASE)
// 				{
// 					if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL ||
// 							__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG/* GBase */)
// 					{
// 						memcpy(&(__ORA_SESSION->mysql_capability_flag_1_client),&(tmp_sessinfo->mysql_capability_flag_1_client),sizeof(DBFW_MySQL_CapabilityFlag_Low2Byte));
// 						memcpy(&(__ORA_SESSION->mysql_capability_flag_1_server),&(tmp_sessinfo->mysql_capability_flag_1_server),sizeof(DBFW_MySQL_CapabilityFlag_Low2Byte));
// 						if(__ORA_SESSION->mysql_handshake_response)
// 							((DBFW_MySQL_HandshakeResponse41*)__ORA_SESSION->mysql_handshake_response)->client_character_set = tmp_sessinfo->client_character_set;
// 					}
// 				}
// #endif
// #ifdef ENABLE_DB2
// 				if(__SGA_AC_XSEC_DATABASE)
// 				{
// 					if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_DB2)
// 					{
// 						__ORA_SESSION->db2_ccsid_client.ccsidsbc = tmp_sessinfo->ccsidsbc;
// 					}
// 				}        
// #endif
// 			}
// 		}
#ifdef ENABLE_MYSQL
		if(__SGA_AC_XSEC_DATABASE)
		{
			if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL ||
					__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG/* GBase */)
			{
				memcpy(&(__ORA_SESSION->mysql_capability_flag_1_client),&(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->mysql_capability_flag_1_client),sizeof(DBFW_MySQL_CapabilityFlag_Low2Byte));
				memcpy(&(__ORA_SESSION->mysql_capability_flag_1_server),&(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->mysql_capability_flag_1_server),sizeof(DBFW_MySQL_CapabilityFlag_Low2Byte));
				if(__ORA_SESSION->mysql_handshake_response == NULL)
				{
					DBFW_MySQL_HandshakeResponse41 *mysql_handshakeresponse41 = NULL;
					mysql_handshakeresponse41 = (DBFW_MySQL_HandshakeResponse41*)ZMalloc(sizeof(DBFW_MySQL_HandshakeResponse41));
					Init_MySQL_HandshakeResponse41(mysql_handshakeresponse41);
					__ORA_SESSION->mysql_handshake_response = (void*)mysql_handshakeresponse41;
					__ORA_SESSION->mysql_handshake_response_version = DBFW_MYSQL_PROTOCOL_HANDSHAKERESPONSE41;
				}
				((DBFW_MySQL_HandshakeResponse41*)__ORA_SESSION->mysql_handshake_response)->client_character_set = ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_character_set;
			}
		}
#endif
#ifdef ENABLE_DB2
		if(__SGA_AC_XSEC_DATABASE)
		{
			if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_DB2)
			{
				__ORA_SESSION->db2_ccsid_client.ccsidsbc = ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->ccsidsbc;
			}
		}        
#endif
	}
    #ifdef ENABLE_DBSCLOUD
	dbsc_custom_init();
    #endif
    
    /* 与SQL改写包处理有关的逻辑 */
    rewrite_packet.packparse_result = 0;
    rewrite_packet.packet_num = 0;
    rewrite_packet.tnspack_isfull = 0;
    rewrite_packet.tnspack_num = 0;
    rewrite_packet.packet_broken_flag = 0;
    rewrite_packet.reqid = 0;
    rewrite_packet.stmthandle = 0;
    rewrite_packet.is_switchoff = 0;
    rewrite_packet.raise_for_switchoff = 0;
    rewrite_packet.rowlimit_result = 0;
    rewrite_packet.help_last_packet_type = 0;
    rewrite_packet.placehold_pack_size_req = 0;
    rewrite_packet.placehold_pack_req = NULL;
    rewrite_packet.stmthandle_placehold = 0;
#ifdef HAVE_SQL_MODIFY_ENGINE
	memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
#endif
    for(i=0;i<DBFW_MAX_TNSPACK_FORSQLRW;i++)
    {
        rewrite_packet.packet_size[i] = 0;
        rewrite_packet.packet_data[i] = NULL;
        rewrite_packet.tcpbuff_bak_len[i] = 0;
        rewrite_packet.tcpbuff_bak[i] = NULL;
    }
    rewrite_packet.sqlsize = 0;
    /* 与SQL改写包处理有关的逻辑结束 */
    if(!db_type)
    {
        db_type = (u_char*)malloc(12);
        memset(db_type,0x00,12);
        switch(__SGA_AC_XSEC_DATABASE->dialect)
        {
        case DBFW_DBTYPE_ORACLE:
            z_strcpy((char*)db_type,(char*)"oracle", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        case DBFW_DBTYPE_MSSQL:
		case DBFW_DBTYPE_SYBASE:
            z_strcpy((char*)db_type,(char*)"mssql", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        case DBFW_DBTYPE_DB2: /* DB2 */
            z_strcpy((char*)db_type,(char*)"db2", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        case DBFW_DBTYPE_MYSQL:
        case DBFW_DBTYPE_SHENTONG:
            z_strcpy((char*)db_type,(char*)"mysql", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        case DBFW_DBTYPE_DM:
            z_strcpy((char*)db_type,(char*)"dameng", __FILE__, __LINE__, Smem_LogError_Format);
            break;
		case DBFW_DBTYPE_POSTGREE:
			z_strcpy((char*)db_type,(char*)"pstgre", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_KINGBASE:
			z_strcpy((char*)db_type,(char*)"kbase", __FILE__, __LINE__, Smem_LogError_Format);
			break;
        case DBFW_DBTYPE_OSCAR: /*DBFW_DBTYPE_OSCAR*/
            z_strcpy((char*)db_type,(char*)"oscar", __FILE__, __LINE__, Smem_LogError_Format);
            break;
		case DBFW_DBTYPE_IFX: /*Informix*/
		case DBFW_DBTYPE_GBASE8T:
			z_strcpy((char*)db_type,(char*)"ifx", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_CACHEDB: /*Cachedb*/
			z_strcpy((char*)db_type,(char*)"cachdb", __FILE__, __LINE__, Smem_LogError_Format);
			break;
        case DBFW_DBTYPE_HBASE: /*HBase*/
            z_strcpy((char*)db_type,(char*)"hbase", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        case DBFW_DBTYPE_MONGODB: /*Mongodb*/
            z_strcpy((char*)db_type,(char*)"mongodb", __FILE__, __LINE__, Smem_LogError_Format);
            break;
		case DBFW_DBTYPE_TERADATA: /*teradata*/
			z_strcpy((char*)db_type,(char*)"teradata", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_HIVE: /*Hive*/
            z_strcpy((char*)db_type,(char*)"hive", __FILE__, __LINE__, Smem_LogError_Format);
            break;
		case DBFW_DBTYPE_IMPALA: /*Impala*/
            z_strcpy((char*)db_type,(char*)"impala", __FILE__, __LINE__, Smem_LogError_Format);
            break;
		case DBFW_DBTYPE_HRPC: /*Hdfs*/
            z_strcpy((char*)db_type,(char*)"hrpc", __FILE__, __LINE__, Smem_LogError_Format);
            break;
		case DBFW_DBTYPE_SENTRY: /*Sentry*/
            z_strcpy((char*)db_type,(char*)"sentry", __FILE__, __LINE__, Smem_LogError_Format);
            break;
		case DBFW_DBTYPE_REDIS: /*Redis*/
            z_strcpy((char*)db_type,(char*)"redis", __FILE__, __LINE__, Smem_LogError_Format);
            break;
		case DBFW_DBTYPE_HANA: /*hana*/
			z_strcpy((char*)db_type,(char*)"hana", __FILE__, __LINE__, Smem_LogError_Format);
			break;
		case DBFW_DBTYPE_ES: /*elasticsearch*/
            z_strcpy((char*)db_type,(char*)"es", __FILE__, __LINE__, Smem_LogError_Format);
            break;
		case DBFW_DBTYPE_SYBASEIQ:/*iq*/
			z_strcpy((char*)db_type,(char*)"iq", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        case DBFW_DBTYPE_GAUSSDBT:/*gaussdbt*/
            z_strcpy((char*)db_type,(char*)"gausst", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        case DBFW_DBTYPE_ZOOKEEPER: /*zookeeper*/
            z_strcpy((char*)db_type,(char*)"zk", __FILE__, __LINE__, Smem_LogError_Format);
            break;
        default:
            break;
        }
    }
    buff = (unsigned char *)ZMalloc(ORANET_MAX_PACKAGESIZE);        /* 32838 Byte */
    if(!buff) 
    {
        //std_err();
        /* malloc error exit */
#ifdef WIN32
        Npp_Exception_WithLogAndExit(NPP_ERROR_MALLOC,0,__FILE__, __LINE__, __FUNCTION__,(int)ORANET_MAX_PACKAGESIZE);
#else
        Npp_Exception_WithLogAndExit(NPP_ERROR_MALLOC,errno,__FILE__, __LINE__, __FUNCTION__,(int)ORANET_MAX_PACKAGESIZE);
#endif        
    }
	static int csc_tmp = 0;
	static u_char data[105] = {0x00,0x00,0x00,0x64,0x80,0x01,0x00,0x01,0x00,0x00,0x00,0x12,0x47,0x65,0x74,0x4f,0x70,0x65,0x72,0x61,0x74,0x69,0x6f,0x6e,0x53,0x74,0x61,0x74,0x75,0x73,0x00,0x00,0x00,0x05,0x0c,0x00,0x01,0x0c,0x00,0x01,0x0c,0x00,0x01,0x0b,0x00,0x01,0x00,0x00,0x00,0x10,0x08,0x37,0xce,0xe2,0x48,0xfc,0x42,0x13,0xa3,0x8d,0xaf,0x99,0x12,0x14,0x0c,0xd0,0x0b,0x00,0x02,0x00,0x00,0x00,0x10,0x14,0x8d,0xde,0x6a,0x53,0xe2,0x4f,0xbf,0xb3,0xbd,0x99,0x6b,0x67,0x5a,0x62,0x9c,0x00,0x08,0x00,0x02,0x00,0x00,0x00,0x00,0x02,0x00,0x03,0x01,0x00,0x00,0x00,0x00};

	static u_char data1[107] = {0x00,0x00,0x00,0x66,0x80,0x01,0x00,0x01,0x00,0x00,0x00,0x14,0x47,0x65,0x74,0x52,0x65,0x73,0x75,0x6c,0x74,0x53,0x65,0x74,0x4d,0x65,0x74,0x61,0x64,0x61,0x74,0x61,0x00,0x00,0x00,0x06,0x0c,0x00,0x01,0x0c,0x00,0x01,0x0c,0x00,0x01,0x0b,0x00,0x01,0x00,0x00,0x00,0x10,0x08,0x37,0xce,0xe2,0x48,0xfc,0x42,0x13,0xa3,0x8d,0xaf,0x99,0x12,0x14,0x0c,0xd0,0x0b,0x00,0x02,0x00,0x00,0x00,0x10,0x14,0x8d,0xde,0x6a,0x53,0xe2,0x4f,0xbf,0xb3,0xbd,0x99,0x6b,0x67,0x5a,0x62,0x9c,0x00,0x08,0x00,0x02,0x00,0x00,0x00,0x00,0x02,0x00,0x03,0x01,0x00,0x00,0x00,0x00};
    static u_char db2_rdbcmm[10] = {0x00,0x0a,0xd0,0x01,0x00,0x01,0x00,0x04,0x20,0x0e};
	static u_char cache_data[17] = {0x03,0x00,0x00,0x00,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4f,0x45,0x03,0x04,0x1b};
	for(;;) {
receive_client_and_server:
        FD_ZERO(&rset);
        FD_SET(sock, &rset);
        /* 2015-04-10 增加退出标记检查和处理逻辑，取代handle信号 */
        if(ha)
        {
        	nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
        }
        process_exit_forflag();
        if(ha)
        {
			nppproxy_unregister(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
        }

        /*2019-06-21:xiaxudong FIX BUG:when occurs OOM, then npls_mon will kill npp by DBFWRemoveSem method */
        int* p_smemid = NULL;
        p_smemid = __SGA_SESSBUF->semid_head + __NPP_ALL_CONFIG->sessionid_fornpc;
        if( Dbfw_GetSemValue(*p_smemid) < 0)
        {
            __NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
            process_exit_forflag();
        }

#ifndef WIN32
        /* 设置select的超时时间为1秒 */
        /* TODO : 通过参数来设置超时时间 */
        select_tv.tv_sec = 1;
        select_tv.tv_usec = 0;
#endif
        selsock = sock;
        for(i = 0; i < socks; i++) {
            if(multi_skip && multi_skip[i]) continue;
            FD_SET(sd[i], &rset);
            if(selsock < sd[i]) selsock = sd[i];
        }
        
		if(__NPP_ALL_CONFIG->process_exit_flag == DBFW_HANDLEEXIT_FORREORDER)
			__NPP_ALL_CONFIG->process_exit_flag = DBFW_HANDLEEXIT_NORMAL;
#ifndef WIN32
        select_ret = compat_select(selsock + 1, &rset, NULL, NULL, &select_tv);
#else
        select_ret = compat_select(selsock + 1, &rset, NULL, NULL, NULL);
#endif
#ifdef NEW_TAMPER_FORPROXY
        /* 与SQL改写包处理有关的逻辑 */
        if(__ORA_SESSION)
            __ORA_SESSION->help_parse_result=NPP_RESULT_NORMAL;
        //printf("[CHERRY] : rewrite_packet.is_switchoff = %d\n",rewrite_packet.is_switchoff);
        if(__ORA_SESSION->need_tamper>0)
        {
            /* 发送篡改通讯包 */
            /* 检查当前的篡改标记是否是需要阻断了 */
            //printf("[CHERRY] : help_tamper_flag = %d\n",__ORA_SESSION->help_tamper_flag);
            if(__ORA_SESSION->help_tamper_flag==DBFW_TAMPER_DORESET)
            {
                /* 是，发送篡改+RESET包 */
                __ORA_SESSION->help_tamper_flag = 0;
                goto quit;
            }
            else
            {
                //Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_TAMPER);
            }            
            __ORA_SESSION->need_tamper = 0; /* 清理当前包篡改标记,避免后续的非篡改包被篡改 */
        }
        else if(__ORA_SESSION->help_tamper_flag==DBFW_TAMPER_DORESET)
        {
            /* 检查当前的篡改标记是否是需要阻断了 */
            /* 是，发送阻断包 */
            //Dbfw_SetSendQueueToRtbuf(DBFW_TAMPER_TYPE_SWITCHOFF);
            __ORA_SESSION->help_tamper_flag = 0;
            goto quit;
        }
        else
        {
            /* 发送正常的通讯包 */
            //begin_loop_flag = 1;
        }
#endif  /* NEW_TAMPER_FORPROXY */
        /* 2015-04-10 增加退出标记检查和处理逻辑，取代handle信号 */
        if(ha)
        {
        	nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
        }
        process_exit_forflag();
        if(ha)
        {
			nppproxy_unregister(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
        }
        if(select_ret < 0) {
            //fprintf(stderr, "- select() call failed\n");
#ifdef WIN32
            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SELECT_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,(selsock + 1));
#else
            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SELECT_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,(selsock + 1));
#endif            
			if(errno == EINTR)
			{
				continue;
			}
			goto quit;
        }
        else if(select_ret == 0)
        {
			//每次超时需要更新worktime,即keepalive 时间
			int     keep_alive = 1; //set keep alive
			int     keep_idle = 5; //开始首次keepalive探测前的TCP空闭时间
			int     keep_interval = 5; //两次keepalive探测间隔时间
			int     keep_count = 12; //判定断开前的keepalive探测次数
			u_char var_value[PROCESS_PARAM_MAX_VALUES_LEN];
			uint64_t worktime_deadline;

			/* 取工作时长 */
			memset(var_value, 0x00, sizeof(var_value));
			ret = Dbfw_Fixarray_GetValueAndValuelenInGlobal(&__SGA_FIXARRAY, S_SMON_WORKTIME_DEADLINE, var_value, PROCESS_PARAM_MAX_VALUES_LEN);
			if(ret==GET_PARAM_ERROR || strlen((char*)var_value)==0)
			{    
				worktime_deadline = WORKTIME_DEFALUT; /* 默认值为60秒 */
			}    
			else 
			{    
				worktime_deadline = atoi((char*)var_value);
				if(worktime_deadline==0)
				{
					worktime_deadline = WORKTIME_DEFALUT;
				} 
			}
//    			keep_count = 12;
//    			keep_interval = (worktime_deadline+keep_count-1)/keep_count;
//    			keep_idle = keep_interval;
//    			keep_idle = 20;
//    			keep_interval = 20;

			setsockopt(sock,SOL_SOCKET, SO_KEEPALIVE, (void*)&keep_alive,sizeof(keep_alive));
			setsockopt(sock,SOL_TCP, TCP_KEEPIDLE, (void*)&keep_idle,sizeof(keep_idle));
			setsockopt(sock,SOL_TCP, TCP_KEEPINTVL, (void*)&keep_interval,sizeof(keep_interval));
			setsockopt(sock,SOL_TCP, TCP_KEEPCNT, (void*)&keep_count,sizeof(keep_count));
			for(i = 0; i < socks; i++) {
				if(multi_skip && multi_skip[i]) continue;
				setsockopt(sd[i],SOL_SOCKET, SO_KEEPALIVE, (void*)&keep_alive,sizeof(keep_alive));
				setsockopt(sd[i],SOL_TCP, TCP_KEEPIDLE, (void*)&keep_idle,sizeof(keep_idle));
				setsockopt(sd[i],SOL_TCP, TCP_KEEPINTVL, (void*)&keep_interval,sizeof(keep_interval));
				setsockopt(sd[i],SOL_TCP, TCP_KEEPCNT, (void*)&keep_count,sizeof(keep_count));
			}

            /*保持模式下，当缓存区有包超时，也不转发*/
            if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
            {
                send_packet_flag = 0;
                send_packet_delay_count = 0;
                send_packet_direct = 0;
            }
				
			/* 检测之前循环中是否有包没发 */
			if (send_packet_flag == 1)
			{
				send_packet_delay_count++;
				send_packet_delay_max = Dbfw_Fixarray_GetIntParamInFixarray(&__SGA_FIXARRAY, S_NPP_PROXY_TIMEOUT_TRANS);
                if(send_packet_delay_max ==0)
                {
                	send_packet_delay_count = 0;
                	send_packet_direct = 0;
                	send_packet_flag = 0;
                }
                else
                {
					if (send_packet_delay_count >= send_packet_delay_max)
					{
						send_packet_direct = 1;
						send_packet_delay_count = 0;
						goto client2server_direct;
					}			
				}			
			}
			else
			{
				send_packet_delay_count = 0;
				send_packet_direct = 0;
			}
			
            //fail_tcp_count = 0;
            /* time out 1s */
            /* 检查配置变更；检查是否达到了tlogbuf刷新的时间(默认为10秒) */
            conf_change = Npp_CheckChangeAndReloadAllConfig(__NPP_ALL_CONFIG);
            GetLocalTime_Now(&__NPP_ALL_CONFIG->tm_current);
            /* TODO : 刷新数据到磁盘，或者发送心跳信号 */
            /* 发送AliveSignal */
#ifndef WIN32
            alive_time = Npp_GetEpochTime_MicroSecond();
            __NPP_ALL_CONFIG->current_time = alive_time;
            Dbfw_Fixarray_SetProcessAliveSignal(&__SGA_FIXARRAY, __PROCESS_ID, alive_time,DBFW_PTYPE_NPP);
            /* tlog每隔10秒刷新到tlog buffer区一次，无论这期间是否有通讯包被处理了 */
            ret = NPP_HandleTlog(alive_time,__ORA_SESSION);
#endif
			if(__DB_ISFIND == 0 && __NPP_ALL_CONFIG->has_inst == 0)
				goto quit;
            continue;
        }
        else
        {
            /* 正常获得数据,发送工作信号到SGA */
            timeout_recorder = 0;
            conf_change = Npp_CheckChangeAndReloadAllConfig(__NPP_ALL_CONFIG);
            GetLocalTime_Now(&__NPP_ALL_CONFIG->tm_current);
			if(__DB_ISFIND == 0 && __NPP_ALL_CONFIG->has_inst == 0)
				goto quit;
            /* 发送AliveSignal和WorkSignal */
#ifndef WIN32
            alive_time = Npp_GetEpochTime_MicroSecond();
            __NPP_ALL_CONFIG->current_time = alive_time;
            GetLocalTime((time_t)(alive_time/1000000),&tm_current);
            /* 2014-09-11 
               当session的压力很大时，触发的次数会很频繁
               而worktime和alivetime的值理论上只需要每秒变化一次即可
               这种情况下，为了减少设置worktime和alivetime的次数,需要增加一个最后一次设置alivetime的时间戳指示器，用于判断
               当last_alivetime+1000000 < alivetime时，才设置一次
            */
            if((last_alive_time+1000000) <= alive_time)
            {
                /* 当最后记录的last_alivetime与当前时间相差一秒或以上时，则记录一次 */
                Dbfw_Fixarray_SetProcessAliveSignal(&__SGA_FIXARRAY, __PROCESS_ID, alive_time,DBFW_PTYPE_NPP);
#ifndef HAVE_CHERRY
                Dbfw_Fixarray_SetProcessWorkSignal(&__SGA_FIXARRAY, __PROCESS_ID, alive_time,DBFW_PTYPE_NPP);
#endif
                last_alive_time = alive_time;
            }
#endif
        }
        /* 
        注意：需要解决通讯过程中，通讯包的不连续问题，因此需要参考TNS的协议进行包完整性的校验，并根据其通信的最大长度来过滤掉非法的通讯攻击
        目前的策略是如果发现包不连续了，则不进行解析处理，直接进行通讯转发,这样做能够保证解析的包的完整性 
        可能存在以下两种原因造成捕获的通讯包长度超过了TNS包长度的情况：
          1)由于内容太长，比如SQL语句太长或参数内容太长，造成需要拆分成多个TNS包，而这些包肯定都是U->O或O->U的，并且中间不需要resp
          2)属于非法的攻击包，或错误包
        当发生这种情况时，需要在通讯层和TNS协议解析层之间增加一个通讯缓冲层，对通讯包进行拆包、拼包处理
        */
        if(FD_ISSET(sock, &rset)) 
        {			
			#ifdef ENABLE_SSL
			memset(cipher_name,0,sizeof(cipher_name));
			if(backend_ssl_state == SSL_STATE_READY)
			{
				int jj = 0;
				for(jj=0;jj<socks;jj++)
				{
					ctx_2server[jj] = SSL_CTX_new(TLSv1_client_method());
					SSL_CTX_set_options(ctx_2server[jj], ssl_ctx_options);

					ssl_client_verify= SSL_VERIFY_NONE; //SSL_VERIFY_PEER
					SSL_CTX_set_verify(ctx_2server[jj], ssl_client_verify, NULL);
					/*
					memset(ca_file,0,sizeof(ca_file));
					strcpy(ca_file,"/etc/cert/ca-cert.pem");
					if(!SSL_CTX_load_verify_locations(ctx_2server[jj],ca_file, NULL))
					{
						SSL_CTX_free(ctx_2server[jj]);
						ctx_2server[jj] = NULL;
						backend_ssl_state = SSL_STATE_CTX_FAIL;
						Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_CTX_load_verify_locations failed.  ca_file: %s",ca_file);
						break;
					}
					//  载入公钥证书
					memset(cert_file,0,sizeof(cert_file));
					strcpy(cert_file,"/etc/cert/client-cert.pem");
					if (SSL_CTX_use_certificate_file(ctx_2server[jj],cert_file, SSL_FILETYPE_PEM) <= 0) 
					{
						SSL_CTX_free(ctx_2server[jj]);
						ctx_2server[jj] = NULL;
						backend_ssl_state = SSL_STATE_CTX_FAIL;
						Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_CTX_use_certificate_file failed.  cert_file: %s",cert_file);
						break;
					}

					//   加载私钥证书
					memset(key_file,0,sizeof(key_file));
					strcpy(key_file,"/etc/cert/client-key.pem");
					if (ctx_2server[jj] && SSL_CTX_use_PrivateKey_file(ctx_2server[jj],key_file, SSL_FILETYPE_PEM) <= 0) 
					{
						SSL_CTX_free(ctx_2server[jj]);
						ctx_2server[jj] = NULL;	
						backend_ssl_state = SSL_STATE_CTX_FAIL;
						Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_CTX_use_PrivateKey_file failed.  key_file: %s",key_file);
						break;
					}

					if(!SSL_CTX_check_private_key(ctx_2server[jj])) 
					{
						SSL_CTX_free(ctx_2server[jj]);
						ctx_2server[jj] = NULL;	
						backend_ssl_state = SSL_STATE_CTX_FAIL;
						Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_CTX_check_private_key failed.  key_file: %s",key_file);
						break;
					}
					else
					{
						Npp_LogInfo_Format(__FILE__, __LINE__, __FUNCTION__,"SSL_CTX_check_private_key success.  version: %s",SSLeay_version(SSLEAY_VERSION));			
					}
					*/
					
					//Npp_LogInfo_Format(__FILE__, __LINE__, __FUNCTION__,"backend ssl. sock: %d",sd[jj]);
					ssl_sd[jj] = SSL_new(ctx_2server[jj]);
					//SSL_SESSION_set_timeout(SSL_get_session(ssl_sd[jj]), 3);
					SSL_set_fd(ssl_sd[jj] , sd[jj]);
					SSL_set_mode( ssl_sd[jj],SSL_MODE_AUTO_RETRY );
					ret = SSL_connect(ssl_sd[jj]);
					if (ret <= 0)
					{
						char error_buffer[256];
						memset(error_buffer,0,sizeof(error_buffer));
						int errid = SSL_get_error(ssl_sd[jj],ret);
						if(errid == SSL_ERROR_WANT_READ || errid == SSL_ERROR_WANT_WRITE)
						{
							backend_ssl_state = SSL_STATE_HANDSHAKE_OK;
							ERR_error_string(errid, error_buffer);
							Npp_LogInfo_Format(__FILE__, __LINE__, __FUNCTION__,error_buffer);
						}
						else if(errid == SSL_ERROR_SYSCALL)
						{
							int myerrno = errno;
							if(myerrno)
							{
								SSL_shutdown(ssl_sd[jj]);
								SSL_free(ssl_sd[jj] );
								ssl_sd[jj] = NULL;
								backend_ssl_state = SSL_STATE_HANDSHAKE_FAIL;
								sprintf(error_buffer,"socket error(%d):%s",myerrno,strerror(myerrno));
								Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,error_buffer);
							}
							else
							{
								backend_ssl_state = SSL_STATE_HANDSHAKE_OK;
								//Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_connect success.");
							}
						}
						else
						{
							SSL_shutdown(ssl_sd[jj]);
							SSL_free(ssl_sd[jj] );
							ssl_sd[jj] = NULL;
							backend_ssl_state = SSL_STATE_HANDSHAKE_FAIL;
							ERR_error_string(errid, error_buffer);
							Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_connect failed. %s",error_buffer);
						}
					}
					else
					{
						backend_ssl_state = SSL_STATE_HANDSHAKE_OK;
						strcpy(cipher_name,SSL_get_cipher_name(ssl_sd[jj]));
						Npp_LogInfo_Format(__FILE__, __LINE__, __FUNCTION__,"SSL_connect success. cipher: %s",cipher_name);
					}
				}
			}
			if(frontend_ssl_state == SSL_STATE_READY)
			{
				ctx_sock = SSL_CTX_new(TLSv1_server_method()); //TLSv1_2_server_method
				SSL_CTX_set_options(ctx_sock, ssl_ctx_options);
				

				if(cipher_name[0] == 0)
				{
					strcpy(cipher_name,"AES256-SHA");
				}
				if(SSL_CTX_set_cipher_list(ctx_sock,cipher_name) == 0)
				{
					SSL_CTX_free(ctx_sock);
					ctx_sock = NULL;	
					frontend_ssl_state = SSL_STATE_CTX_FAIL;
					Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_CTX_set_cipher_list failed.");
				}
				
				//SSL_CTX_sess_set_cache_size(ctx_sock, 128);
				//SSL_CTX_set_verify(ctx_sock, ssl_server_verify, NULL);
				memset(ca_file,0,sizeof(ca_file));
				strcpy(ca_file,"/etc/cert/ca-cert.pem");
				if(!SSL_CTX_load_verify_locations(ctx_sock,ca_file, NULL))
				{
					SSL_CTX_free(ctx_sock);
					ctx_sock = NULL;	
					frontend_ssl_state = SSL_STATE_CTX_FAIL;
					Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_CTX_load_verify_locations failed.  ca_file: %s",ca_file);
				}

				/*  载入公钥证书 */
				memset(cert_file,0,sizeof(cert_file));
				strcpy(cert_file,"/etc/cert/server-cert.pem");
				if (SSL_CTX_use_certificate_file(ctx_sock,cert_file, SSL_FILETYPE_PEM) <= 0) 
				{
					SSL_CTX_free(ctx_sock);
					ctx_sock = NULL;
					frontend_ssl_state = SSL_STATE_CTX_FAIL;
					Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_CTX_use_certificate_file failed.  cert_file: %s",cert_file);
				}

				/*   加载私钥证书  */
				memset(key_file,0,sizeof(key_file));
				strcpy(key_file,"/etc/cert/server-key.pem");
				if (ctx_sock && SSL_CTX_use_PrivateKey_file(ctx_sock,key_file, SSL_FILETYPE_PEM) <= 0) 
				{
					SSL_CTX_free(ctx_sock);
					ctx_sock = NULL;	
					frontend_ssl_state = SSL_STATE_CTX_FAIL;
					Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_CTX_use_PrivateKey_file failed.  key_file: %s",key_file);
				}

				if (ctx_sock)
				{
					if(!SSL_CTX_check_private_key(ctx_sock)) 
					{
						SSL_CTX_free(ctx_sock);
						ctx_sock = NULL;	
						frontend_ssl_state = SSL_STATE_CTX_FAIL;
						Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_CTX_check_private_key failed.  key_file: %s",key_file);
					}
					else
					{
						Npp_LogInfo_Format(__FILE__, __LINE__, __FUNCTION__,"SSL_CTX_check_private_key success.  version: %s",SSLeay_version(SSLEAY_VERSION));
					}
				}

				if(ctx_sock)
				{
					#ifdef ENABLE_MYSQL
					dh= get_dh2048();
					if (SSL_CTX_set_tmp_dh(ctx_sock, dh) == 0)
					{
						DH_free(dh);
						SSL_CTX_free(ctx_sock);
						ctx_sock = NULL;
						frontend_ssl_state = SSL_STATE_CTX_FAIL;
						Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_CTX_set_tmp_dh failed.");		
					}
					DH_free(dh);
					#endif
				}
				
				if(ctx_sock)
				{
					ssl_sock = SSL_new(ctx_sock);
					SSL_clear(ssl_sock);
					//Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"frontend ssl.  sock: %d.",sock);
					SSL_set_fd(ssl_sock, sock);
					SSL_set_accept_state(ssl_sock);
					ret = SSL_do_handshake(ssl_sock);									
					//ret = SSL_accept(ssl_sock);
					if (ret <= 0)
					{
						char error_buffer[256];
						int errid = SSL_get_error(ssl_sock,ret);
						if(errid == SSL_ERROR_WANT_READ || errid == SSL_ERROR_WANT_WRITE)
						{
							frontend_ssl_state = SSL_STATE_HANDSHAKE_OK;
							ERR_error_string(errid, error_buffer);
							Npp_LogInfo_Format(__FILE__, __LINE__, __FUNCTION__,error_buffer);
							continue;
						}
						else if(errid == SSL_ERROR_SYSCALL)
						{
							int myerrno = errno;
							if(myerrno != 0)
							{
								SSL_shutdown(ssl_sock);
								SSL_free(ssl_sock);
								ssl_sock = NULL;
								frontend_ssl_state = SSL_STATE_HANDSHAKE_FAIL;
								sprintf(error_buffer,"SSL_accept error(%d):%s",myerrno,strerror(myerrno));
								Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,error_buffer);
							}
							else
							{
								frontend_ssl_state = SSL_STATE_HANDSHAKE_OK;
								Npp_LogInfo_Format(__FILE__, __LINE__, __FUNCTION__,"SSL_accept success.");
								continue;
							}
						}
						else
						{
							SSL_shutdown(ssl_sock);
							SSL_free(ssl_sock);
							ssl_sock = NULL;
							frontend_ssl_state = SSL_STATE_HANDSHAKE_FAIL;
							ERR_error_string(errid, error_buffer);
							Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,"SSL_accept failed. %s",error_buffer);
						}
					}
					else
					{
						frontend_ssl_state = SSL_STATE_HANDSHAKE_OK;
						Npp_LogInfo_Format(__FILE__, __LINE__, __FUNCTION__,"SSL_accept success.");
						continue;
					}
				}
			}
			#endif
			if(ha)
			{
				nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
			}
			#ifdef ENABLE_MYSQL
			if(__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_MYSQL)
			{
				 if(__ORA_SESSION->mysql_help_islogined == 1)
				 {
					len = myrecv(ssl_sock, sock, buff, ORANET_MAX_PACKAGESIZE);
				 }
				 else
				 {
					 MySQL_Header *mysql_header = NULL;
					 u_int mysql_pkg_size = 0;
					len = myrecv_safe(ssl_sock, sock, buff, sizeof(MySQL_Header));
					if(len > 0)
					{
						mysql_header = (MySQL_Header*)buff;
						memcpy(&mysql_pkg_size,mysql_header->packet_size,3);
						len = myrecv_safe(ssl_sock, sock, buff + sizeof(MySQL_Header), mysql_pkg_size);
						len +=  sizeof(MySQL_Header);
						//Npp_LogInfo_Format(__FILE__, __LINE__, __FUNCTION__,"myrecv login from client. sock: %d  len: %d.",sock,len);
					}
				 }
			}
			else
			{
				len = myrecv(ssl_sock, sock, buff, ORANET_MAX_PACKAGESIZE);				
			}
			#else
			len = myrecv(ssl_sock, sock, buff, ORANET_MAX_PACKAGESIZE);			
			#endif
            //fprintf(stderr, "FD_ISSET:local port recv size=%d\n",len);
            if(len <= 0) 
            {
                /* 可能是客户端断开连接了(len=0) */
                if(len<0)
                {
#ifdef WIN32
                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_RECV_FAIL,len,__FILE__, __LINE__, __FUNCTION__,sock);
#else
                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_RECV_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sock);
#endif
                //if(fail_tcp_count>3)
                    goto quit;
                }
                else
                {
                    fail_tcp_count++;
                    //printf("len = %u\n",len);
                    //continue;
                    if(fail_tcp_count>3)
                    {
                        goto quit;
                    }
                    else
                    {
						if(ha)
						{
							nppproxy_unregister(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        goto server2client;
                    }
                }
            }
			if(ha)
			{
				Tis_Package_Info info;
				info.portid = 0;

				ret = Tis_Content_Write(tis,__NPP_ALL_CONFIG->sessionid_fornpc,buff,len,&info);
				if(ret >= 0)
					nppproxy_unregister(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
			}
            if(l_xor & 1) xor_data(buff, len);
//            if(dump_fd) acp_dump(dump_fd, SOCK_STREAM, IPPROTO_TCP, sip, htons(sport), dip, htons(dport), buff, len, &seq1, &ack1, &seq2, &ack2);
            if(dump_stdout) fwrite(buff, 1, len, stdout);
            if(cleardump) fwrite(buff, 1, len, dump_fd);
            if(subst1) subst(buff, len);
            /* parse tns&net8 data */
            //Npp_Dump_Memepool(stdout);
            if(len>0)
            {
				OraNet_DumpSql("======len:%d\n", len);
                fail_tcp_count = 0;
                /* DUMP内存数据 */
#ifdef DUMP_TCPDATA
                if(!dump_tcpdata)
                {
                    dump_tcpdata = fopen((char*)"./dump_tcpdata_da.dat","wb");                    
                }
                if(dump_tcpdata)
                {
                    Npp_DumpDefault(dump_tcpdata,(char*)"--------USER2ORA(len=%d)--------\n",len);
                    Npp_DumpMemoryData(dump_tcpdata,(char*)buff,len);
                }
#endif
                /* 处理佛山现场无连接会话小包问题 */
                if(total_pack_size<1510)
                    total_pack_size = total_pack_size + len;

                if(__DB_ISFIND==0 || __NPP_ALL_CONFIG->dbfw_fordb_state==0
#ifdef USE_RUNTIME_OVERRUN_OPER
				|| ((rewrite_packet.packet_broken_flag >= 0 || rewrite_packet.packet_broken_flag < ORANET_PARSEFUNC_DATABREAK)
				&& (((__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_BYPASS)
					&& (__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_discard, 0) == DBF_RUNTIME_OPER_DISCARD_PKT)) 
				|| (Dbfw_Fixarray_GetIntParamInFixarray(&__SGA_FIXARRAY, S_LICENSE_VALID) <= 0))
				|| (__packet_bypass_state == 1))		
#endif	               	                         
                )

                {
					if(ha)
					{
						nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
					}
                    __packet_bypass_state = 1; /*请求方向已经发生转包*/
                    /* 使用之前备份的Client通讯包，发完所有的缓存的包 */
                    {
#ifdef HAVE_SQL_MODIFY_ENGINE
    					if(rewrite_packet.packet_num>0)
    					{
    						/* 有改写包 */
    						OraNet_DumpSql("~~~~10873~~~~~have sql modify packet~~~~~~~~~~~~~~\n");
    						OraNet_DumpSql("rewrite_packet.packet_num = %d\n",rewrite_packet.packet_num);
							__ORA_SESSION->wait_spy_result = 1;
    						/* 使用改写后的通讯包发送到服务器 */
    						for(i = 0; i < socks; i++) 
    						{
    							if(multi_skip && multi_skip[i]) continue;
    							for(j=0;j<rewrite_packet.packet_num;j++)   /* 发送所有包到Server */
    							{
    								OraNet_DumpSql("send rewrite_packet to server : rewrite_packet.packet_num[%d] = %d\n",j,rewrite_packet.packet_size[j]);
    								{
    									select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.packet_data[j], rewrite_packet.packet_size[j]);
    								}
    								if(select_ret <= 0) 
    								{
#ifdef WIN32
    									Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
    									Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                
    									MULTI_SKIP_QUIT
    								}
    								ZFree(rewrite_packet.packet_data[j]);
    								rewrite_packet.packet_size[j] = 0;
    							}
    							rewrite_packet.packet_num = 0;
                                /* 准备SQL改写和MASK的数据 */
                                __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
                                /* 清理包改写信息 */
                                Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
    							/* 清理包改写信息 */
    							//memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
    						}
    						/* 清理tcpbuff_bak */
#ifdef HAVE_SQL_SPY
                            /* SPY模式下不能清理tcpbuff_bak */
                            if(__ORA_SESSION->is_spy_flag>0 /*&& (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT)*/)
                            {
                                /* 不清理tcpbuff_bak */
                                //OraNet_DumpSql("[not clear tcpbuff_bak] IS SPY mode and spy_sql_type=%d , rewriteinfo_for_request.package_size=%d\n",__ORA_SESSION->spy_sql_type,__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.package_size);
                            }
                            else
                            {
#endif
    							for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
    							{
    								ZFree(rewrite_packet.tcpbuff_bak[j]);
    								rewrite_packet.tcpbuff_bak_len[j] = 0;
    							}
    							rewrite_packet.tnspack_num = 0;
#ifdef HAVE_SQL_SPY
                            }   /* else for SPY模式下不能清理tcpbuff_bak */
#endif
    					}
    					else
    					{
#endif
    	                    for(i = 0; i < socks; i++) 
    	                    {
    	                        //OraNet_DumpSql("client->server 2 : use backup client packet\n");
    	                        if(multi_skip && multi_skip[i]) continue;
    	                        for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
    	                        {
    	                        	OraNet_DumpSql("s->c rewrite_packet.tcpbuff_bak_len[j]:%d\n",rewrite_packet.tcpbuff_bak_len[j]);
    	                            {
    	                                select_ret = mysend(ssl_sd[i] , sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
    	                            }
    	                            if(select_ret <= 0) 
    	                            {
#ifdef WIN32
    	                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
    	                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                
    	                                MULTI_SKIP_QUIT
    	                            }
    	                            ZFree(rewrite_packet.tcpbuff_bak[j]);
    	                            rewrite_packet.tcpbuff_bak_len[j] = 0;
    	                        }
    	                        rewrite_packet.tnspack_num = 0;
#ifdef HAVE_SQL_MODIFY_ENGINE
    	                        /* 准备SQL改写和MASK的数据 */
    	                        __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
    	                        /* 清理包改写信息 */
    	                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
    							/* 清理包改写信息 */
    							//memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
#endif
    	                    }
#ifdef HAVE_SQL_MODIFY_ENGINE
    					}/* for else */
#endif
                    }

                    /* 不是被保护的DB，或者被保护的数据库的状态为“失效”，直接旁路 */
                    for(i = 0; i < socks; i++) 
                    {
                        if(multi_skip && multi_skip[i]) continue;
                        select_ret = mysend(ssl_sd[i], sd[i], buff, len);
                        if(select_ret <= 0) 
                        {
#ifdef WIN32
                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                            
                            MULTI_SKIP_QUIT
                        }
                    }
					if(ha)
					{
						nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
					}
                    goto server2client;
                }
                if(__NPP_ALL_CONFIG->dbfw_fordb_state==1 && __NPP_ALL_CONFIG->dbfw_fordb_state_old==0)
                {
                    /* 保护状态由“失效”变为“生效”，需要关闭连接，强制应用系统重连 */
                    goto quit;
                }
#ifdef HAVE_SQL_MODIFY_ENGINE
				if(__ORA_SESSION->stmt_for_spy)
				{
				    OraNet8_SqlStmtData * stmt_spy = (OraNet8_SqlStmtData *)__ORA_SESSION->stmt_for_spy;
					Release_Stmt(stmt_spy);
					__ORA_SESSION->stmt_for_spy = NULL;
					if(__ORA_SESSION->stmt_spy_handle > 0)
						ZHashDelete(__ORA_SESSION->stmp_table_hash, __ORA_SESSION->stmt_spy_handle);
				}
				__ORA_SESSION->stmt_spy_handle = 0;
#endif
                /* 计算运行时统计信息：时间段内累计上行字节数 */
                if(strcasecmp((char *)db_type,"oracle")==0)
                {
                    /* oracle */
                    rewrite_packet.packet_broken_flag = ORANET_PARSEFUNC_DATABREAK; /* 设置断链标记，使client->server在断链时不发包，保证异常包的正常逻辑 */
                    /* 接收到一个TNS通讯包，首先对包进行备份处理 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        //if(fail_tcp_count>10)
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i], sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
#ifdef HAVE_SQL_MODIFY_ENGINE
                        /* 清理包改写信息 */
                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
#endif
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
						if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->encrypt_alg != 0x11)
						{
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
						}
                    }
                    //printf("len= %d\n",len);
                    
                    send_packet_flag = 1;
                    
#ifdef NEW_TAMPER_FORPROXY
                    /* 准备用于篡改的地址 */
					if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->encrypt_alg != 0x11)
                    	__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef HAVE_SQL_MODIFY_ENGINE
					/* 准备SQL改写和MASK的数据 */
					__ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
#endif
					__ORA_SESSION->is_sns_pkg = 0;
                    tcp_buffer_size = Ora_AddTcpPackageToBuffer(buff,len,tcp_info,USER2ORA); 
                    OraNet_DumpSql("tcp_buffer_size:%d\n",tcp_buffer_size);
					if(tcp_buffer_size == 0)
					{
                        rewrite_packet.packet_broken_flag = 0;
                        goto client2server;
					}
					else
					{
						do{
							/* 进行TNS包的拆包、拼包和包解析处理 */
							tns_pack_data = Ora_TnsPackage_PreProcess(tcp_info,USER2ORA,(u_int*)&tns_package_size);
							if(tns_package_size>0)
							{

								rewrite_packet.packet_broken_flag = 0;
								/* 性能测试：暂时去掉解析逻辑 */
								//parse_ret = 1;
								parse_ret = OraTnsPackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2ORA,&rewrite_packet);
								parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2ORA);
#ifdef HAVE_SQL_MODIFY_ENGINE
                                if(__ORA_SESSION->stmt_for_sqlmodify 
									&& ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag == 1) /* 命中的规则走脱敏逻辑 */
                                {
                                	if(__ORA_SESSION->sqlmodify_flag==1 && __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext>0 &&
									((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule == 1)
									{
	                                    if(__ORA_SESSION->mask_result>0)
	                                    {
	                                        /* 生成脱敏语句成功,脱敏后的SQL语句保存在rewrite_net_packet->rewriteinfo_for_request.new_sql_text */
	                                        /* 判断是否脱敏后的语句中存在*,如果存在则需要通过SPY SQL进行字段列表探测 */
	                                        if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star == 1)
	                                        {
	                                            /* 测试SPY SQL能力 */
#ifdef HAVE_SQL_SPY
                                                /* 生成字段列表探测语句和相应的stmt_for_spy，并且和当前的stmt进行交换 */
                                                if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->stmtCommon.sqltype_1 == 8)
                                                {
                                                	{
														u_int idx = 0;
														for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx ++)
														{
															__ORA_SESSION->tcpbuff_bak_len[idx] = 0;
															ZFree(__ORA_SESSION->tcpbuff_bak[idx]);
														}
														__ORA_SESSION->tnspack_num = 0;
														{
															memset(&__ORA_SESSION->rewriteinfo_for_request, 0x00, sizeof(Npp_RewriteInfoForRequestPack));
															memcpy(&__ORA_SESSION->rewriteinfo_for_request, &__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
															__ORA_SESSION->rewriteinfo_for_request.use_get_table_desc = 1;
															__ORA_SESSION->tnspack_num = __ORA_SESSION->rewrite_net_packet->tnspack_num;
															for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx ++)
															{
																__ORA_SESSION->tcpbuff_bak_len[idx] = __ORA_SESSION->rewrite_net_packet->tcpbuff_bak_len[idx];
																__ORA_SESSION->tcpbuff_bak[idx] = (u_char*)ZMalloc(__ORA_SESSION->tcpbuff_bak_len[idx]);
																memcpy(__ORA_SESSION->tcpbuff_bak[idx], __ORA_SESSION->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak_len[idx]);
															}
														}
													}
                                                	OraNet_DumpSql("======opt spy\n");
#ifdef HAVE_SQL_TREE
													if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
													{
														Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
														memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
														memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
														__ORA_SESSION->table_index = 0;
														__ORA_SESSION->nonneed_table = 0;
														//Dbfw_GetTableAndAlisa(__ORA_SESSION);
														GetTableFromSqlTree((void*)__ORA_SESSION);
														Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
														Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
														ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,1);
														if(ret>0)
														{
															if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
															{
																memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
																((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
																int idx = 0;
																for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
																{
																	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
																	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
																	memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
																}
															}
															__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
															ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
																(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
																((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
															attention_cnt = 0;
														}
														if(__ORA_SESSION->table_index == 0)
														{
															__ORA_SESSION->spy_field_result = 3;
														}
														else
														{
															__ORA_SESSION->spy_field_result = 2;
														}

													}
												    else
#endif
	                                                {
															ret = Dbfw_PrepareSqlSpy_ForFieldDetect_ChangeOpt(__ORA_SESSION);
															if(ret>0)
															{
																/* 使用新生成的字段列表探测语句生成通讯包,准备发送到服务器 */
																ret = Dbfw_SqlModifyPacket_Opt(__ORA_SESSION,NULL,0,
																	(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
																	((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length);
																attention_cnt = 0;
														}
													}
                                                }
                                                else
                                                {
                                               	 	OraNet_DumpSql("====== spy\n");
													if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star == 1)
													{
														u_int idx = 0;
														for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx ++)
														{
															__ORA_SESSION->tcpbuff_bak_len[idx] = 0;
															ZFree(__ORA_SESSION->tcpbuff_bak[idx]);
														}
														__ORA_SESSION->tnspack_num = 0;
														{
															memset(&__ORA_SESSION->rewriteinfo_for_request, 0x00, sizeof(Npp_RewriteInfoForRequestPack));
															memcpy(&__ORA_SESSION->rewriteinfo_for_request, &__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
															__ORA_SESSION->rewriteinfo_for_request.use_get_table_desc = 1;
															__ORA_SESSION->tnspack_num = __ORA_SESSION->rewrite_net_packet->tnspack_num;
															for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx ++)
															{
																__ORA_SESSION->tcpbuff_bak_len[idx] = __ORA_SESSION->rewrite_net_packet->tcpbuff_bak_len[idx];
																__ORA_SESSION->tcpbuff_bak[idx] = (u_char*)ZMalloc(__ORA_SESSION->tcpbuff_bak_len[idx]);
																memcpy(__ORA_SESSION->tcpbuff_bak[idx], __ORA_SESSION->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak_len[idx]);
															}
														}
													}
													ret = Dbfw_PrepareSqlSpy_ForFieldDetect(__ORA_SESSION);

													if(ret>0)
													{
														/* 使用新生成的字段列表探测语句生成通讯包,准备发送到服务器 */
														ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
															(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
															((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,0);
														attention_cnt = 0;
													}
                                                 }
#endif
	                                        }
	                                        else
	                                        {
												//__ORA_SESSION->spy_field_result = 5;
	                                            /* 没有*需要处理，直接使用脱敏后的SQL语句生成通讯包 */
	                                            ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
	                                                (char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text,
	                                                __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size,0);
	                                        }
	                                    }
                                	}
									else
									{
#ifdef DBFW_PASSWD_BRIDGE
										if(__ORA_SESSION->change_schema_sql_len > 0)
										{
											ret = Dbfw_SqlModifyPacket(__ORA_SESSION, NULL, 0, (char*)__ORA_SESSION->change_schema_sql, __ORA_SESSION->change_schema_sql_len,0);
											__ORA_SESSION->change_schema_sql_len = 0;
											ZFree(__ORA_SESSION->change_schema_sql);
										}
#endif
										Dbfw_ResetRewriteInfoForRequestPack((void*)__ORA_SESSION);
									}
									__ORA_SESSION->sqlmodify_flag = 0;	  /* 恢复SQL改写标记为0 */
                                }
#endif
								/* 脱敏改写 */

								/*对于9i的oci，现采取的措施是拦截掉，退出*/
								if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->tns_connect_header.tns_version == ORA_TNS_VER_312)
								{
                                    OraNet_DumpSql("Oracle 9i(Client) TNS=%d\n",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->tns_connect_header.tns_version);
								}
								if(rewrite_packet.packparse_result>0)
								{
process_sqlreplace: /* 处理SQL重写包的处理逻辑的入口 */
									/* 进入SQL重写包的处理逻辑 */
									OraNet_DumpSql("rewrite_packet.packet_num = %d\n",rewrite_packet.packet_num);
									/* 这里暂时先释放该数据，以避免目前的memleak错误，等逻辑实现完整后再调整 */
									{
										if(tns_pack_data!=NULL)
										{
											ZFree(tns_pack_data);
											tns_pack_data = NULL;
										}
									}
									OraNet_DumpSql("goto client2server\n");
									goto client2server;
								}                            
								if(tns_pack_data!=NULL)
									ZFree(tns_pack_data);
							}
						}
						while(tns_package_size>0);
						
					}
                }
                else if(strcasecmp((char *)db_type,"mssql")==0)
                {
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    rewrite_packet.packet_broken_flag = ORANET_PARSEFUNC_DATABREAK;
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        //if(fail_tcp_count>10)
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i], sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                //if(fail_tcp_count>10)
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
#ifdef HAVE_SQL_MODIFY_ENGINE
                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
#endif
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
					else
					{
						/* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
						rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
						rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
						z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
						rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
					}
					/*陈寿仓添加结束*/
					
					send_packet_flag = 1;
					
#ifdef NEW_TAMPER_FORPROXY
                    /* 准备用于篡改的地址 */
                    __ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef HAVE_SQL_MODIFY_ENGINE
                    /* 准备SQL改写和MASK的数据 */
                    __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
#endif
                    /* MSSQL */
#ifdef ENABLE_MSSQL
                    tcp_buffer_size = MSTDS_AddTcpPackageToBuffer(buff,len,tcp_info,USER2MSSQL);
					if(tcp_buffer_size == 0)
					{

						rewrite_packet.packet_broken_flag = 0;
						goto client2server;
					}
                    //printf("(user->MSSQL) add to buffer:size=%d\n",tcp_buffer_size);
                    do{
                        tns_pack_data = MSTDS_Package_PreProcess(tcp_info,USER2MSSQL,(u_int*)&tns_package_size);
                        
                        if(tns_package_size == 0 
                            && __ORA_SESSION != NULL
                            && __ORA_SESSION->skip_for_error_package == 1)
                        {
                            rewrite_packet.packet_broken_flag = 0;
                            __ORA_SESSION->skip_for_error_package = 0;
    						goto client2server;
                        }
                        if(tns_package_size>0)
                        {
                        	rewrite_packet.packet_broken_flag = 0;
                            parse_ret = MSTDSPackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2MSSQL,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2MSSQL);
#ifdef HAVE_SQL_MODIFY_ENGINE
							if(__ORA_SESSION->stmt_for_sqlmodify && ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag == 1)
							{
								if(__ORA_SESSION->sqlmodify_flag==1 && __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext>0 &&
								((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule == 1
								&& __ORA_SESSION->mask_result>0)
								{
									/* 生成脱敏语句成功,脱敏后的SQL语句保存在rewrite_net_packet->rewriteinfo_for_request.new_sql_text */
									/* 判断是否脱敏后的语句中存在*,如果存在则需要通过SPY SQL进行字段列表探测 */
									
									if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star == 1)
									{
#ifdef HAVE_SQL_SPY
#ifdef HAVE_SQL_TREE
												if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
												{
													Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
													memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
													memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
													__ORA_SESSION->table_index = 0;
													__ORA_SESSION->nonneed_table = 0;
													//Dbfw_GetTableAndAlisa(__ORA_SESSION);
													GetTableFromSqlTree((void*)__ORA_SESSION);
													Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
													Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
													ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,1);
													if(ret>0)
													{
														if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
														{
															memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
															((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
															int idx = 0;
															for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
															{
																((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
																((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
																memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
															}
														}
														__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
														ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
															(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
															((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
														attention_cnt = 0;
													}
													if(__ORA_SESSION->table_index == 0)
													{
														__ORA_SESSION->spy_field_result = 3;
													}
													else
													{
														__ORA_SESSION->spy_field_result = 2;
													}
												}
                                        else
#endif
									    {
										/* 生成字段列表探测语句和相应的stmt_for_spy，并且和当前的stmt进行交换 */
										ret = Dbfw_PrepareSqlSpy_ForFieldDetect(__ORA_SESSION);
										if(ret>0)
										{
											/* 使用新生成的字段列表探测语句生成通讯包,准备发送到服务器 */
											ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
													(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
													((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,0);
											attention_cnt = 0;
										}								 
										}								 
#endif
									}
									else
									{
										/* 没有*需要处理，直接使用脱敏后的SQL语句生成通讯包 */
										ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
											(char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text,
											__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size,0);
									}
								}
								else
								{
									/* 数据不正常，需要清理 */
									Dbfw_ResetRewriteInfoForRequestPack((void*)__ORA_SESSION);
								}
								__ORA_SESSION->sqlmodify_flag = 0;	  /* 恢复SQL改写标记为0 */
							}
#endif
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }
                /* 2014-04-17 */
                else if(strcasecmp((char *)db_type,"mysql")==0)
                {
                    /* mysql协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    rewrite_packet.packet_broken_flag = ORANET_PARSEFUNC_DATABREAK; /* 设置断链标记，使client->server在断链时不发包，保证异>
      常包的正常逻辑 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        //if(fail_tcp_count>10)
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i], sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
#ifdef HAVE_SQL_MODIFY_ENGINE
						/* 清理包改写信息 */
                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
#endif
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef ENABLE_MYSQL
                         /* 刘思成开始添加 */
                         if(__ORA_SESSION->mysql_capability_flag_1_client.client_ssl == 1 
                                && __ORA_SESSION->mysql_capability_flag_1_server.client_ssl == 1)
                          {
								#ifdef ENABLE_SSL
								if(frontend_ssl_state == SSL_STATE_CTX_FAIL || frontend_ssl_state == SSL_STATE_HANDSHAKE_FAIL)
								{
									rewrite_packet.packet_broken_flag = 0;
									goto client2server;
								}
								if(backend_ssl_state == SSL_STATE_CTX_FAIL || backend_ssl_state == SSL_STATE_HANDSHAKE_FAIL)
								{
									rewrite_packet.packet_broken_flag = 0;
									goto client2server;
								}
								#else
                                if(__ORA_SESSION->log_flag == 0)
                                {
                                    __ORA_SESSION->log_flag = 1;
                                    Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__
                                        ,(char*)"find mysql ssl session,bypass");
                                }
                             rewrite_packet.packet_broken_flag = 0;
	                        goto client2server;
								#endif
                          }
						  ret_compress_for_mysql = MYSQL_Uncompress(tcp_info,buff,len,USER2MYSQL);	
						  if(ret_compress_for_mysql != -2)/* 非断包 */
						  {
							  if (ret_compress_for_mysql == 0)/* 非压缩 */
							  {
								  tcp_buffer_size = MYSQL_AddTcpPackageToBuffer(buff,len,tcp_info,USER2MYSQL);
								  if(tcp_buffer_size == 0) 
			                      {     
			                        rewrite_packet.packet_broken_flag = 0;
			                        goto client2server;
			                      }   
#ifdef NEW_TAMPER_FORPROXY
                                  /* 准备用于篡改的地址 */
                                  __ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef HAVE_SQL_MODIFY_ENGINE
								  /* 准备SQL改写和MASK的数据 */
								  __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
#endif
							  }
							  else
							  {
							  tcp_buffer_size = MYSQL_AddTcpPackageToBuffer(__ORA_SESSION->mysql_dyna_uncompress_buff,__ORA_SESSION->mysql_dyna_uncompress_buff_size,tcp_info,USER2MYSQL);
							  ZFree(__ORA_SESSION->mysql_dyna_uncompress_buff);
							  __ORA_SESSION->mysql_dyna_uncompress_buff_size =0;
								   if(tcp_buffer_size == 0) 
	        	                  {     
			            	            rewrite_packet.packet_broken_flag = 0;
			        	                goto client2server;
			                      }   
							  }
						  
						do{
							tns_pack_data = MYSQL_Package_PreProcess(tcp_info,USER2MYSQL,(u_int*)&tns_package_size);
							if(tns_package_size>0)
							{
								rewrite_packet.packet_broken_flag = 0;
								parse_ret = MYSQL_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2MYSQL,&rewrite_packet);
								parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2ORA);
#ifdef HAVE_SQL_MODIFY_ENGINE
                                /* TODO 先进行是否需要进行脱敏的检查(参考后面的检查逻辑) */
                                /* 如果需要脱敏，则调用Dbfw_MakeMaskSql_General函数进行脱敏处理 */
                                if(__ORA_SESSION->stmt_for_sqlmodify 
									&& ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag == 1) /* 命中的规则走脱敏逻辑 */
                                {
                                	if(__ORA_SESSION->sqlmodify_flag==1 && __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext>0 &&
									((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule == 1)		//与ora定义的一致
									{
	                                    if(__ORA_SESSION->mask_result>0)
	                                    {
	                                        /* 生成脱敏语句成功,脱敏后的SQL语句保存在rewrite_net_packet->rewriteinfo_for_request.new_sql_text */
	                                        /* 判断是否脱敏后的语句中存在*,如果存在则需要通过SPY SQL进行字段列表探测 */
	                                        
	                                        if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star == 1)	                                        
	                                        {
	                                            /* 测试SPY SQL能力 */
#ifdef HAVE_SQL_SPY
                                                /* 生成字段列表探测语句和相应的stmt_for_spy，并且和当前的stmt进行交换 */
                                                ret = Dbfw_PrepareSqlSpy_ForFieldDetect(__ORA_SESSION);
                                                if(ret>0)
                                                {
                                                    /* 使用新生成的字段列表探测语句生成通讯包,准备发送到服务器 */
                                                    ret = Dbfw_SqlModifyPacket(__ORA_SESSION,(void*)tns_pack_data,(int)tns_package_size,
                                                        (char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
                                                        ((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,0);
                                                }                              
#endif
	                                        }
	                                        else
	                                        {
	                                            /* 没有*需要处理，直接使用脱敏后的SQL语句生成通讯包 */
	                                            ret = Dbfw_SqlModifyPacket(__ORA_SESSION,(void*)tns_pack_data,(int)tns_package_size,
	                                                (char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text,
	                                                __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size,0);
	                                        }
	                                    }
                                	}
									else
									{
										/* 数据不正常，需要清理 */
										Dbfw_ResetRewriteInfoForRequestPack((void*)__ORA_SESSION);
									}
									__ORA_SESSION->sqlmodify_flag = 0;	  /* 恢复SQL改写标记为0 */
                                }
#endif
								if(tns_pack_data!=NULL)
									ZFree(tns_pack_data);
							}
						  }
						while(tns_package_size>0);
						
                        if(__ORA_SESSION->mysql_capability_flag_1_client.client_ssl == 1 
                                && __ORA_SESSION->mysql_capability_flag_1_server.client_ssl == 1)
                          {
								#ifdef ENABLE_SSL
                                if(__ORA_SESSION->log_flag == 0)
                                {
                                    __ORA_SESSION->log_flag = 1;
									Npp_LogInfo_Format(__FILE__, __LINE__, __FUNCTION__,"find mysql ssl session,process ssl session");	
                                }
								if(frontend_ssl_state == 0)
								{
									__ORA_SESSION->mysql_help_islogined = 0;
									frontend_ssl_state = SSL_STATE_READY;
								}
								if(backend_ssl_state == 0)
								{
									backend_ssl_state = SSL_STATE_READY;
								}
							#endif
                          }
					    }	
					   
					   /* 刘思成添加结束 */
#endif
                }
                /* 2014-03-04 */
                else if(strcasecmp((char *)db_type,"db2")==0)
                {
                    /* Db2协议解析 */
                    rewrite_packet.packet_broken_flag = ORANET_PARSEFUNC_DATABREAK;
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i], sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
#ifdef HAVE_SQL_MODIFY_ENGINE
                        /* 清理包改写信息 */
                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
						/* 清理包改写信息 */
#endif
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef HAVE_SQL_MODIFY_ENGINE
                    /* 准备SQL改写和MASK的数据 */
                    __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
					__ORA_SESSION->mask_result = 0;
#endif
#ifdef ENABLE_DB2
                    OraNet_DumpSql("start DB2_AddTcpPackageToBuffer : %d\n",len);
                    tcp_buffer_size = DB2_AddTcpPackageToBuffer(buff,len,tcp_info,USER2DB2);
                    do{
						OraNet_DumpSql("DB2_Package_PreProcess\n");
                        tns_pack_data = DB2_Package_PreProcess(tcp_info,USER2DB2,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
							OraNet_DumpSql("DB2_PackageParse\n");
                        	rewrite_packet.packet_broken_flag = 0;
                            parse_ret = DB2_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2DB2,&rewrite_packet);
							OraNet_DumpSql("parse_ret:%d,tns_package_size:%d\n\n",parse_ret,tns_package_size);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2ORA);
							if(rewrite_packet.packparse_result==NPP_RESULT_SWITCHOFF || rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
								__ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF || __ORA_SESSION->help_parse_result==NPP_RESULT_BLOCKING_THROW)
								__ORA_SESSION->respon_switchoff_moresql = NPP_RESULT_SWITCHOFF;
#ifdef HAVE_SQL_MODIFY_ENGINE
							if(__ORA_SESSION->stmt_for_sqlmodify 
								&& ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag == 1) /* 命中的规则走脱敏逻辑 */
							{
								if(__ORA_SESSION->sqlmodify_flag==1 && __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext>0 &&
								((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule == 1)
								{
									if(__ORA_SESSION->mask_result>0)
									{
										/* 生成脱敏语句成功,脱敏后的SQL语句保存在rewrite_net_packet->rewriteinfo_for_request.new_sql_text */
										/* 判断是否脱敏后的语句中存在*,如果存在则需要通过SPY SQL进行字段列表探测 */
										if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star == 1)
										{
											/* 测试SPY SQL能力 */
#ifdef HAVE_SQL_SPY
											/* 生成字段列表探测语句和相应的stmt_for_spy，并且和当前的stmt进行交换 */
													{
														u_int idx = 0;
														for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx ++)
														{
															__ORA_SESSION->tcpbuff_bak_len[idx] = 0;
															ZFree(__ORA_SESSION->tcpbuff_bak[idx]);
														}
														__ORA_SESSION->tnspack_num = 0;
														{
															memset(&__ORA_SESSION->rewriteinfo_for_request, 0x00, sizeof(Npp_RewriteInfoForRequestPack));
															memcpy(&__ORA_SESSION->rewriteinfo_for_request, &__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
															__ORA_SESSION->rewriteinfo_for_request.use_get_table_desc = 1;
															__ORA_SESSION->tnspack_num = __ORA_SESSION->rewrite_net_packet->tnspack_num;
															for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx ++)
															{
																__ORA_SESSION->tcpbuff_bak_len[idx] = __ORA_SESSION->rewrite_net_packet->tcpbuff_bak_len[idx];
																__ORA_SESSION->tcpbuff_bak[idx] = (u_char*)ZMalloc(__ORA_SESSION->tcpbuff_bak_len[idx]);
																memcpy(__ORA_SESSION->tcpbuff_bak[idx], __ORA_SESSION->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak_len[idx]);
															}
														}
													}
													if(1==1)
													{
														Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
														memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
														memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
														__ORA_SESSION->table_index = 0;
														__ORA_SESSION->nonneed_table = 0;
														Dbfw_GetTableAndAlisa(__ORA_SESSION);
														//GetTableFromSqlTree((void*)__ORA_SESSION);
														Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
														Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
														ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,1);
														if(ret>0)
														{
															if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
															{
																memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
																((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
																int idx = 0;
																for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
																{
																	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
																	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
																	memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
																}
															}
															__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
															ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
																(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
																((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
															attention_cnt = 0;
														}
														if(__ORA_SESSION->table_index == 0)
														{
															__ORA_SESSION->spy_field_result = 3;
														}
														else
														{
															__ORA_SESSION->spy_field_result = 2;
														}
													}
													else
													{

												ret = Dbfw_PrepareSqlSpy_ForFieldDetect(__ORA_SESSION);

												if(ret>0)
												{
													/* 使用新生成的字段列表探测语句生成通讯包,准备发送到服务器 */
													ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
														(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
														((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,0);
													attention_cnt = 0;
												}
													}
			
#endif
										}
										else
										{
											/* 没有*需要处理，直接使用脱敏后的SQL语句生成通讯包 */
											ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
												(char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text,
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size,0);
										}
									}
								}
								else
								{
									/* 数据不正常，需要清理 */
									Dbfw_ResetRewriteInfoForRequestPack((void*)__ORA_SESSION);
								}
								__ORA_SESSION->sqlmodify_flag = 0;	  /* 恢复SQL改写标记为0 */
							}
#endif

                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
//                                if(rewrite_packet.packparse_result>0)
//                                {
//                                	goto client2server;
//                                }
                        }
#ifdef HAVE_SQL_MODIFY_ENGINE
                        /* 处理长SQL语句分包问题 */
                        else
                        {
                            if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor>0 &&
                                ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor < ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage
                               )
                            {
                                /* 包还没有解析完 */
                                OraNet_DumpSql("ATTENTION have more pack data need parse : buffer_cursor=%d\n",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor);
                                rewrite_packet.packet_broken_flag = ORANET_PARSEFUNC_DATABREAK; /* 设置断链标记，使client->server在断链时不发包，保证异常包的正常逻辑 */
                            }
                        }

						if(rewrite_packet.packet_broken_flag == ORANET_PARSEFUNC_DATABREAK)
							__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.package_break_pos = __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.start_cursor_for03xx;
#endif
					}
                    while(tns_package_size>0);
#endif
                }
                /* 2014-03-18 */
                else if(strcasecmp((char *)db_type,"dameng")==0)
                {
                    /* 达梦数据库协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    rewrite_packet.packet_broken_flag = ORANET_PARSEFUNC_DATABREAK; /* 设置断链标记，使client->server在断链时不发包，保证异>
      常包的正常逻辑 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i], sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
#ifdef HAVE_SQL_MODIFY_ENGINE
                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
						//memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
#endif
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef NEW_TAMPER_FORPROXY
                    /* 准备用于篡改的地址 */
                    __ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef HAVE_SQL_MODIFY_ENGINE
                    /* 准备SQL改写和MASK的数据 */
                    __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
#endif
#ifdef ENABLE_DM
                    tcp_buffer_size = DM_AddTcpPackageToBuffer(buff,len,tcp_info,USER2DM);
                    if(tcp_buffer_size == 0)
                    {
                    	rewrite_packet.packet_broken_flag = 0;                    	
                    	goto client2server;
                    }
                    do{
                        tns_pack_data = DM_Package_PreProcess(tcp_info,USER2DM,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
                        	rewrite_packet.packet_broken_flag = 0; 
                            parse_ret = DM_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2DM,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2ORA);
#ifdef HAVE_SQL_MODIFY_ENGINE
							if(__ORA_SESSION->stmt_for_sqlmodify && ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag == 1)
							{
								/* 说明已经进行了规则校验，但是回存在一个问题，参数化语句暂未处理 */
								if(__ORA_SESSION->sqlmodify_flag==1 && __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext>0 &&
								((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->currStmtCommon->blackorwhite == 8)
								{
									int ret_tmp = 0;
									ret_tmp = Dbfw_SqlModifyPacket_ForDaMeng((void*)__ORA_SESSION,(void*)tns_pack_data,(int)tns_package_size);
									OraNet_DumpSql("ret_tmp:%d\n",ret_tmp); 									if(ret_tmp>0)
									{
										__ORA_SESSION->sqlmodify_result = 0x01;
									}
									else
									{
										__ORA_SESSION->sqlmodify_result = 0x00;
									}
									OraNet_DumpSql("ora_session->sqlmodify_result = %d\n",__ORA_SESSION->sqlmodify_result);
									Dbfw_ResetRewriteInfoForRequestPack((void*)__ORA_SESSION);
								}
								else
								{
									/* 数据不正常，需要清理 */
									Dbfw_ResetRewriteInfoForRequestPack((void*)__ORA_SESSION);
								}
								__ORA_SESSION->sqlmodify_flag = 0;	  /* 恢复SQL改写标记为0 */
							}					
#endif

                            //parse_ret = 1;
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }
				/* 2015-01-10 */
				else if (strcasecmp((char *)db_type,"pstgre") == 0)
				{
					  /* Postgre数据库协议解析 */
        			  rewrite_packet.packet_broken_flag = ORANET_PARSEFUNC_DATABREAK; /* 设置断链标记，使client->server在断链时不发包，保证异>
						   常包的正常逻辑 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    //Npp_DumpMemoryData(stdout,(char*)rewrite_packet.tcpbuff_bak[j],rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        //if(fail_tcp_count>10)
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i], sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                //if(fail_tcp_count>10)
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
#ifdef HAVE_SQL_MODIFY_ENGINE
                        /* 清理包改写信息 */
                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
#endif
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef NEW_TAMPER_FORPROXY
					/* 准备用于篡改的地址 */
					__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef HAVE_SQL_MODIFY_ENGINE
                    /* 准备SQL改写和MASK的数据 */
                    __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
#endif
#ifdef ENABLE_PGSQL
					tcp_buffer_size = PG_AddTcpPackageToBuffer(buff,len,tcp_info,USER2PG);
					if(tcp_buffer_size == 0)
					{
                        rewrite_packet.packet_broken_flag = 0;
                        goto client2server;
					}

					do{
						if((((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor < ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage ))
						{
							rewrite_packet.packet_broken_flag = ORANET_PARSEFUNC_DATABREAK; /* 设置断链标记，使client->server在断链时不发包，保证异>
								 常包的正常逻辑 */
						}
						tns_pack_data = PG_Package_PreProcess(tcp_info,USER2PG,(u_int*)&tns_package_size);
						
						if(tns_package_size>0)
						{
							rewrite_packet.packet_broken_flag = 0;
							parse_ret = PG_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2PG,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2PG);
#ifdef HAVE_SQL_MODIFY_ENGINE
							/* 先检查end_cursor_for_sqltext是否已经获取到正确的值，如果是0则表示没有解析完整 */
							if(__ORA_SESSION->stmt_for_sqlmodify && ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag == 1)
							{
								/* 说明已经进行了规则校验，但是回存在一个问题，参数化语句暂未处理 */
								if(__ORA_SESSION->sqlmodify_flag==1 && __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext>0 &&
								((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule == 1)

								{
									if(__ORA_SESSION->mask_result>0)
									{
											 /* 生成脱敏语句成功,脱敏后的SQL语句保存在rewrite_net_packet->rewriteinfo_for_request.new_sql_text */
											 /* 判断是否脱敏后的语句中存在*,如果存在则需要通过SPY SQL进行字段列表探测 */
										if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star == 1)
										{
#ifdef HAVE_SQL_SPY
											/* 生成字段列表探测语句和相应的stmt_for_spy，并且和当前的stmt进行交换 */
											{
														u_int idx = 0;
														for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx ++)
														{
															__ORA_SESSION->tcpbuff_bak_len[idx] = 0;
															ZFree(__ORA_SESSION->tcpbuff_bak[idx]);
														}
														__ORA_SESSION->tnspack_num = 0;
														{
															memset(&__ORA_SESSION->rewriteinfo_for_request, 0x00, sizeof(Npp_RewriteInfoForRequestPack));
															memcpy(&__ORA_SESSION->rewriteinfo_for_request, &__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
															__ORA_SESSION->rewriteinfo_for_request.use_get_table_desc = 1;
															__ORA_SESSION->tnspack_num = __ORA_SESSION->rewrite_net_packet->tnspack_num;
															for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx ++)
															{
																__ORA_SESSION->tcpbuff_bak_len[idx] = __ORA_SESSION->rewrite_net_packet->tcpbuff_bak_len[idx];
																__ORA_SESSION->tcpbuff_bak[idx] = (u_char*)ZMalloc(__ORA_SESSION->tcpbuff_bak_len[idx]);
																memcpy(__ORA_SESSION->tcpbuff_bak[idx], __ORA_SESSION->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak_len[idx]);
															}
														}
													}

												ret = Dbfw_PrepareSqlSpy_ForFieldDetect(__ORA_SESSION);
												if(ret > 0)
												{
															/* 使用新生成的字段列表探测语句生成通讯包,准备发送到服务器 */
													ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,	                                                        
													(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,	                                                        
													((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,0);														
													if(tns_pack_data!=NULL)
													{
														ZFree(tns_pack_data);
														tns_pack_data = NULL;
													}

													OraNet_DumpSql("goto client2server\n");
													goto client2server;
											}
#endif
										}
										else
										{
												 /* 没有*需要处理，直接使用脱敏后的SQL语句生成通讯包 */
											int ret_tmp = 0;
											ret_tmp = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
	                                                (char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text,
	                                                __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size, 0);
											OraNet_DumpSql("ret_tmp:%d\n",ret_tmp); 			
											if(ret_tmp>0)
											{
												__ORA_SESSION->sqlmodify_result = 0x01;
											}
											else
											{
												__ORA_SESSION->sqlmodify_result = 0x00;
											}
										}         
									}
								}
								else
								{
									/* 数据不正常，需要清理 */
            #ifdef HAVE_APPROVAL
									OraNet_DumpSql("__ORA_SESSION->filter_sesscommon.is_code_sql :%d\n",__ORA_SESSION->filter_sesscommon.is_code_sql );
									OraNet_DumpSql("rewrite_packet.packparse_result:%d\n",rewrite_packet.packparse_result);
									if((__ORA_SESSION->filter_sesscommon.is_code_sql == 1 && ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->un_write_sql_flag == 0 ) || (rewrite_packet.packparse_result == NPP_RESULT_BLOCKING_THROW && rewrite_packet.tnspack_num == 1))
		#else
                                        if(rewrite_packet.packparse_result == NPP_RESULT_BLOCKING_THROW && rewrite_packet.tnspack_num == 1)
            #endif
                                    {
										int ret_tmp = 0;
                #ifdef HAVE_APPROVAL
										if(__ORA_SESSION->filter_sesscommon.is_code_sql == 1)
										{
											if(__ORA_SESSION->filter_sesscommon.code_pass_flag == 1)
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'code pass' as codemessage");
											else
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'code no pass' as codemessage");
										}
										else
                #endif
										{
                                            if(__ORA_SESSION->filter_sesscommon.s_no_oem_switch == 1)
                                            {
                                                 __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Reject By DBSEC' as message");
                                            }
                                            else
                                            {
                                                __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Reject' as message");
                                            }
										}
										if((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text)
											ZFree(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text);
										__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text = (u_char*)ZMalloc(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
				 #ifdef HAVE_APPROVAL
                                        if(__ORA_SESSION->filter_sesscommon.is_code_sql == 1)
										{
											if(__ORA_SESSION->filter_sesscommon.code_pass_flag == 1)
												memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'code pass' as codemessage", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
											else
												memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'code no pass' as codemessage", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
										}
										else
                #endif
										{
                                            if(__ORA_SESSION->filter_sesscommon.s_no_oem_switch == 1)
                                            {
                                                memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Reject By DBSEC' as message", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
                                            }
                                            else
                                            {
                                                memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Reject' as message", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
                                            }
										}
										ret_tmp = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
												(char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text,
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size,0);
										OraNet_DumpSql("ret_tmp:%d\n",ret_tmp); 			
										if(ret_tmp>0)
										{
											__ORA_SESSION->sqlmodify_result = 0x01;
										}
										else
										{
											__ORA_SESSION->sqlmodify_result = 0x00;
										}
										rewrite_packet.packparse_result = 0;
										__ORA_SESSION->help_tamper_flag = 0;
									Dbfw_ResetRewriteInfoForRequestPack((void*)__ORA_SESSION);
                                    }
                                    else if((rewrite_packet.packparse_result == NPP_RESULT_SWITCHOFF && rewrite_packet.tnspack_num == 1)
                                            || (rewrite_packet.is_switchoff == 1 && rewrite_packet.tnspack_num == 1))
                                        {
                                            int ret_tmp = 0;
                                            if(__ORA_SESSION->filter_sesscommon.s_no_oem_switch == 1)
                                            {
                                                __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Denied By DBSEC' as message");
                                            }
                                            else
                                            {
                                                __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Denied' as message");
                                            }
                                            if((char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text)
                                                ZFree(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text);
                                            __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text = (u_char *) ZMalloc(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
                                            if(__ORA_SESSION->filter_sesscommon.s_no_oem_switch == 1)
                                                memcpy((char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Denied By DBSEC' as message", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
                                            else
                                                memcpy((char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Denied' as message", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
                                            ret_tmp = Dbfw_SqlModifyPacket(__ORA_SESSION, tns_pack_data
                                                                           , tns_package_size
                                                                           , (char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text
                                                                           , __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size
                                                                           , 0);
                                            OraNet_DumpSql("ret_tmp:%d\n", ret_tmp);
                                            if (ret_tmp > 0)
                                            {
                                                __ORA_SESSION->sqlmodify_result = 0x01;
                                            }
                                            else
                                            {
                                                __ORA_SESSION->sqlmodify_result = 0x00;
                                            }
                                            rewrite_packet.packparse_result = 0;
									Dbfw_ResetRewriteInfoForRequestPack((void*)__ORA_SESSION);
                                        }
								}
								__ORA_SESSION->sqlmodify_flag = 0;	  /* 恢复SQL改写标记为0 */
							}				
#endif
							if(rewrite_packet.rewriteinfo_for_request.pg_cursor_start == 0)
								rewrite_packet.rewriteinfo_for_request.more_sql_offset = rewrite_packet.rewriteinfo_for_request.more_sql_offset + tns_package_size;
							if(rewrite_packet.packparse_result>0)
							{
							    OraNet_DumpSql("[CHERRY:POSTGRES] rewrite_packet.is_switchoff=%d,rewrite_packet.packparse_result=%d\n",rewrite_packet.is_switchoff,rewrite_packet.packparse_result);
								#ifdef HAVE_APPROVAL
								OraNet_DumpSql("__ORA_SESSION->filter_sesscommon.is_code_sql :%d\n",__ORA_SESSION->filter_sesscommon.is_code_sql );
								#endif
									OraNet_DumpSql("rewrite_packet.packparse_result:%d\n",rewrite_packet.packparse_result);
#ifdef HAVE_APPROVAL
								if((__ORA_SESSION->filter_sesscommon.is_code_sql == 1  ) || (rewrite_packet.packparse_result == NPP_RESULT_BLOCKING_THROW && rewrite_packet.tnspack_num == 1))
#else
								if( (rewrite_packet.packparse_result == NPP_RESULT_BLOCKING_THROW && rewrite_packet.tnspack_num == 1))
#endif
									{
										int ret_tmp = 0;
	#ifdef HAVE_APPROVAL
										if(__ORA_SESSION->filter_sesscommon.is_code_sql == 1)
										{
											if(__ORA_SESSION->filter_sesscommon.code_pass_flag == 1)
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'code pass' as codemessage");
											else
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'code no pass' as codemessage");
										}
										else
	#endif
										{
											__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Reject By DBSEC' as message");
										}
										if((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text)
											ZFree(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text);
										__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text = (u_char*)ZMalloc(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
#ifdef HAVE_APPROVAL
										if(__ORA_SESSION->filter_sesscommon.is_code_sql == 1)
										{
											if(__ORA_SESSION->filter_sesscommon.code_pass_flag == 1)
												memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'code pass' as codemessage", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
											else
												memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'code no pass' as codemessage", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
										}
										else
#endif
										{
											memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Reject By DBSEC' as message", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
										}
										ret_tmp = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
												(char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text,
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size,0);
										OraNet_DumpSql("ret_tmp:%d\n",ret_tmp); 			
										if(ret_tmp>0)
										{
											__ORA_SESSION->sqlmodify_result = 0x01;
										}
										else
										{
											__ORA_SESSION->sqlmodify_result = 0x00;
										}
										rewrite_packet.packparse_result = 0;
										__ORA_SESSION->help_tamper_flag = 0;
									}
									Dbfw_ResetRewriteInfoForRequestPack((void*)__ORA_SESSION);
								/* 这里暂时先释放该数据，以避免目前的memleak错误，等逻辑实现完整后再调整 */
								if(tns_pack_data!=NULL)
								{
									ZFree(tns_pack_data);
									tns_pack_data = NULL;
								}
								rewrite_packet.packparse_result = 0;
								OraNet_DumpSql("goto client2server\n");
								goto client2server;
							}                   

							if(tns_pack_data!=NULL)
								ZFree(tns_pack_data);
						}						
#ifdef HAVE_SQL_MODIFY_ENGINE
                        /* 处理长SQL语句分包问题 */
                        else
                        {
                            /* 注意：PG的buffer_cursor一般都是从头开始的，所以不能带>0逻辑 */
                            if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor < ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage
                                )
                            {
                                /* 包还没有解析完 */
                                OraNet_DumpSql("ATTENTION have more pack data need parse : buffer_cursor=%d\n",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor);
                                rewrite_packet.packet_broken_flag = ORANET_PARSEFUNC_DATABREAK; /* 设置断链标记，使client->server在断链时不发包，保证异常包的正常逻辑 */
                            }
                        }
#endif
					}
					while(tns_package_size>0);

#endif
				}
				/* 2015-01-10 */
				else if (strcasecmp((char *)db_type,"kbase")==0)
				{
					  /* Kingbase数据库协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    rewrite_packet.packet_broken_flag = ORANET_PARSEFUNC_DATABREAK; /* 设置断链标记，使client->server在断链时不发包，保证异>
      常包的正常逻辑 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i], sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                //if(fail_tcp_count>10)
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
#ifdef HAVE_SQL_MODIFY_ENGINE
                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
						/* 清理包改写信息 */
						//memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
#endif
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef NEW_TAMPER_FORPROXY
					/* 准备用于?鄹牡牡刂? */
					__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef HAVE_SQL_MODIFY_ENGINE
                    /* 准备SQL改写和MASK的数据 */
                    __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
#endif
#ifdef ENABLE_KINGBASE
					OraNet_DumpSql("==pgsql req:len:%d\n",len);
					tcp_buffer_size = PG_AddTcpPackageToBuffer(buff,len,tcp_info,USER2PG);
					if(tcp_buffer_size == 0) 
					{	  
						rewrite_packet.packet_broken_flag = 0;
						goto client2server;
					}	
					
					do{
						tns_pack_data = PG_Package_PreProcess(tcp_info,USER2PG,(u_int*)&tns_package_size);
						
						if(tns_package_size>0)
						{
							rewrite_packet.packet_broken_flag = 0;
							parse_ret = PG_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2PG,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2ORA);
							//parse_ret = 1;
							if(rewrite_packet.packparse_result>0)
							{
								OraNet_DumpSql("[CHERRY:Kingbase] rewrite_packet.is_switchoff=%d,rewrite_packet.packparse_result=%d\n",rewrite_packet.is_switchoff,rewrite_packet.packparse_result);
								/* 这里暂时先释放该数据，以避免目前的memleak错误，等逻辑实现完整后再调整 */
								{
									if(tns_pack_data!=NULL)
									{
										ZFree(tns_pack_data);
										tns_pack_data = NULL;
									}
								}
								OraNet_DumpSql("goto client2server\n");
								goto client2server;
							}               
							if(tns_pack_data!=NULL)
								ZFree(tns_pack_data);
						}						
					}
					while(tns_package_size>0);
#endif
				}
                /* 2015-08-06 */
                else if(strcasecmp((char *)db_type,"oscar")==0)
                {
                    /* OSCAR数据库协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i] , sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i], sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
#ifdef HAVE_SQL_MODIFY_ENGINE
                        /* 清理包改写信息 */
                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
						/* 清理包改写信息 */
						//memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
#endif
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef HAVE_SQL_MODIFY_ENGINE
                    /* 准备SQL改写和MASK的数据 */
                    __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
#endif
#ifdef ENABLE_OSCAR
                    tcp_buffer_size = OSCAR_AddTcpPackageToBuffer(buff,len,tcp_info,USER2OSCAR);
                    do{
                        tns_pack_data = OSCAR_Package_PreProcess(tcp_info,USER2OSCAR,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
                            parse_ret = OSCAR_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2OSCAR,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2ORA);
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }
				/* 2015-08-12 */
                else if(strcasecmp((char *)db_type,"ifx")==0)
                {
                    /* OSCAR数据库协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend( ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i] , sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
#ifdef HAVE_SQL_MODIFY_ENGINE
                        /* 清理包改写信息 */
                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
#endif
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef NEW_TAMPER_FORPROXY
					/* 准备用于篡改的地址 */
					__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef HAVE_SQL_MODIFY_ENGINE
                    /* 准备SQL改写和MASK的数据 */
                    __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
#endif
#ifdef ENABLE_IIF
                    tcp_buffer_size = IFX_AddTcpPackageToBuffer(buff,len,tcp_info,USER2IIF);
                    do{
                        tns_pack_data = IFX_Package_PreProcess(tcp_info,USER2IIF,(u_int*)&tns_package_size);
#ifdef HAVE_SQL_MODIFY_ENGINE
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor == 0
                        	&& ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage >0)
                        {
                        	/* informix 的断包判断是在preprocess 函数，所以要设置断包，否则会转发 */
                        	rewrite_packet.packet_broken_flag = -1;
                        }
                        else
                        {
                        	rewrite_packet.packet_broken_flag = 0;
                        }
#endif
                        if(tns_package_size>0)
                        {
                            parse_ret = IFX_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2IIF,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2IIF);
							if(__ORA_SESSION->stmt_for_sqlmodify)
							{
							OraNet_DumpSql("((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag:%d\n",((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag);
							OraNet_DumpSql("__ORA_SESSION->sqlmodify_flag:%d\n",__ORA_SESSION->sqlmodify_flag);
							OraNet_DumpSql("__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext:%d\n",__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext);
							OraNet_DumpSql("((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule :%d\n",((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule );
							OraNet_DumpSql("((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star:%d\n",((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star);
							}
#ifdef HAVE_SQL_MODIFY_ENGINE
							/* 先检查end_cursor_for_sqltext是否已经获取到正确的值，如果是0则表示没有解析完整 */
							if(__ORA_SESSION->stmt_for_sqlmodify && ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag == 1)
							{
								/* 说明已经进行了规则校验，但是回存在一个问题，参数化语句暂未处理 */
								if(__ORA_SESSION->sqlmodify_flag==1 && __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext>0 &&
								((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule == 1)

								{
									if(__ORA_SESSION->mask_result>0)
									{
											 /* 生成脱敏语句成功,脱敏后的SQL语句保存在rewrite_net_packet->rewriteinfo_for_request.new_sql_text */
											 /* 判断是否脱敏后的语句中存在*,如果存在则需要通过SPY SQL进行字段列表探测 */
										if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star == 1)
										{
#ifdef HAVE_SQL_SPY
											/* 生成字段列表探测语句和相应的stmt_for_spy，并且和当前的stmt进行交换 */


												ret = Dbfw_PrepareSqlSpy_ForFieldDetect(__ORA_SESSION);
												if(ret > 0)
												{
															/* 使用新生成的字段列表探测语句生成通讯包,准备发送到服务器 */
													ret = Dbfw_SqlModifyPacket(__ORA_SESSION,(void*)tns_pack_data,(int)tns_package_size,															
													(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,															
													((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,0);	

													if(tns_pack_data!=NULL)
													{
														ZFree(tns_pack_data);
														tns_pack_data = NULL;
													}

													OraNet_DumpSql("goto client2server\n");
													goto client2server;
											}
#endif
										}
										else
										{
												 /* 没有*需要处理，直接使用脱敏后的SQL语句生成通讯?? */
											int ret_tmp = 0;
											ret_tmp = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
													(char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text,
													__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size,0);
											OraNet_DumpSql("ret_tmp:%d\n",ret_tmp); 			
											if(ret_tmp>0)
											{
												__ORA_SESSION->sqlmodify_result = 0x01;
											}
											else
											{
												__ORA_SESSION->sqlmodify_result = 0x00;
											}
										}		  
									}
								}
								else
								{
									/* 数据不正常，需要清理 */
#ifdef HAVE_APPROVAL
									if(__ORA_SESSION->filter_sesscommon.is_code_sql == 1 || (rewrite_packet.packparse_result == NPP_RESULT_BLOCKING_THROW && rewrite_packet.tnspack_num == 1))
#else
									if((rewrite_packet.packparse_result == NPP_RESULT_BLOCKING_THROW && rewrite_packet.tnspack_num == 1))
#endif
									{
										int ret_tmp = 0;
#ifdef HAVE_APPROVAL
										if(__ORA_SESSION->filter_sesscommon.is_code_sql == 1)
										{
											if(__ORA_SESSION->filter_sesscommon.code_pass_flag == 1)
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'code pass' as codemessage from sysmaster:sysshmvals");
											else
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'code no pass' as codemessage from sysmaster:sysshmvals");
										}
										else
#endif
										{
											if(__ORA_SESSION->filter_sesscommon.s_no_oem_switch == 1)
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Reject By DBSEC' as message from sysmaster:sysshmvals");
											else
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Reject' as message from sysmaster:sysshmvals");
										}
										if((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text)
											ZFree(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text);
										__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text = (u_char*)ZMalloc(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
#ifdef HAVE_APPROVAL
										if(__ORA_SESSION->filter_sesscommon.is_code_sql == 1)
										{
											if(__ORA_SESSION->filter_sesscommon.code_pass_flag == 1)
												memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'code pass' as codemessage from sysmaster:sysshmvals", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
											else
												memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'code no pass' as codemessage from sysmaster:sysshmvals", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
										}
										else
#endif
										{
											if(__ORA_SESSION->filter_sesscommon.s_no_oem_switch == 1)
												memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Reject By DBSEC' as message from sysmaster:sysshmvals", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
											else
												memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Reject' as message from sysmaster:sysshmvals", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
										}
										ret_tmp = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
												(char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text,
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size,0);
										OraNet_DumpSql("ret_tmp:%d\n",ret_tmp); 			
										if(ret_tmp>0)
										{
											__ORA_SESSION->sqlmodify_result = 0x01;
										}
										else
										{
											__ORA_SESSION->sqlmodify_result = 0x00;
										}
										rewrite_packet.packparse_result = 0;
									}
									else if((rewrite_packet.packparse_result == NPP_RESULT_SWITCHOFF && rewrite_packet.tnspack_num == 1)
											|| (rewrite_packet.is_switchoff == 1 && rewrite_packet.tnspack_num == 1))
									{
										int ret_tmp = 0;

										if(__ORA_SESSION->filter_sesscommon.s_no_oem_switch == 1)
											__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Denied By DBSEC' as message from sysmaster:sysshmvals");
										else
											__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Denied' as message from sysmaster:sysshmvals");

										if((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text)
											ZFree(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text);
										__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text = (u_char*)ZMalloc(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);

										if(__ORA_SESSION->filter_sesscommon.s_no_oem_switch == 1)
											memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Denied By DBSEC' as message from sysmaster:sysshmvals", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
										else
											memcpy((char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Denied' as message from sysmaster:sysshmvals", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);

										ret_tmp = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
												(char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text,
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size,0);
										OraNet_DumpSql("ret_tmp:%d\n",ret_tmp); 			
										if(ret_tmp>0)
										{
											__ORA_SESSION->sqlmodify_result = 0x01;
										}
										else
										{
											__ORA_SESSION->sqlmodify_result = 0x00;
										}
										rewrite_packet.packparse_result = 0;
									}
									Dbfw_ResetRewriteInfoForRequestPack((void*)__ORA_SESSION);
								}
								__ORA_SESSION->sqlmodify_flag = 0;	  /* 恢复SQL改写标记为0 */
							}				
#endif
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }
				/* 2015-08-31 */
                else if(strcasecmp((char *)db_type,"cachdb")==0)
                {
                    /* OSCAR数据库协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i] , sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
#ifdef HAVE_SQL_MODIFY_ENGINE
                        /* 清理包改写信息 */
                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
						/* 清理包改写信息 */
						//memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
#endif
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
					rewrite_packet.packet_broken_flag = 0;
                    
                    send_packet_flag = 1;
                    
#ifdef NEW_TAMPER_FORPROXY
					/* 准备用于篡改的地址 */
					__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef HAVE_SQL_MODIFY_ENGINE
                    /* 准备SQL改写和MASK的数据 */
                    __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
#endif
#ifdef ENABLE_CACHEDB
                    tcp_buffer_size = CacheDB_AddTcpPackageToBuffer(buff,len,tcp_info,USER2CACHEDB);
                    do{
                        tns_pack_data = CacheDB_Package_PreProcess(tcp_info,USER2CACHEDB,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
                            parse_ret = CacheDB_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2CACHEDB,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2ORA);
							if(__ORA_SESSION->stmt_for_sqlmodify)
							{
							OraNet_DumpSql("((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag:%d\n",((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag);
							OraNet_DumpSql("__ORA_SESSION->sqlmodify_flag:%d\n",__ORA_SESSION->sqlmodify_flag);
							OraNet_DumpSql("__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext:%d\n",__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext);
							OraNet_DumpSql("((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule :%d\n",((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule );
							OraNet_DumpSql("((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star:%d\n",((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star);
							}
							/* 脱敏 */
							ret = Dbsec_MakeSpySqlAndModifyPacket(__ORA_SESSION,tns_pack_data,tns_package_size);
							OraNet_DumpSql("ret:%d\n",ret);
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
						else
						{
#ifdef HAVE_SQL_MODIFY_ENGINE 
							if(__ORA_SESSION->len_1169 == 99)
								rewrite_packet.packet_broken_flag = -1;
#endif
						}
						
                    }
                    while(tns_package_size>0);
#endif
                }
                else if(strcasecmp((char *)db_type,"teradata")==0)
                {
                    /* OSCAR数据库协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i], sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef NEW_TAMPER_FORPROXY
					/* 准备用于篡改的地址 */
					__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef ENABLE_TERADATA
                    tcp_buffer_size = Tera_AddTcpPackageToBuffer(buff,len,tcp_info,USER2TERA);
                    do{
                        tns_pack_data = Tera_Package_PreProcess(tcp_info,USER2TERA,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
                            parse_ret = Tera_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2TERA,&rewrite_packet,NULL);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2TERA);
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }
				else if(strcasecmp((char *)db_type,"hive")==0)
				{
                    /* OSCAR数据库协议解析 */
					rewrite_packet.packet_broken_flag = ORANET_PARSEFUNC_DATABREAK;
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i] , sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef NEW_TAMPER_FORPROXY
					/* 准备用于篡改的地址 */
					__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef ENABLE_HIVE
					__ORA_SESSION->hive_get_username = 0;
                    tcp_buffer_size = Hive_AddTcpPackageToBuffer(buff,len,tcp_info,USER2HIVE);
                    do{
                        tns_pack_data = Hive_Package_PreProcess(tcp_info,USER2HIVE,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
							OraNet_DumpSql("tns_package_size:%d\n",tns_package_size);
							rewrite_packet.packet_broken_flag = 0;
                            parse_ret = Hive_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2HIVE,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2HIVE);
#ifdef HAVE_SQL_MODIFY_ENGINE
								if(__ORA_SESSION->stmt_for_sqlmodify) 
									OraNet_DumpSql("sqlprocess_flag:%d,sqlmodify_flag:%d,end_cursor_for_sqltext:%d,hit_mask_rule:%d,__ORA_SESSION->mask_result:%d\n",((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag,__ORA_SESSION->sqlmodify_flag,__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext,((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule,__ORA_SESSION->mask_result);
                                if(__ORA_SESSION->stmt_for_sqlmodify 
									&& ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag == 1) /* ���еĹ����������߼� */
                                {
                                	if(__ORA_SESSION->sqlmodify_flag==1  &&
									((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule == 1)
									{
	                                    if(__ORA_SESSION->mask_result>0)
	                                    {
	                                     	if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star == 1)	                                        
	                                        {
	                                            
#ifdef HAVE_SQL_SPY
	{
														u_int idx = 0;
														for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx ++)
														{
															__ORA_SESSION->tcpbuff_bak_len[idx] = 0;
															ZFree(__ORA_SESSION->tcpbuff_bak[idx]);
														}
														__ORA_SESSION->tnspack_num = 0;
														{
															memset(&__ORA_SESSION->rewriteinfo_for_request, 0x00, sizeof(Npp_RewriteInfoForRequestPack));
															memcpy(&__ORA_SESSION->rewriteinfo_for_request, &__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
															__ORA_SESSION->rewriteinfo_for_request.use_get_table_desc = 1;
															__ORA_SESSION->tnspack_num = __ORA_SESSION->rewrite_net_packet->tnspack_num;
															for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx ++)
															{
																__ORA_SESSION->tcpbuff_bak_len[idx] = __ORA_SESSION->rewrite_net_packet->tcpbuff_bak_len[idx];
																__ORA_SESSION->tcpbuff_bak[idx] = (u_char*)ZMalloc(__ORA_SESSION->tcpbuff_bak_len[idx]);
																memcpy(__ORA_SESSION->tcpbuff_bak[idx], __ORA_SESSION->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak_len[idx]);
															}
														}
													}
												if(1==1)
												{
													Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
														memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
														memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
														__ORA_SESSION->table_index = 0;
														__ORA_SESSION->nonneed_table = 0;
														Dbfw_GetTableAndAlisa(__ORA_SESSION);
														//GetTableFromSqlTree((void*)__ORA_SESSION);
														Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
														Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
														ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,1);
														if(ret>0)
														{
															if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
															{
																memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
																((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
																int idx = 0;
																for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
																{
																	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
																	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
																	memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
																}
															}
															__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
															ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
																(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
																((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
															attention_cnt = 0;
														}
														if(__ORA_SESSION->table_index == 0)
														{
															__ORA_SESSION->spy_field_result = 3;
														}
														else
														{
															__ORA_SESSION->spy_field_result = 2;
														}
														csc_tmp = 1;
												}
												else
												{
                                                ret = Dbfw_PrepareSqlSpy_ForFieldDetect(__ORA_SESSION);
                                                if(ret>0)
                                                {
                                                    {
														u_int idx = 0;
														for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx ++)
														{
															__ORA_SESSION->tcpbuff_bak_len[idx] = 0;
															ZFree(__ORA_SESSION->tcpbuff_bak[idx]);
														}
														__ORA_SESSION->tnspack_num = 0;
														{
															memset(&__ORA_SESSION->rewriteinfo_for_request, 0x00, sizeof(Npp_RewriteInfoForRequestPack));
															memcpy(&__ORA_SESSION->rewriteinfo_for_request, &__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
															__ORA_SESSION->rewriteinfo_for_request.use_get_table_desc = 1;
															__ORA_SESSION->tnspack_num = __ORA_SESSION->rewrite_net_packet->tnspack_num;
															for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx ++)
															{
																__ORA_SESSION->tcpbuff_bak_len[idx] = __ORA_SESSION->rewrite_net_packet->tcpbuff_bak_len[idx];
																__ORA_SESSION->tcpbuff_bak[idx] = (u_char*)ZMalloc(__ORA_SESSION->tcpbuff_bak_len[idx]);
																memcpy(__ORA_SESSION->tcpbuff_bak[idx], __ORA_SESSION->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak_len[idx]);
															}
														}
														csc_tmp = 1;
														
													}
                                                    ret = Dbfw_SqlModifyPacket(__ORA_SESSION,(void*)tns_pack_data,(int)tns_package_size,
                                                        (char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
                                                        ((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length, 0);
                                                }   
												}
												 
												for(j=0;j<rewrite_packet.tnspack_num;j++) 
												{
													ZFree(rewrite_packet.tcpbuff_bak[j]);
													rewrite_packet.tcpbuff_bak_len[j] = 0;
												}
												rewrite_packet.tnspack_num = 0;                        
#endif
	                                        }
	                                        else
	                                        {
	                                            ret = Dbfw_SqlModifyPacket(__ORA_SESSION,(void*)tns_pack_data,(int)tns_package_size,
	                                                (char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text,
	                                                __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size, 0);

												if(ret > 0  && __ORA_SESSION->rewrite_net_packet->packet_num > 0)
												{
													for(j = 0; j < rewrite_packet.tnspack_num; j++) 
													{
														ZFree(rewrite_packet.tcpbuff_bak[j]);
														rewrite_packet.tcpbuff_bak_len[j] = 0;
													}
													rewrite_packet.tnspack_num = 0; 
												}
	                                        }
	                                    }
                                	}
									else
									{
#ifdef HAVE_APPROVAL
                                        if (__ORA_SESSION->filter_sesscommon.is_code_sql == 1
                                            || (rewrite_packet.packparse_result == NPP_RESULT_BLOCKING_THROW && rewrite_packet.tnspack_num == 1))
#else
                                        if((rewrite_packet.packparse_result == NPP_RESULT_BLOCKING_THROW && rewrite_packet.tnspack_num == 1))
#endif
                                        {
                                            int ret_tmp = 0;
#ifdef HAVE_APPROVAL
                                            if (__ORA_SESSION->filter_sesscommon.is_code_sql == 1)
                                            {
                                                if (__ORA_SESSION->filter_sesscommon.code_pass_flag == 1)
                                                {
                                                    __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'code pass' as codemessage");
                                                }
                                                else
                                                {
                                                    __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'code no pass' as codemessage");
                                                }
                                            }
                                            else
#endif
                                            {
												if(__ORA_SESSION->filter_sesscommon.s_no_oem_switch == 1)
												{
                                                	__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Reject By DBSEC' as message");
												}
												else
												{
													__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Reject' as message");
												}
											}
                                            if((char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text)
                                            	ZFree(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text);
                                            __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text = (u_char *) ZMalloc(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
#ifdef HAVE_APPROVAL
                                            if (__ORA_SESSION->filter_sesscommon.is_code_sql == 1)
                                            {
                                                if (__ORA_SESSION->filter_sesscommon.code_pass_flag == 1)
                                                {
                                                    memcpy((char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'code pass' as codemessage", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
                                                }
                                                else
                                                {
                                                    memcpy((char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'code no pass' as codemessage", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
                                                }
                                            }
                                            else
#endif
                                            {
												if(__ORA_SESSION->filter_sesscommon.s_no_oem_switch == 1)
												{
                                                	memcpy((char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Reject By DBSEC' as message", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
												}
												else
												{
													memcpy((char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Reject' as message", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
												}
											}
                                            ret_tmp = Dbfw_SqlModifyPacket(__ORA_SESSION, tns_pack_data
                                                                           , tns_package_size
                                                                           , (char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text
                                                                           , __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size
                                                                           , 0);
                                            OraNet_DumpSql("ret_tmp:%d\n", ret_tmp);
                                            if (ret_tmp > 0)
                                            {
                                                __ORA_SESSION->sqlmodify_result = 0x01;
                                            }
                                            else
                                            {
                                                __ORA_SESSION->sqlmodify_result = 0x00;
                                            }
                                            rewrite_packet.packparse_result = 0;
                                        }
										else if((rewrite_packet.packparse_result == NPP_RESULT_SWITCHOFF && rewrite_packet.tnspack_num == 1)
											|| (rewrite_packet.is_switchoff == 1 && rewrite_packet.tnspack_num == 1))
										{
											int ret_tmp = 0;
											if(__ORA_SESSION->filter_sesscommon.s_no_oem_switch == 1)
											{
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Denied By DBSEC' as message");
											}
											else
											{
												__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size = strlen("select 'Denied' as message");
											}
                                            if((char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text)
                                            	ZFree(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text);
                                            __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text = (u_char *) ZMalloc(__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
											if(__ORA_SESSION->filter_sesscommon.s_no_oem_switch == 1)
												memcpy((char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Denied By DBSEC' as message", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
											else
												memcpy((char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text, "select 'Denied' as message", __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size);
											ret_tmp = Dbfw_SqlModifyPacket(__ORA_SESSION, tns_pack_data
                                                                           , tns_package_size
                                                                           , (char *) __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text
                                                                           , __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size
                                                                           , 0);
                                            OraNet_DumpSql("ret_tmp:%d\n", ret_tmp);
                                            if (ret_tmp > 0)
                                            {
                                                __ORA_SESSION->sqlmodify_result = 0x01;
                                            }
                                            else
                                            {
                                                __ORA_SESSION->sqlmodify_result = 0x00;
                                            }
                                            rewrite_packet.packparse_result = 0;
										}
                                        Dbfw_ResetRewriteInfoForRequestPack((void *) __ORA_SESSION);
                                    }
                                    __ORA_SESSION->sqlmodify_flag = 0;      /* �ָ�SQL��д���Ϊ0 */
                                }
#endif
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
						else
						{
							if(__ORA_SESSION->hive_get_username == 1)
                            {
                                rewrite_packet.packet_broken_flag = 0;
                            }
							if(true == __ORA_SESSION->is_auth_pack)
                            {
                                rewrite_packet.packet_broken_flag = 0;
                            }
						}
                    }
                    while(tns_package_size>0);
#endif
                }
                else if(strcasecmp((char *)db_type,"mongodb")==0)
				{
                    /* OSCAR数据库协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i] , sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef NEW_TAMPER_FORPROXY
					/* 准备用于篡改的地址 */
					__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef ENABLE_MONGODB
                    tcp_buffer_size = MONGODB_AddTcpPackageToBuffer(buff,len,tcp_info,USER2ORA);
                    do{
                        tns_pack_data = MONGODB_Package_PreProcess(tcp_info,USER2ORA,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
                        	void* tmp = NULL;
                        	MongoDB_Parse_Result mg_parse_result;
                			Init_MGO_Parse_Result(&mg_parse_result);
                            parse_ret = MONGODB_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2ORA,&mg_parse_result,&rewrite_packet,&tmp);
							if(tmp)
								free(tmp);
							if(parse_ret && mg_parse_result.parse_result >= MGO_Success && mg_parse_result.is_request && mg_parse_result.is_fetch == 0)
			                {
			                    Dbfw_NoSQL_Dbfw_Stmt_List noSQL_dbfw_stmt_list;
			                    Init_Dbfw_NoSQL_Dbfw_Stmt_List(&noSQL_dbfw_stmt_list);

			                    Dbfw_NoSQL_Dbfw_Stmt_List* p_nosql_dbfw_stmt_list = NULL;
			                    if(mg_parse_result.stmt_list.stmt_list.size > 1)
			                    {
			                        p_nosql_dbfw_stmt_list = &noSQL_dbfw_stmt_list;
			                    }

			                    Dbfw_NoSQL_Stmt *mgdb_stmt = mg_parse_result.stmt_list.stmt_list.head;
			                    while (mgdb_stmt != NULL)
			                    {

			                        parse_ret = MONGODB_STMT_session_proc(&mg_parse_result,mgdb_stmt,p_nosql_dbfw_stmt_list,tcp_info);
			                        if(parse_ret < 0){ continue;}

			                        //sleep(20);
			                        parse_ret = NPP_SqlProcess(&rewrite_packet, __ORA_SESSION, USER2ORA);
#ifdef HAVE_CHERRY
    									/* informix目前只支持阻断，并且无法抛出异常 */
    									if(rewrite_packet.is_switchoff==1 ||
    									   rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
    									   rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
    									   rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH
    									  )
    									{
    										/* 
    											阻断或拦截
    											MSSQL目前只支持阻断
    										*/
    										//Dbfw_Switchoff_Immediately_ForHandleNpc();
    										//mgdb_stmt = mgdb_stmt->next;
    										//continue;
    										break;
    									}
    									else
    									{
    										/* 放行 */
    										OraNet_DumpSql("step[20.4] NPP_HandleDB2Package_ForHandleNpc result is pass\n");
    									}
#endif  /* HAVE_CHERRY */


			                        mgdb_stmt = mgdb_stmt->next;
			                    }//for each stmt

			                    if(p_nosql_dbfw_stmt_list)
			                    {
			                        OraNet8_SqlStmtData *dbfw_sql_stmt = (OraNet8_SqlStmtData*)p_nosql_dbfw_stmt_list->tail->stmt_ptr;
			                        if(dbfw_sql_stmt)
			                        {
			                            Init_Dbfw_NoSQL_Dbfw_Stmt_List(&dbfw_sql_stmt->nosql_dbfw_stmt_list);
			                            Dbfw_Stmt_Ptr_Item * stmt_ptr_item = p_nosql_dbfw_stmt_list->head;
			                            while (stmt_ptr_item)
			                            {
			                                Dbfw_Stmt_Ptr_Item * new_stmt_ptr_item = Append_Dbfw_Stmt_Ptr(&dbfw_sql_stmt->nosql_dbfw_stmt_list);
			                                new_stmt_ptr_item->stmt_ptr = stmt_ptr_item->stmt_ptr;

			                                stmt_ptr_item = stmt_ptr_item->next;
			                            }
			                        }
			                    }
			                    Release_Dbfw_NoSQL_Dbfw_Stmt_List(&noSQL_dbfw_stmt_list);//release nosql stmt list

			                }//if parse ret && is request
			                else if(mg_parse_result.is_request && mg_parse_result.is_fetch == 0)
			                {
			                    //HBASE_STMT_session_proc(&hb_parse_result,rt_com->tcp_info,0);
			                }

			                //clear result
			                Release_MGO_Parse_Result(&mg_parse_result);
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }
				else if(strcasecmp((char *)db_type,"impala")==0)
				{
                    /* IMPALA数据库协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i] , sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend( ssl_sd[i], sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef NEW_TAMPER_FORPROXY
					/* 准备用于篡改的地址 */
					__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef ENABLE_IMPALA
                    tcp_buffer_size = Impala_AddTcpPackageToBuffer(buff,len,tcp_info,USER2IMPALA);
                    do{
                        tns_pack_data = Impala_Package_PreProcess(tcp_info,USER2IMPALA,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
                            parse_ret = Impala_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2IMPALA,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2IMPALA);
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }
                else if(strcasecmp((char *)db_type,"hana")==0)
                {
                    /* OSCAR数据库协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
					//rewrite_packet.packet_broken_flag = ORANET_PARSEFUNC_DATABREAK;
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i] , sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend( ssl_sd[i], sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef NEW_TAMPER_FORPROXY
					/* 准备用于篡改的地址 */
					__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef ENABLE_HANA
                    tcp_buffer_size = Hana_AddTcpPackageToBuffer(buff,len,tcp_info,USER2HANA);
                    do{
                        tns_pack_data = Hana_Package_PreProcess(tcp_info,USER2HANA,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
                            parse_ret = Hana_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2HANA,&rewrite_packet,NULL);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2HANA);
							Dbsec_MakeSpySqlAndModifyPacket(__ORA_SESSION,tns_pack_data,tns_package_size);
							OraNet_DumpSql("__ORA_SESSION->mask_info.spy_mode:%d\n",__ORA_SESSION->mask_info.spy_mode);
							OraNet_DumpSql("rewrite_packet.packparse_result:%d\n",rewrite_packet.packparse_result);
							OraNet_DumpSql("rewrite_packet.tnspack_num:%d\n",rewrite_packet.tnspack_num);
									/* ���ݲ���������Ҫ���� */
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }
                else if(strcasecmp((char *)db_type,"gausst")==0)
                {
                    /* OSCAR数据库协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /*
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
                        if(ha)
                        {
                            nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
                        }
                        for(i = 0; i < socks; i++)
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd ? ssl_sd[i] : NULL, sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0)
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd ? ssl_sd[i] : NULL, sd[i], buff, len);
                            if(select_ret < 0)
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
                        if(ha)
                        {
                            nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
                        }
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }

                    send_packet_flag = 1;

#ifdef NEW_TAMPER_FORPROXY
                    /* 准备用于篡改的地址 */
					__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef ENABLE_GAUSSDB_T
                    tcp_buffer_size = GaussdbT_AddTcpPackageToBuffer(buff,len,tcp_info,USER2GAUSSDB);
                    do{
                        tns_pack_data = GaussdbT_Package_PreProcess(tcp_info,USER2GAUSSDB,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
                            parse_ret = GaussdbT_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2GAUSSDB,&rewrite_packet,NULL);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2GAUSSDB);
#ifdef HAVE_SQL_MODIFY_ENGINE
							/* 先检查end_cursor_for_sqltext是否已经获取到正确的值，如果是0则表示没有解析完整 */
							if(__ORA_SESSION->stmt_for_sqlmodify)
							{
								OraNet_DumpSql("__ORA_SESSION->sqlmodify_flag:%d,__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext:%d\n",__ORA_SESSION->sqlmodify_flag,__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext);
								OraNet_DumpSql("(OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule:%d,__ORA_SESSION->mask_result:%d\n",((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule,__ORA_SESSION->mask_result);
								OraNet_DumpSql(" ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag :%d\n", ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag );
							}
							if(__ORA_SESSION->stmt_for_sqlmodify && ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->sqlprocess_flag == 1)
							{
								/* 说明已经进行了规则校验，但是回存在一个问题，参数化语句暂未处理 */
								if(__ORA_SESSION->sqlmodify_flag==1 && __ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.end_cursor_for_sqltext>0 &&
								((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.hit_mask_rule == 1)

								{
									if(__ORA_SESSION->mask_result>0)
									{
											 /* 生成脱敏语句成功,脱敏后的SQL语句保存在rewrite_net_packet->rewriteinfo_for_request.new_sql_text */
											 /* 判断是否脱敏后的语句中存在*,如果存在则需要通过SPY SQL进行字段列表探测 */
										if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_sqlmodify))->filter_sqlcommon.have_star == 1)
										{
#ifdef HAVE_SQL_SPY
											/* 生成字段列表探测语句和相应的stmt_for_spy，并且和当前的stmt进行交换 */
											ret = Dbfw_PrepareSqlSpy_ForFieldDetect(__ORA_SESSION);
											if(ret > 0)
											{
														 /* 使用新生成的字段列表探测语句生成通讯包,准备发送到服务器 */
												ret = Dbfw_SqlModifyPacket(__ORA_SESSION,(void*)tns_pack_data,(int)tns_package_size,															
												(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,															
												((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,0);	

												if(tns_pack_data!=NULL)
												{
													ZFree(tns_pack_data);
													tns_pack_data = NULL;
												}

												OraNet_DumpSql("goto client2server\n");
												goto client2server;
											}
#endif
										}
										else
										{
												 /* 没有*需要处理，直接使用脱敏后的SQL语句生成通讯?? */
											int ret_tmp = 0;
											ret_tmp = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
													(char*)__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_text,
													__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.new_sql_size,0);
											OraNet_DumpSql("ret_tmp:%d\n",ret_tmp); 			
											if(ret_tmp>0)
											{
												__ORA_SESSION->sqlmodify_result = 0x01;
											}
											else
											{
												__ORA_SESSION->sqlmodify_result = 0x00;
											}
										}		  
									}
								}
								else
								{
									/* 数据不正常，需要清理 */
									Dbfw_ResetRewriteInfoForRequestPack((void*)__ORA_SESSION);
								}
								__ORA_SESSION->sqlmodify_flag = 0;	  /* 恢复SQL改写标记为0 */
							}				
#endif
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }
				else if(strcasecmp((char *)db_type,"redis")==0)
                {
                    /* OSCAR数据库协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /* 
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        for(i = 0; i < socks; i++) 
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0) 
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                            
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd[i], sd[i], buff, len);
                            if(select_ret < 0) 
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                    
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }
                    
                    send_packet_flag = 1;
                    
#ifdef NEW_TAMPER_FORPROXY
					/* 准备用于篡改的地址 */
					__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef ENABLE_REDIS
                    tcp_buffer_size = Redis_AddTcpPackageToBuffer(buff,len,tcp_info,USER2REDIS);
                    do{
                        tns_pack_data = Redis_Package_PreProcess(tcp_info,USER2REDIS,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
                            parse_ret = Redis_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2REDIS,&rewrite_packet);
							
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,USER2REDIS);
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }
                else if(strcasecmp((char *)db_type,"zk")==0)
                {
                    /* OSCAR数据库协议解析 */
                    /* 2014-06-11 修复请求通讯包个数太多造成的异常 */
                    if(rewrite_packet.tnspack_num>=DBFW_MAX_TNSPACK_FORSQLRW || rewrite_packet.tnspack_isfull==0x01/* 通讯包已经满了 */)
                    {
                        /*
                            备份包已经满了，不再进行备份，直接放行
                            1:将原来缓存的包放行,并清理缓冲区包
                            2:设置通讯包已满标记
                            3:清理ora_session->buffer_tcppackage
                            4:直接跳转到server2client
                        */
                        printf("ATTENTION : rewrite_packet.tnspack_num=%d\n",rewrite_packet.tnspack_num);
                        rewrite_packet.packet_broken_flag = 0;
                        if(ha)
                        {
                            nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
                        }
                        for(i = 0; i < socks; i++)
                        {
                            if(multi_skip && multi_skip[i]) continue;
                            for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                            {
                                fail_tcp_count = 0;
                                if(rewrite_packet.tcpbuff_bak_len[j]>0)
                                {
                                    /* 在Oracle for ODBC下，需要尝试多次 */
                                    select_ret = mysend(ssl_sd ? ssl_sd[i] : NULL, sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                                    if(select_ret < 0)
                                    {
                                        {
#ifdef WIN32
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                            Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif
                                            MULTI_SKIP_QUIT
                                        }
                                    }
                                }
                                ZFree(rewrite_packet.tcpbuff_bak[j]);
                                rewrite_packet.tcpbuff_bak_len[j] = 0;
                            }
                            /* 发送buff数据 */
                            select_ret = mysend(ssl_sd ? ssl_sd[i] : NULL, sd[i], buff, len);
                            if(select_ret < 0)
                            {
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif
                                    MULTI_SKIP_QUIT
                                }
                            }
                        }
                        if(ha)
                        {
                            nppproxy_unregister(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
                        }
                        rewrite_packet.tnspack_num = 0;
                        /* 设置标记 */
                        rewrite_packet.tnspack_isfull = 0x01;
                        /* 清理缓冲区 */
                        if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage>0)
                        {
                            ZFree(__ORA_SESSION->buffer_tcppackage);
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage = 0;
                            ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor = 0;
                        }
                        if(__ORA_SESSION->reserved_packsize>0)
                        {
                            ZFree(__ORA_SESSION->reserved_packdata);
                            __ORA_SESSION->reserved_packsize = 0;
                        }
                        goto server2client;
                    }
                    else
                    {
                        /* 有可用的备份包空间，开始备份到rewrite_packet.tcpbuff_bak数组中 */
                        rewrite_packet.tcpbuff_bak_len[rewrite_packet.tnspack_num] = len;
                        rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num] = (u_char*)ZMalloc(sizeof(u_char)*len);
                        z_memcpy(rewrite_packet.tcpbuff_bak[rewrite_packet.tnspack_num],buff,len, __FILE__, __LINE__, Smem_LogError_Format);
                        rewrite_packet.tnspack_num = rewrite_packet.tnspack_num+1;
                    }

                    send_packet_flag = 1;

#ifdef NEW_TAMPER_FORPROXY
                    /* 准备用于篡改的地址 */
					__ORA_SESSION->tamper_data_addr = (u_char*)(rewrite_packet.tcpbuff_bak[0]);
#endif
#ifdef ENABLE_ZK
                    tcp_buffer_size = ZooKeeper_AddTcpPackageToBuffer(buff,len,tcp_info,USER2ZK);
                    do{
                        tns_pack_data = ZooKeeper_Package_PreProcess(tcp_info,USER2ZK,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
                            parse_ret = ZooKeeper_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,USER2ZK,&rewrite_packet,NULL);
                            if(tns_pack_data!=NULL)
                            ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }else
                {
                    /* unknow */
                }
            }
            
client2server: 
			/* TODO 登陆风险校验*/
			ret = NPP_ConnectFilter(__ORA_SESSION,&rewrite_packet);
			
			/* 传入标记:登陆校验、
				传出:
			*/

			/* 处理tlog*/
			ret = NPP_HandleTlog(0,__ORA_SESSION);
			
            /* 
                新版本的拦截阻断处理方法(NEW_TAMPER_FORPROXY)
                由于是串联方式，所以包是完整的，直接篡改包头即可
                如果rewrite_packet.tnspack_isfull==0x01表是通讯包缓冲区已经满了，则不能进行篡改，这里可以不进行判断，原因是前面进行了goto server2client处理
            */
		  	OraNet_DumpSql("ewrite_packet.packparse_result:%d\n",rewrite_packet.packparse_result);
			OraNet_DumpSql("rewrite_packet.is_switchoff:%d\n",rewrite_packet.is_switchoff);
            if(rewrite_packet.is_switchoff==1 && __ORA_SESSION->help_tamper_flag==0/* 未篡改过 */)
            {
                /* 
                    阻断 
                    1:篡改当前包为拦截包，发送该包
                    2:等待04包返回，并篡改返回的报错信息,并发送
                    3:发送reset包
                */
#ifdef DEBUG_CHERRY
                printf("[C->S / ProxyMode]OraTnsPackageParse result is switchoff\n");
#endif                
                /* 由于是代理模式，理论上肯定应该有包头数据 */
                /* Oracle数据库阻断 */
                if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_ORACLE)
                {
                    /* Oracle数据库 */
                    tamper_dbtype = DBFW_TAMPER_TYPE_ORACLE;
                    tamper_mode = DBFW_TAMPER_TYPE_REQ_HEADER;
                    tamper_type = tamper_dbtype|tamper_mode;
                    ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,0);
                }
                /* MySQL/GBase数据库阻断 */
#ifdef ENABLE_MYSQL
                else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL||__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG)
                {
                    if(ret_compress_for_mysql==0/* 非压缩 */)
                    {
                        tamper_dbtype = DBFW_TAMPER_TYPE_MYSQL;
                        tamper_mode = DBFW_TAMPER_TYPE_PACKALL_FF;
                        tamper_type = tamper_dbtype|tamper_mode;
                        ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,4);
                    }
                    else
                    {
                        /* 压缩协议，直接断包 */
#ifdef DEBUG_CHERRY
                        printf("============switch off for mysql compress====================\n");
#endif
                        goto quit;
                    }
                }
#endif  /* ENABLE_MYSQL */
                /* MSSQL数据库阻断 */
#ifdef ENABLE_MSSQL
                else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MSSQL||__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SYBASE)
                {
                    tamper_dbtype = DBFW_TAMPER_TYPE_MSSQL;
                    tamper_mode = DBFW_TAMPER_TYPE_REQ8BYTE_FF;
                    tamper_type = tamper_dbtype|tamper_mode;
                    ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,sizeof(MSTDS_Packet_Header));
                }
#endif  /* ENABLE_MSSQL */
                /* 达梦数据库阻断 */
#ifdef ENABLE_DM
                else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_DM)
                {
                    tamper_dbtype = DBFW_TAMPER_TYPE_DM;
                    tamper_mode = DBFW_TAMPER_TYPE_DMHEADER;
                    tamper_type = tamper_dbtype|tamper_mode;
                    ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,sizeof(DM_PacketHeader));
                }
#endif  /* ENABLE_DM */
#ifdef  ENABLE_PGSQL
				else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_POSTGREE)
				{
					tamper_dbtype = DBFW_TAMPER_TYPE_POSTGRE;
					tamper_mode = DBFW_TAMPER_TYPE_REQ5BYTE_00;
					tamper_type = tamper_dbtype|tamper_mode;
					ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,sizeof(PG_Packet_CommonHead));
					__ORA_SESSION->wait_spy_result = 1;
				}
#endif  /* ENABLE_PGSQL */
#ifdef ENABLE_KINGBASE
				else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_KINGBASE)
				{
					tamper_dbtype = DBFW_TAMPER_TYPE_KINGBASE;
					tamper_mode = DBFW_TAMPER_TYPE_REQ5BYTE_00;
					tamper_type = tamper_dbtype|tamper_mode;
					ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,sizeof(PG_Packet_CommonHead));
				}
#endif /* ENABLE_KINGBASE */
				else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_CACHEDB)
				{
					tamper_dbtype = DBFW_TAMPER_TYPE_CACHEDB;
					tamper_mode = DBFW_TAMPER_TYPE_PACKALL_00;
					tamper_type = tamper_dbtype|tamper_mode;
					ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,12);
					rewrite_packet.packparse_result = 0;
				}
#ifdef ENABLE_GAUSSDB_T
                else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_GAUSSDBT )
                {
                    tamper_dbtype = DBFW_TAMPER_TYPE_GAUSSDB_T;
                    tamper_mode = DBFW_TAMPER_TYPE_REQ8BYTE_FF;
                    tamper_type = tamper_dbtype|tamper_mode;
                    ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,sizeof(GaussdbT_FixHeader));
                }
#endif  /* ENABLE_MSSQL */
				/* 阻断的时候没有设置成功，未改包，去掉该逻辑 */
				// else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_REDIS && __ORA_SESSION->sessCommon.rule_id == 0)
				// {
				// 	OraNet_DumpSql("__ORA_SESSION->redis_cmd_offset:%d\n",__ORA_SESSION->redis_cmd_offset);
				// 	rewrite_packet.tcpbuff_bak[0][__ORA_SESSION->redis_cmd_offset]=rewrite_packet.tcpbuff_bak[0][__ORA_SESSION->redis_cmd_offset] + '1';
				// 	rewrite_packet.packparse_result = 0;
				// 	//rewrite_packet.tcpbuff_bak_len[0]
				// 	ret = 1;
				// }
                else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_DB2 ||
                       /* __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_POSTGREE ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_KINGBASE ||*/
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_OSCAR ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_IFX ||
					    __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_GBASE8T	||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_CACHEDB ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_TERADATA ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_HIVE ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MONGODB ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_IMPALA ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_HRPC ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SENTRY ||
                        //__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_HANA ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_ES ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_WEBHTTP ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SYBASEIQ ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_GAUSSDBT ||
						__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_REDIS
                       )
                {
                    /* 
                        DB2/POSTGREE/KINGBASE/OSCAR/Informix/CACHEDB 
                        目前只支持直接阻断
                    */
                    goto quit;
                }
                else
                {
                    /* 其他的数据库类型，直接阻断 */
                    goto quit;
                }
                if(ret>0)
                {
                    /* 篡改成功 */
#ifdef DEBUG_CHERRY
                    printf("============tamper success====================\n");
#endif
                    __ORA_SESSION->help_tamper_flag=DBFW_TAMPER_SWITCHOFF;
                    __ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
                }
                else
                {
                    /* 篡改失败，直接断连接(当前是阻断状态) */
#ifdef DEBUG_CHERRY
                    printf("============switch off for tamper error====================\n");
#endif
                    goto quit;
                }
				if(__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_ORACLE)
					encryp_pkg(__ORA_SESSION, USER2ORA);
                /* 发送篡改后的通讯包 */
                //if(rewrite_packet.packet_broken_flag>=0 || rewrite_packet.packet_broken_flag<ORANET_PARSEFUNC_DATABREAK)
				if(ha)
				{
					nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
				}
                {
                    for(i = 0; i < socks; i++) 
                    {
                        if(multi_skip && multi_skip[i]) continue;
                        for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                        {
                            //printf("rewrite_packet.tcpbuff_bak_len[%d] = %d\n",j,rewrite_packet.tcpbuff_bak_len[j]);
                            {
                                select_ret = mysend(ssl_sd[i] , sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                            }
                            if(select_ret <= 0) 
                            {
#ifdef WIN32
                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                
                                MULTI_SKIP_QUIT
                            }
                            ZFree(rewrite_packet.tcpbuff_bak[j]);
                            rewrite_packet.tcpbuff_bak_len[j] = 0;
                        }
                        rewrite_packet.tnspack_num = 0;
#ifdef HAVE_SQL_MODIFY_ENGINE
                        /* 准备SQL改写和MASK的数据 */
                        __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
                        /* 清理包改写信息 */
                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
						/* 清理包改写信息 */
						//memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
#endif
                    }
                    
                    send_packet_flag = 0;
                    if (send_packet_direct == 1)
                    {
                    	send_packet_direct = 0;
                    }
                }
				if(ha)
				{
					nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
				}
                
            }
            else if(rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
                rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORFETCH ||
				__ORA_SESSION->respon_switchoff_moresql == NPP_RESULT_SWITCHOFF
                )
            {
                /* 拦截处理 */
#ifdef DEBUG_CHERRY
                printf("[C->S / ProxyMode]OraTnsPackageParse result is throw\n");
#endif 
                /* 由于是代理模式，理论上肯定应该有包头数据 */
                if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_ORACLE)
                {
                    tamper_dbtype = DBFW_TAMPER_TYPE_ORACLE;
                    tamper_mode = DBFW_TAMPER_TYPE_REQ_HEADER;
                    tamper_type = tamper_dbtype|tamper_mode;
                    ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,0);
                }
                /* MySQL/GBase数据库阻断 */
#ifdef ENABLE_MYSQL
                else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MYSQL||__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SHENTONG)
                {
                    if(ret_compress_for_mysql==0/* 非压缩 */)
                    {
                        tamper_dbtype = DBFW_TAMPER_TYPE_MYSQL;
                        tamper_mode = DBFW_TAMPER_TYPE_PACKALL_FF;
                        tamper_type = tamper_dbtype|tamper_mode;
                        ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,4);
                    }
                    else
                    {
                        /* 压缩协议，直接断包 */
#ifdef DEBUG_CHERRY
                        printf("============switch off for mysql compress====================\n");
#endif
                        goto quit;
                    }
                }
#endif  /* ENABLE_MYSQL */
                /* MSSQL数据库拦截 */
#ifdef ENABLE_MSSQL
                else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MSSQL||__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SYBASE)
                {
                    //printf("do Dbfw_Package_Tamper_ForProxy\n");
                    tamper_dbtype = DBFW_TAMPER_TYPE_MSSQL;
                    tamper_mode = DBFW_TAMPER_TYPE_REQ8BYTE_FF;
                    tamper_type = tamper_dbtype|tamper_mode;
                    ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,sizeof(MSTDS_Packet_Header));
                }
#endif  /* ENABLE_MSSQL */
                /* 达梦数据库拦截 */
#ifdef ENABLE_DM
                else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_DM)
                {
                    tamper_dbtype = DBFW_TAMPER_TYPE_DM;
                    tamper_mode = DBFW_TAMPER_TYPE_DMHEADER;
                    tamper_type = tamper_dbtype|tamper_mode;
                    ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,sizeof(DM_PacketHeader));
                }
#endif  /* ENABLE_DM */
#ifdef  ENABLE_PGSQL
				else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_POSTGREE)
				{
					tamper_dbtype = DBFW_TAMPER_TYPE_POSTGRE;
					tamper_mode = DBFW_TAMPER_TYPE_REQ5BYTE_00;
					tamper_type = tamper_dbtype|tamper_mode;
					ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,sizeof(PG_Packet_CommonHead));
					/* bug 10957 阻断的时，有时候会抛出两条Denied信息 原因是没有等待Z的结束命令就发送给客户端串改包*/
					__ORA_SESSION->wait_spy_result = 1;
				}
#endif  /* ENABLE_PGSQL */
#ifdef ENABLE_KINGBASE
				else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_KINGBASE)
				{
					tamper_dbtype = DBFW_TAMPER_TYPE_KINGBASE;
					tamper_mode = DBFW_TAMPER_TYPE_REQ5BYTE_00;
					tamper_type = tamper_dbtype|tamper_mode;
					ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,sizeof(PG_Packet_CommonHead));
				}
#endif /* ENABLE_KINGBASE */
				else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_CACHEDB)
				{
					tamper_dbtype = DBFW_TAMPER_TYPE_CACHEDB;
					tamper_mode = DBFW_TAMPER_TYPE_PACKALL_00;
					tamper_type = tamper_dbtype|tamper_mode;
					ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,12);
					rewrite_packet.packparse_result = 0;
				}
#ifdef ENABLE_GAUSSDB_T
                else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_GAUSSDBT )
                {
                    tamper_dbtype = DBFW_TAMPER_TYPE_GAUSSDB_T;
                    tamper_mode = DBFW_TAMPER_TYPE_REQ8BYTE_FF;
                    tamper_type = tamper_dbtype|tamper_mode;
                    ret = Dbfw_Package_Tamper_ForProxy(tamper_type,(Npp_RewriteNetPacket*)&rewrite_packet,sizeof(GaussdbT_FixHeader));
                }
#endif  /* ENABLE_MSSQL */
				else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_REDIS && __ORA_SESSION->sessCommon.rule_id == 0)
				{
					OraNet_DumpSql("__ORA_SESSION->redis_cmd_offset:%d\n",__ORA_SESSION->redis_cmd_offset);
					rewrite_packet.tcpbuff_bak[0][__ORA_SESSION->redis_cmd_offset]=rewrite_packet.tcpbuff_bak[0][__ORA_SESSION->redis_cmd_offset] + '1';
					rewrite_packet.packparse_result = 0;
					//rewrite_packet.tcpbuff_bak_len[0]
					ret = 1;
				}
                else if(__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_DB2 ||
                        /*__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_POSTGREE ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_KINGBASE ||*/
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_OSCAR ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_IFX ||
						__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_GBASE8T||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_CACHEDB ||
						__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_TERADATA ||
						__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_HIVE ||
						__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_MONGODB ||
						__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_IMPALA ||
						__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_HRPC ||
						__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SENTRY ||
						__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_HANA ||
						__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_ES ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_WEBHTTP ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_SYBASEIQ ||
                        __SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_GAUSSDBT ||
						__SGA_AC_XSEC_DATABASE->dialect==DBFW_DBTYPE_REDIS
                       )
                {
                    /* 
                        DB2/POSTGREE/KINGBASE/OSCAR/Informix/CACHEDB 
                        目前只支持直接阻断
                    */
                    goto quit;
                }
                else
                {
                    /* 其他的数据库类型，直接阻断 */
                    goto quit;
                }
                if(ret>0)
                {
                    /* 篡改成功 */
#ifdef DEBUG_CHERRY
                    printf("============tamper success(for throw)====================\n");
#endif
                    __ORA_SESSION->help_tamper_flag=DBFW_TAMPER_THROW;
                    __ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
                }
                else
                {
                    /* 篡改失败，直接断连接(当前是阻断状态) */
#ifdef DEBUG_CHERRY
                    printf("============switch off for tamper error(throw)====================\n");
#endif
                    goto quit;
                }
				if(__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_ORACLE)
					encryp_pkg(__ORA_SESSION, USER2ORA);
                /* 发送篡改后的通讯包 */
				if(ha)
				{
					nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
				}
                {
                    for(i = 0; i < socks; i++) 
                    {
                        if(multi_skip && multi_skip[i]) continue;
                        for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                        {
                            {
                                select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                            }
                            if(select_ret <= 0) 
                            {
#ifdef WIN32
                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                
                                MULTI_SKIP_QUIT
                            }
                            ZFree(rewrite_packet.tcpbuff_bak[j]);
                            rewrite_packet.tcpbuff_bak_len[j] = 0;
                        }
                        rewrite_packet.tnspack_num = 0;
#ifdef HAVE_SQL_MODIFY_ENGINE
                        /* 准备SQL改写和MASK的数据 */
                        __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
                        /* 清理包改写信息 */
                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
						/* 清理包改写信息 */
						//memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
#endif
                    }
                    
                    send_packet_flag = 0;
                    if (send_packet_direct == 1)
                    {
                    	send_packet_direct = 0;
                    }
                }
				if(ha)
				{
					nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
				}
            }
            
	
//            else if(__ORA_SESSION->enc_tamper_pkg_len > 0)
//            {
//				OraNet_DumpSql("__ORA_SESSION->enc_tamper_pkg_len:%d\n",__ORA_SESSION->enc_tamper_pkg_len);

//				{
//					
//					/* 是重构的新的重定向包 */
//					//if(__ORA_SESSION->help_dynaport_env.redirect_package_size>0)
//					{
//						if(ha)
//						{
//							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
//						}
//						
//						for(i = 0; i < socks; i++) 
//						{
//							//OraNet_DumpSql("client->server 2 : use backup client packet\n");
//							//OraNet_DumpSql("__ORA_SESSION->help_dynaport_env.redirect_package_size:%d\n",__ORA_SESSION->help_dynaport_env.redirect_package_size);
//							if(multi_skip && multi_skip[i]) continue;
//							select_ret = mysend(ssl_sd[i], sd[i]
//							,  __ORA_SESSION->enc_tamper_pkg
//							, __ORA_SESSION->enc_tamper_pkg_len);
//							if(select_ret <= 0) 
//							{
//#ifdef WIN32
//								Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
//#else
//								Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
//#endif                                
//								MULTI_SKIP_QUIT
//							}
//						}
//						ZFree(__ORA_SESSION->enc_tamper_pkg);
//						__ORA_SESSION->enc_tamper_pkg = NULL;
//						__ORA_SESSION->enc_tamper_pkg_len = 0;
//						
//						
//						
//						if(ha)
//						{
//							nppproxy_unregister(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
//						}
//					}

//					if(__ORA_SESSION->help_dynaport_env.redirect_package_size_ext2 > 0)
//					
//					for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
//                    {
//                        ZFree(rewrite_packet.tcpbuff_bak[j]);
//                        rewrite_packet.tcpbuff_bak_len[j] = 0;
//                    }
//                    rewrite_packet.tnspack_num = 0;
//#ifdef HAVE_SQL_MODIFY_ENGINE
//                    /* 准备SQL改写和MASK的数据 */
//                    __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
//                    /* 清理包改写信息 */
//                    Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
//					/* 清理包改写信息 */
//					//memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
//#endif
//				}
//			}
#ifdef HAVE_DYNAPORT
                        /*2016-11-23,alter by liyanjun,发现jdbc客户端连接rac的scanip的代理ip时，由于发给服务器的connect包里的ip和端口是代理ip和端口，
                    造成服务器拒绝连接。增加逻辑：在本地代理下，将转发给数据库的connect包里的ip和端口写回成被保护数据库的真实ip和端口*/

			else if(__ORA_SESSION->is_connect_pack==1)
			{
				OraNet_DumpSql("__ORA_SESSION->is_connect_pack:%d\n",__ORA_SESSION->is_connect_pack);
				OraNet_DumpSql("__ORA_SESSION->connect_break_flag:%d\n",__ORA_SESSION->connect_break_flag);
					if(__ORA_SESSION->connect_break_flag == 1)
				{
					/* redirect package break, wait for next tcp package, do nothing */
				}
				else
				{
					 /* 是重构的新的重定向包 */
					if(__ORA_SESSION->help_dynaport_env.redirect_package_size_ext>0)
					{
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
						for(i = 0; i < socks; i++) 
	                    {
	                        //OraNet_DumpSql("client->server 2 : use backup client packet\n");
	                        OraNet_DumpSql("__ORA_SESSION->help_dynaport_env.redirect_package_size_ext:%d\n",__ORA_SESSION->help_dynaport_env.redirect_package_size_ext);
	                        if(multi_skip && multi_skip[i]) continue;
							select_ret = mysend(ssl_sd[i], sd[i], __ORA_SESSION->help_dynaport_env.redirect_package_data_ext, __ORA_SESSION->help_dynaport_env.redirect_package_size_ext);
                            if(select_ret <= 0) 
                            {
#ifdef WIN32
                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                
                                MULTI_SKIP_QUIT
                            }
	                    }
	                    
	                    send_packet_flag = 0;
	                    if (send_packet_direct == 1)
                  		{
                    		send_packet_direct = 0;
                    	}
	                    
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
					}
					/* 是重构的新的重定向包 */
					if(__ORA_SESSION->help_dynaport_env.redirect_package_size>0)
					{
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
						
						for(i = 0; i < socks; i++) 
						{
							//OraNet_DumpSql("client->server 2 : use backup client packet\n");
							OraNet_DumpSql("__ORA_SESSION->help_dynaport_env.redirect_package_size:%d\n",__ORA_SESSION->help_dynaport_env.redirect_package_size);
							if(multi_skip && multi_skip[i]) continue;
							select_ret = mysend(ssl_sd[i], sd[i],  __ORA_SESSION->help_dynaport_env.redirect_package_data, __ORA_SESSION->help_dynaport_env.redirect_package_size);
							if(select_ret <= 0) 
							{
#ifdef WIN32
								Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
								Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                
								MULTI_SKIP_QUIT
							}
						}
						
						send_packet_flag = 0;
						if (send_packet_direct == 1)
                    	{
                    		send_packet_direct = 0;
                   		}
						
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
					}

					if(__ORA_SESSION->help_dynaport_env.redirect_package_size_ext2 > 0)
					{
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
						
						for(i = 0; i < socks; i++) 
						{
							//OraNet_DumpSql("client->server 2 : use backup client packet\n");
							OraNet_DumpSql("__ORA_SESSION->help_dynaport_env.redirect_package_size_ext2:%d\n",__ORA_SESSION->help_dynaport_env.redirect_package_size_ext2);
							if(multi_skip && multi_skip[i]) continue;
							select_ret = mysend(ssl_sd[i], sd[i],  __ORA_SESSION->help_dynaport_env.redirect_package_data_ext2, __ORA_SESSION->help_dynaport_env.redirect_package_size_ext2);
							if(select_ret <= 0) 
							{
#ifdef WIN32
								Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
								Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                
								MULTI_SKIP_QUIT
							}
						}
						
						send_packet_flag = 0;
						if (send_packet_direct == 1)
                    	{
                    		send_packet_direct = 0;
                   		}
						
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
					}
					
					if(__ORA_SESSION->help_dynaport_env.redirect_package_size>0)
					{
						ZFree(__ORA_SESSION->help_dynaport_env.redirect_package_data);
						__ORA_SESSION->help_dynaport_env.redirect_package_size = 0;
					}
					if(__ORA_SESSION->help_dynaport_env.redirect_package_size_ext>0)
					{
						ZFree(__ORA_SESSION->help_dynaport_env.redirect_package_data_ext);
						__ORA_SESSION->help_dynaport_env.redirect_package_size_ext= 0;
					}
					if(__ORA_SESSION->help_dynaport_env.redirect_package_size_ext2>0)
					{
						ZFree(__ORA_SESSION->help_dynaport_env.redirect_package_data_ext2);
						__ORA_SESSION->help_dynaport_env.redirect_package_size_ext2 = 0;
					}
					if(__ORA_SESSION->help_dynaport_env.ori_package_size_ext>0)
					{
						ZFree(__ORA_SESSION->help_dynaport_env.ori_package_data_ext);
						__ORA_SESSION->help_dynaport_env.ori_package_size_ext= 0;
					}
					if(__ORA_SESSION->help_dynaport_env.ori_package_size>0)
				    {
				        ZFree(__ORA_SESSION->help_dynaport_env.ori_package_data);
				        __ORA_SESSION->help_dynaport_env.ori_package_size = 0;
				    }
					__ORA_SESSION->is_connect_pack = 0;
					for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                    {
                        ZFree(rewrite_packet.tcpbuff_bak[j]);
                        rewrite_packet.tcpbuff_bak_len[j] = 0;
                    }
                    rewrite_packet.tnspack_num = 0;
#ifdef HAVE_SQL_MODIFY_ENGINE
                    /* 准备SQL改写和MASK的数据 */
                    __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
                    /* 清理包改写信息 */
                    Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
					/* 清理包改写信息 */
					//memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
#endif
				}
			}
#endif
            else
            {
            	
client2server_direct:
				if(ha)
				{
					nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
				}
                /* 使用之前备份的Client通讯包 */
				OraNet_DumpSql("rewrite_packet.packet_broken_flag:%d,send_packet_direct:%d\n\n",rewrite_packet.packet_broken_flag,send_packet_direct);
                if(rewrite_packet.packet_broken_flag>=0 || rewrite_packet.packet_broken_flag<ORANET_PARSEFUNC_DATABREAK || send_packet_direct == 1)
                {
#ifdef HAVE_SQL_MODIFY_ENGINE
					if(rewrite_packet.packet_num>0)
					{
                        krb_enc_buff_len = 0;
						/* 有改写包 */
						OraNet_DumpSql("~~~~c->s ~~~~~have sql modify packet~~~~~~~~~~~~~~\n");
						OraNet_DumpSql("rewrite_packet.packet_num = %d\n",rewrite_packet.packet_num);
						__ORA_SESSION->wait_spy_result = 1;
#ifdef ENABLE_HIVE
						if(AUTH_TYPE_KERBEROS == __ORA_SESSION->auth_type)
                        {
                            OraNet_DumpSql("~~~~~~~~~is kerberos !!!!~~~~~~~~~~~~~~\n");

						    if(rewrite_packet.packet_num == 1)
                            {
                                krb_enc_buff_len = npp_krb_gen_encrypt_package(rewrite_packet.packet_data[0]
                                                                               , rewrite_packet.packet_size[0]
                                                                               , &krb_enc_buff
                                                                               , &krb_enc_buff_size
                                                                               , __ORA_SESSION->krb_token_status
                                );


                                OraNet_DumpSql("plain data (%d,%08x):\n", rewrite_packet.packet_size[0]
                                               , rewrite_packet.packet_size[0]);
                                Npp_DumpMemoryData(stdout, (char *) rewrite_packet.packet_data[0]
                                                   , rewrite_packet.packet_size[0]);

                                OraNet_DumpSql("encrypt data (%d,%08x), size = %d\n", krb_enc_buff, krb_enc_buff_len
                                               , krb_enc_buff_size);
                                Npp_DumpMemoryData(stdout, (char *) krb_enc_buff, krb_enc_buff_len);
                            }
                        }
#endif
						/* 使用改写后的通讯包发送到服务器 */
						for(i = 0; i < socks; i++) 
						{
							if(multi_skip && multi_skip[i]) continue;
							for(j=0;j<rewrite_packet.packet_num;j++)   /* 发送所有包到Server */
							{
								OraNet_DumpSql("send rewrite_packet to server : rewrite_packet.packet_num[%d] = %d\n",j,rewrite_packet.packet_size[j]);
								if(krb_enc_buff_len > 0)
								{
									select_ret = mysend(ssl_sd[i], sd[i], krb_enc_buff, krb_enc_buff_len);
                                }
								else
                                {
                                    select_ret = mysend(ssl_sd[i], sd[i], rewrite_packet.packet_data[j], rewrite_packet.packet_size[j]);
                                }
								if(select_ret <= 0) 
								{
#ifdef WIN32
									Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
									Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                
									MULTI_SKIP_QUIT
								}
								ZFree(rewrite_packet.packet_data[j]);
								rewrite_packet.packet_size[j] = 0;
							}
							rewrite_packet.packet_num = 0;
                            /* 准备SQL改写和MASK的数据 */
                            __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
                            /* 清理包改写信息 */
                            Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
							/* 清理包改写信息 */
							//memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
						}
						/* 清理tcpbuff_bak */
#ifdef HAVE_SQL_SPY
                        /* SPY模式下不能清理tcpbuff_bak */
						OraNet_DumpSql("__ORA_SESSION->is_spy_flag:%d\n",__ORA_SESSION->is_spy_flag);
                        if(__ORA_SESSION->is_spy_flag>0 /*&& (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT)*/)
                        {
                            /* 不清理tcpbuff_bak */
                            //OraNet_DumpSql("[not clear tcpbuff_bak] IS SPY mode and spy_sql_type=%d , rewriteinfo_for_request.package_size=%d\n",__ORA_SESSION->spy_sql_type,__ORA_SESSION->rewrite_net_packet->rewriteinfo_for_request.package_size);
                        }
                        else
                        {
#endif
							for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
							{
								ZFree(rewrite_packet.tcpbuff_bak[j]);
								rewrite_packet.tcpbuff_bak_len[j] = 0;
							}
							rewrite_packet.tnspack_num = 0;
#ifdef HAVE_SQL_SPY
                        }   /* else for SPY模式下不能清理tcpbuff_bak */
#endif
					}
					else
					{
#endif
						if(__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_ORACLE)
							encryp_pkg(__ORA_SESSION, USER2ORA);
	                    for(i = 0; i < socks; i++) 
	                    {
	                        //OraNet_DumpSql("client->server 2 : use backup client packet\n");
	                        if(multi_skip && multi_skip[i]) continue;
	                        for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
	                        {
	                        	OraNet_DumpSql("c->s rewrite_packet.tcpbuff_bak_len[j]:%d\n",rewrite_packet.tcpbuff_bak_len[j]);
	                            {
	                                select_ret = mysend(ssl_sd[i] , sd[i], rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
	                            }
	                            if(select_ret <= 0) 
	                            {
#ifdef WIN32
	                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
	                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                
	                                MULTI_SKIP_QUIT
	                            }
	                            ZFree(rewrite_packet.tcpbuff_bak[j]);
	                            rewrite_packet.tcpbuff_bak_len[j] = 0;
	                        }
	                        rewrite_packet.tnspack_num = 0;
#ifdef HAVE_SQL_MODIFY_ENGINE
	                        /* 准备SQL改写和MASK的数据 */
	                        __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
	                        /* 清理包改写信息 */
	                        Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
							/* 清理包改写信息 */
							//memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
#endif
	                    }
#ifdef HAVE_SQL_MODIFY_ENGINE
					}/* for else */
#endif
                    
                    send_packet_flag = 0;
                    if (send_packet_direct == 1)
                    {
                    	send_packet_direct = 0;
                    }
                }
				if(ha)
				{
					nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
				}
				goto receive_client_and_server;
                
            }
        }
server2client: 
        for(i = 0; i < socks; i++) {    // dest port
            /* 2015-04-10 增加退出标记检查和处理逻辑，取代handle信号 */
            if(ha)
            {
            	nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
            }
            process_exit_forflag();
            if(ha)
            {
				nppproxy_unregister(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
            }
            /* receive data from server */
            if(multi_skip && multi_skip[i]) continue;
            if(!FD_ISSET(sd[i], &rset)) continue;            
			memset(buff,0x00,ORANET_MAX_PACKAGESIZE);
			
			if(ha)
			{
				nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
			}
            len = myrecv(ssl_sd[i], sd[i], buff, ORANET_MAX_PACKAGESIZE);
            if(len <= 0) 
            {
                /* 可能是客户端断开连接了(len=0) */
                if(len<0)
                {
#ifdef WIN32
                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_RECV_FAIL,len,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_RECV_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif
                    
                    MULTI_SKIP_QUIT
                }
                else
                {
                    fail_tcp_count_s2c++;
                    if(fail_tcp_count_s2c>3)
                    {
                        MULTI_SKIP_QUIT 
                    }
                    else
                    {
						if(ha)
						{
							nppproxy_unregister(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
                        continue;
                    }
                }
            }
			if(ha)
			{
				Tis_Package_Info info;
				info.portid = 1;

				ret = Tis_Content_Write(tis,__NPP_ALL_CONFIG->sessionid_fornpc,buff,len,&info);
				if(ret >= 0)
					nppproxy_unregister(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
			}
            if(l_xor & 2) xor_data(buff, len);
//            if(dump_fd) acp_dump(dump_fd, SOCK_STREAM, IPPROTO_TCP, dip, htons(dport), sip, htons(sport), buff, len, &seq2, &ack2, &seq1, &ack1);
            if(dump_stdout) fwrite(buff, 1, len, stdout);
            if(cleardump) fwrite(buff, 1, len, dump_fd);
            if(subst1) subst(buff, len);

            /* parse tns&net8 data */
            if(len>0)
            {
				OraNet_DumpSql("len=%u\n",len);
                fail_tcp_count_s2c = 0;
                /* 清理缓冲区满标记 */
                rewrite_packet.tnspack_isfull = 0x00;
#ifdef DUMP_TCPDATA
                if(!dump_tcpdata)
                {
                    dump_tcpdata = fopen((char*)"./dump_tcpdata_da.dat","wb");                    
                }
                if(dump_tcpdata)
                {
                    Npp_DumpDefault(dump_tcpdata,(char*)"--------ORA2USER(len=%d)--------\n",len);
                    Npp_DumpMemoryData(dump_tcpdata,(char*)buff,len);
                }
#endif

                __packet_bypass_state = 0; //设置一轮请求+应答包转发完成
                if(__DB_ISFIND==0 || __NPP_ALL_CONFIG->dbfw_fordb_state==0
#ifdef USE_RUNTIME_OVERRUN_OPER
				|| (__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_BYPASS
					&& __sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_discard, 0) == DBF_RUNTIME_OPER_DISCARD_PKT) 
				|| (Dbfw_Fixarray_GetIntParamInFixarray(&__SGA_FIXARRAY, S_LICENSE_VALID) <= 0)
#endif	
                )
                
                {
					if(ha)
					{
						nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
					}
                    /* 不是被保护的DB，直接旁路 */
                    select_ret = mysend(ssl_sock, sock, buff, len);
                    if(select_ret <= 0) 
                    {
#ifdef WIN32
                        Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sock);
#else
                        Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sock);
#endif                        
                        goto quit;
                    }
					if(ha)
					{
						nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
					}
                    /* 2013-7-16：在收到了来自服务器的通讯包的情况下，需要在接收后，继续检查是否有后续的通讯包 */
                    continue;
                }
                /* 
                    注意：可能会出现服务器连续发送2个Attention包，被一次性接收到了(22个字节) buff中，
                    造成在向client发送时，一次性的发送了2个TNS包，而不是像服务器那样分2次发送
                    改为：
                        根据TNS解析的情况，如果发现一个TNS包的长度比buff的尺寸小，则需要将这个完整的TNS包先发送出去
                    2013-7-19:加压测试发现采用上述分包发送的方式，会造成较大的性能下降，并且考虑之前出现的僵死和游标异常应该与
                        本问题无关，决定废弃该逻辑，回退到原来不分包的方式处理
                */
                buff_cursor = 0;
                //send_len    = len;
                /* 计算运行时统计信息：时间段内累计下行字节数 */
                //__ORA_SESSION->help_static_thr_byte_outband = __ORA_SESSION->help_static_thr_byte_outband + len;
                int check_header_ok = 0;
				__ORA_SESSION->is_sns_pkg = 0;
				__ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
                if(strcasecmp((char *)db_type,"oracle")==0)
                {
                    /* oracle */
                    tcp_buffer_size = Ora_AddTcpPackageToBuffer(buff,len,tcp_info,ORA2USER);
					if(tcp_buffer_size != 0)
					{
						do{
							tns_pack_data = Ora_TnsPackage_PreProcess(tcp_info,ORA2USER,(u_int*)&tns_package_size);
							if(tns_package_size>0)
							{
								if(rewrite_packet.packparse_result==NPP_RESULT_SQLREP_COUNT && tns_package_size==0x0b)
								{
									/* 是结果集探测包引起的Attention包:直接放行,不进行解析;其他任何包都进行解析处理 */
									if(tns_pack_data!=NULL)
									{
										ZFree(tns_pack_data);
									}
								}
#ifdef HAVE_SQL_MODIFY_ENGINE
	#ifdef HAVE_SQL_SPY
                OraNet_DumpSql("__ORA_SESSION->is_spy_flag:%d\n",__ORA_SESSION->is_spy_flag);
                OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
                OraNet_DumpSql("tns_package_size:%d\n",tns_package_size);
                OraNet_DumpSql("attention_cnt:%d\n",attention_cnt);
								if((__ORA_SESSION->is_spy_flag>0 || __ORA_SESSION->spy_field_result == 4) && tns_package_size==0x0b)	//根据tns包的长度判断是否是attention包
								{
									attention_cnt++;
									if(attention_cnt == 2)
									{
										attention_content = (u_char*)ZMalloc(tns_package_size);
										z_memcpy(attention_content, tns_pack_data, tns_package_size, __FILE__, __LINE__, Smem_LogError_Format);
										check_header_ok = 1;
									}
									if(tns_pack_data!=NULL)
									{
										ZFree(tns_pack_data);
									}
								}
	#endif
#endif
								else
								{
									/* 性能测试：暂时去掉解析逻辑 */
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                                    /* 测试篡改返回包 */
									/* 为了高级安全加密在代理下抛异常，注释掉以下三行 */
									if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->encrypt_alg == 0x11)
									{
										__ORA_SESSION->tamper_data_addr = (u_char*)rewrite_packet.tcpbuff_bak[0];
									}
									else
									{
										if(buff_cursor<len)
                                        	__ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                                    	else
											__ORA_SESSION->tamper_data_addr = (u_char*)rewrite_packet.tcpbuff_bak[0];
									}
                                       
#endif
									check_header_ok = 1;
									parse_ret = OraTnsPackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,ORA2USER,&rewrite_packet);

#ifdef HAVE_SQL_MODIFY_ENGINE
#ifdef HAVE_SQL_SPY
									//判断本次结果是否为spy sql的返回包
									if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT))
                                    {
                                        /* 正在进行SPY处理，不能执行NPP_SqlProcess */
                                        OraNet_DumpSql("[MYSQL RESPONSE] SPY SQL\n");
                                    }
                                    else
                                    {
                                        parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
                                    }
#else
                                    parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
#endif
#else
									parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
#endif
                                    /*对于9i的oci，现采取的措施是拦截掉，退出*/
                                    if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->tns_accept_header.tns_version == ORA_TNS_VER_312)
                                    {
                                        OraNet_DumpSql("Oracle 9i(Server) TNS=%d\n",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->tns_accept_header.tns_version);
                                    }
									/* 对于SQL改写，不需要专门处理DB返回的应答包 */
									if(tns_pack_data!=NULL)
									{
										ZFree(tns_pack_data);
									}
								}

							}
						}
						while(tns_package_size>0);
					}
                    if(rewrite_packet.packparse_result==NPP_RESULT_SQLREP_COUNT && len==0x16)
                    {
                        /* 是结果集探测包引起的Attention包:直接放行,不进行解析;其他任何包都进行解析处理 */
                        {
                            if(buff_cursor<len)
                            {
								if(ha)
								{
									nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
								}
                                select_ret = mysend(ssl_sock, sock, buff+buff_cursor, (len-buff_cursor));
                                if(select_ret <= 0) 
                                {
#ifdef WIN32
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sock);
#else
                                    Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sock);
#endif                                    
                                    goto quit;
                                }
								if(ha)
								{
									nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
								}
                            }
                            goto receive_client_and_server;
                        }
                    }

#ifdef HAVE_SQL_MODIFY_ENGINE
	#ifdef HAVE_SQL_SPY
                    /* 
                        在SPY模式下，不要转发通讯包到客户端 
                        重要的是检查:((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp==0 表示通讯包已经结束了
                    */
				   /* 引入语法树后需要提前 */
				   if((__ORA_SESSION->is_spy_flag>0 || __ORA_SESSION->spy_field_result == 4) /*&& (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT)*/)
				   {
					   	if(attention_cnt == 1)
						{
							/* 应答方向只返回一个，还需要等待应答 */
							goto receive_client_and_server;
						}
						if(attention_cnt == 2)
						{
						
							for(int i=0; i<__ORA_SESSION->rewrite_net_packet->packet_num; i++)
							{
								if(__ORA_SESSION->rewrite_net_packet->packet_size[i] > 0)
								{
									__ORA_SESSION->rewrite_net_packet->packet_size[i] = 0;
									ZFree(__ORA_SESSION->rewrite_net_packet->packet_data[i]);
								}
							}
							
							__ORA_SESSION->rewrite_net_packet->packet_data[0] = attention_content;
							__ORA_SESSION->rewrite_net_packet->packet_size[0] = 0x0b;
							__ORA_SESSION->rewrite_net_packet->packet_num = 1;
							attention_cnt = 0;

							goto client2server;
						}
				   }
                    if(__ORA_SESSION->is_spy_flag>0 && (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag<=0 ||check_header_ok==0))
                    	goto receive_client_and_server;
					/* 处理多表取表结构的问题，2表示正在取表结构中，3表示最后一个 */
                    if(__ORA_SESSION->spy_field_result == 2 || __ORA_SESSION->spy_field_result == 3)
                    {
                    	OraNet8_SqlStmtData * stmt_spy = (OraNet8_SqlStmtData *)__ORA_SESSION->stmt_for_spy;
						int idx_1017 = 0;
						int total_field_cursor = 0;
						short total_field_len = 0;
#ifdef HAVE_SQL_TREE
						if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
						{
							if(stmt_spy->help_select_field > 0)
							{
								u_char alias_len = 0;
								/* 个数 */
								(*(short*)__ORA_SESSION->mask_field->str)++;
								if(__ORA_SESSION->mask_field->length == 0)
									__ORA_SESSION->mask_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
									//total_field_cursor = __ORA_SESSION->mask_field->length;
									//__ORA_SESSION->mask_field->length =  __ORA_SESSION->mask_field->length + sizeof(short);
							}
							if(stmt_spy->help_select_field > 0)
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&(stmt_spy->help_select_field), sizeof(short));
							for(idx_1017=0; idx_1017<stmt_spy->help_select_field; idx_1017++)
							{
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
									(char*)&(stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len),
									sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
									(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
									stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
								OraNet_DumpSql("net8_fielddesc[%d].fieldname:%s\n",idx_1017,stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname);
							}
							// if(stmt_spy->help_select_field > 0)
							// {
							//     total_field_len = __ORA_SESSION->mask_field->length - (total_field_cursor + sizeof(short));
							//      memcpy(__ORA_SESSION->mask_field->str + total_field_cursor, &total_field_len, sizeof(short));
							// }
						}
						else					
#endif
						{
							if(stmt_spy->help_select_field > 0)
							{
								u_char alias_len = 0;
								(*(short*)__ORA_SESSION->mask_field->str)++;
								if(__ORA_SESSION->mask_field->length == 0)
									__ORA_SESSION->mask_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
								total_field_cursor = __ORA_SESSION->mask_field->length;
								__ORA_SESSION->mask_field->length =  __ORA_SESSION->mask_field->length + sizeof(short);
								/*表+字段*/
								(*(short*)__ORA_SESSION->mask_table_field->str)++;
								if(__ORA_SESSION->mask_table_field->length == 0)
									__ORA_SESSION->mask_table_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
								total_field_cursor = __ORA_SESSION->mask_table_field->length;
								__ORA_SESSION->mask_table_field->length =  __ORA_SESSION->mask_table_field->length + sizeof(short);
							}
							for(idx_1017=0; idx_1017<stmt_spy->help_select_field; idx_1017++)
							{
								if(idx_1017 >= ORANET_MAX_COLUMNCOUNT)
									break;
								if(idx_1017 != 0)
								{
									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)",", strlen((char*)","));
									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)",", strlen((char*)","));
								}
								// if(__ORA_SESSION->nonneed_table != 1)
								// {
								// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
								// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)".", strlen((char*)"."));
								// }
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)".", strlen((char*)"."));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
									(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
									stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field,
									(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
									stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
								OraNet_DumpSql("net8_fielddesc[%d].fieldname:%s\n",idx_1017,stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname);
							}
							if(stmt_spy->help_select_field > 0)
							{
								total_field_len = __ORA_SESSION->mask_field->length - (total_field_cursor + sizeof(short));
								memcpy(__ORA_SESSION->mask_field->str + total_field_cursor, &total_field_len, sizeof(short));
								total_field_len = __ORA_SESSION->mask_table_field->length - (total_field_cursor + sizeof(short));
								memcpy(__ORA_SESSION->mask_table_field->str + total_field_cursor, &total_field_len, sizeof(short));
							}
						}
                    }
                    if(__ORA_SESSION->spy_field_result == 2)
                    {
                    	OraNet_DumpSql("ni hao 2\n");
                    	ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
                        if(ret>0)
                        {
                            if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
                            {
                            	memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
                            	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
                            	int idx = 0;
                            	for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
                            	{
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            		memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            	}
                            }
                            __ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
                            ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
                                (char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
                                ((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
							attention_cnt = 0;
                        }
                        if(__ORA_SESSION->table_index == 0)
                       		__ORA_SESSION->spy_field_result = 3;
                        goto client2server;
                    }
                    if(__ORA_SESSION->spy_field_result == 3)
                    {
						__ORA_SESSION->help_last_ack_errorno = 0;
                	    ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult_Table(__ORA_SESSION,NULL,0);
						((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
                        ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
						__ORA_SESSION->is_spy_flag = 0x00;
						__ORA_SESSION->spy_field_result = 0;
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
						memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
						memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
						__ORA_SESSION->table_index = 0;
						__ORA_SESSION->nonneed_table = 0;
						goto client2server;
                    }
					/* 取多个表的逻辑结束 */
					OraNet_DumpSql("__ORA_SESSION->is_spy_flag:%d,__ORA_SESSION->spy_sql_type:%d,check_header_ok:%d\n",__ORA_SESSION->is_spy_flag,__ORA_SESSION->spy_sql_type,check_header_ok);
					OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n", __ORA_SESSION->help_last_ack_errorno);
					OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n", __ORA_SESSION->spy_field_result);
                    if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT) &&
                    ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag>=0 && check_header_ok==1)
                    {
                        if(((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result==0x00)	//mod by luhao mysql使用的判断是mysql_help_hasresp，oracle改为sqlspy_result。在"OraNet8_Parse_1017"系列函数中处理 
                        {
                        	/*当输入错误语句时，spy sql的语句同样也是错的。这时，需要对出错的语句进行特殊处理。经过抓包分析
                        	oracle会先发送两个MARKER(0x0c)包，然后客户端回一个MARKER(0x0c)包内容分别是:
                        	ora2user:	01 00 01
                        				01 00 02
                        	user2ora:	01 00 02
                        	oracle收到客户端发的attention包后再将错误的信息以0x0405包的形式发给客户端*/
							if(attention_cnt == 2)//判断是否收到了oracle发送的2个attention包
							{
								//直接发送内容为"01 00 02"的0x0c包给oracle
								//此时buffer中的数据是两个ora2user的0x0c包
								
								for(int i=0; i<__ORA_SESSION->rewrite_net_packet->packet_num; i++)
								{
									if(__ORA_SESSION->rewrite_net_packet->packet_size[i] > 0)
									{
										__ORA_SESSION->rewrite_net_packet->packet_size[i] = 0;
										ZFree(__ORA_SESSION->rewrite_net_packet->packet_data[i]);
									}
								}
								
								__ORA_SESSION->rewrite_net_packet->packet_data[0] = attention_content;
								__ORA_SESSION->rewrite_net_packet->packet_size[0] = 0x0b;
								__ORA_SESSION->rewrite_net_packet->packet_num = 1;
								attention_cnt = 0;
	
								goto client2server;
							}

							if(attention_cnt>0 && attention_cnt< 2)
							{
	                            /* 应答包还没有处理结束 */
	                            //continue;
	                            goto receive_client_and_server;
							}
                        }
                        /* SPY SQL的应答包已经处理完成了 */
                        /* 使用应答包解析的结果来构造最终的SQL语句 */

                        OraNet_DumpSql("process server->client for SPY\n");
                        /* 检查是否应答包是错误包(SPY语句执行结果是失败) */
                        if(__ORA_SESSION->help_last_ack_errorno != 0 && __ORA_SESSION->help_last_ack_errorno != 1403)	//oracle查询出来0条时报1403错误
                        {
							OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
                  			  OraNet_DumpSql("__ORA_SESSION->mask_table_alias->length:%d\n", __ORA_SESSION->mask_table_alias->length);
                		    OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n", __ORA_SESSION->help_last_ack_errorno);
							if((__ORA_SESSION->help_last_ack_errorno==918 || __ORA_SESSION->help_last_ack_errorno==904 || __ORA_SESSION->help_last_ack_errorno==936 || __ORA_SESSION->help_last_ack_errorno==972 || __ORA_SESSION->help_last_ack_errorno==907))
							{
								__ORA_SESSION->help_last_ack_errorno = 0;
								OraNet8_SqlStmtData * stmt = NULL;
								if(((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle > 0)
								{
									stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->stmp_table_hash,((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle);
								}
								else
								{
									stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->newstmt_table,((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_port);
								}
								if(stmt)
								{
									stmt->stmtCommon.error_code = 0;
									Dbfw_TypedVarData_Release(&stmt->stmtCommon.error_msg);
								}
								OraNet_DumpSql("ni hao\n");
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
								memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
								memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
								__ORA_SESSION->table_index = 0;
								__ORA_SESSION->nonneed_table = 0;
#ifdef HAVE_SQL_TREE
								if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
								{
									GetTableFromSqlTree((void*)__ORA_SESSION);
								}
								else
#endif
								{
								Dbfw_GetTableAndAlisa(__ORA_SESSION);
								}
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
								ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
								if(ret>0)
								{
									if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
									{
										memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
										((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
										int idx = 0;
										for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
										{
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
											memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
										}
									}
									__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
									ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
										(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
										((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,0);
									attention_cnt = 0;
								}
								if(__ORA_SESSION->table_index == 0)
								{
									__ORA_SESSION->spy_field_result = 3;
								}
								else
								{
								__ORA_SESSION->spy_field_result = 2;
								}
								goto client2server;
							}
							else
							{
								                            /* 记录错误日志 */
								Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"SPY SQL Fail , errno=%d , errMsg=%s",
									((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.cmd0401_header.error_no,
									((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.option_cmd0401_data.message
									);
								/* 失败的SPY SQL情况下跳过SQL语句改写 */
								/* 直接换回之前的STMT */
								if(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak)
								{
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
									if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
									else
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';
								}
								ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
								if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
									rewrite_packet.packparse_result=NPP_RESULT_BLOCKING_THROW_FORCOUNT;
								if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
                                {
                                    memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
                                    ((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
                                    int idx = 0;
                                    for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
                                    {
                                        ((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
                                        ((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                                        memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                                    }
                                }
                                else
                                {
                                    OraNet_DumpSql("tcpbuff_bak is null\n");
                                }
                                __ORA_SESSION->help_last_ack_errorno = 0;
                                __ORA_SESSION->spy_field_result = 0;
							}
                        }
                        else
                        {
                            ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult(__ORA_SESSION,NULL,0);

							/* 换回之前的STMT */
							((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
                            ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
							__ORA_SESSION->is_spy_flag = 0x00;
							__ORA_SESSION->spy_field_result = 4;
							__ORA_SESSION->help_last_ack_errorno = 0;
                        }
                        /* 正式发送客户端的请求数据 */
                        goto client2server;
                    }
					if(__ORA_SESSION->spy_field_result == 4 && __ORA_SESSION->help_last_ack_errorno != 0 && __ORA_SESSION->help_last_ack_errorno != 1403)
					{
						if(__ORA_SESSION->help_last_ack_errorno != 0 && __ORA_SESSION->help_last_ack_errorno != 1403)	//oracle查询出来0条时报1403错误
                        {
							OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
                  			  OraNet_DumpSql("__ORA_SESSION->mask_table_alias->length:%d\n", __ORA_SESSION->mask_table_alias->length);
                		    OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n", __ORA_SESSION->help_last_ack_errorno);
							if((__ORA_SESSION->help_last_ack_errorno==918 || __ORA_SESSION->help_last_ack_errorno==904 || __ORA_SESSION->help_last_ack_errorno==936 ||__ORA_SESSION->help_last_ack_errorno==972 || __ORA_SESSION->help_last_ack_errorno==907))
							{
								__ORA_SESSION->help_last_ack_errorno = 0;
								OraNet8_SqlStmtData * stmt = NULL;
								if(((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle > 0)
								{
									stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->stmp_table_hash,((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle);
								}
								else
								{
									stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->newstmt_table,((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_port);
								}
								if(stmt)
								{
									stmt->stmtCommon.error_code = 0;
									Dbfw_TypedVarData_Release(&stmt->stmtCommon.error_msg);
								}
								OraNet_DumpSql("ni hao\n");
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
								memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
								memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
								__ORA_SESSION->table_index = 0;
								__ORA_SESSION->nonneed_table = 0;
#ifdef HAVE_SQL_TREE
								if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
								{	
								    GetTableFromSqlTree((void*)__ORA_SESSION);
								}
								else
#endif
								{
								Dbfw_GetTableAndAlisa(__ORA_SESSION);
								}
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
								ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,1);
								if(ret>0)
								{
									if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
									{
										memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
										((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
										int idx = 0;
										for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
										{
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
											memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
										}
									}
									__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
									ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
										(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
										((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
									attention_cnt = 0;
								}
								if(__ORA_SESSION->table_index == 0)
								{
									__ORA_SESSION->spy_field_result = 3;
								}
								else
								{
									__ORA_SESSION->spy_field_result = 2;
								}
								goto client2server;
							}
							else
							{
								if(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak)
								{
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
									if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
									else
									{
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';
									}
								}
								
								ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
								__ORA_SESSION->help_last_ack_errorno = 0;
								__ORA_SESSION->spy_field_result = 0;
								if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
									rewrite_packet.packparse_result = NPP_RESULT_BLOCKING_THROW_FORCOUNT;

								if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
								{
									memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
									((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
									int idx = 0;
									for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
									{
										((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
										((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
										memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
									}
								}
								else
								{
									OraNet_DumpSql("tcpbuff_bak is null\n");
								}
								
								goto client2server;
							}
                        }
                        
                        /* 正式发送客户端的请求数据 */
						OraNet_DumpSql(" ###### client2server #####\n");
                        //goto client2server;	
					}
					OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);

					if(__ORA_SESSION->spy_field_result == 5 && (__ORA_SESSION->help_last_ack_errorno != 0))
					{
						OraNet_DumpSql("hahahaha\n");
						__ORA_SESSION->spy_field_result = 0;
						if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_BYPASS)
							goto client2server_direct;
					}

                    
                    
	#endif
#endif
                }
                else if(strcasecmp((char *)db_type,"mssql")==0)
                {
                    /* MSSQL */
#ifdef ENABLE_MSSQL
                    tcp_buffer_size = MSTDS_AddTcpPackageToBuffer(buff,len,tcp_info,MSSQL2USER);
                    do{
                        tns_pack_data = MSTDS_Package_PreProcess(tcp_info,MSSQL2USER,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
	#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
	#endif
							check_header_ok = 1;
                            parse_ret = MSTDSPackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,MSSQL2USER,&rewrite_packet);
#ifdef HAVE_SQL_MODIFY_ENGINE
	#ifdef HAVE_SQL_SPY
							//判断本次结果是否为spy sql的返回包
							if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT))
							{
								/* 正在进行SPY处理，不能执行NPP_SqlProcess */
								OraNet_DumpSql("[MYSQL RESPONSE] SPY SQL\n");
							}
							else
							{
								parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
							}
	#else
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
	#endif
#else
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
#endif
							if(rewrite_packet.packparse_result==NPP_RESULT_SWITCHOFF || rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
							__ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF || __ORA_SESSION->help_parse_result==NPP_RESULT_BLOCKING_THROW)
								__ORA_SESSION->respon_switchoff_moresql = NPP_RESULT_SWITCHOFF;
							//parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
#ifdef HAVE_SQL_MODIFY_ENGINE
	#ifdef HAVE_SQL_SPY
                    /* 
                        在SPY模式下，不要转发通讯包到客户端 
                        重要的是检查:((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp==0 表示通讯包已经结束了
                    */
                    if(__ORA_SESSION->is_spy_flag>0 && (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag<=0 ||check_header_ok==0))
                    	goto receive_client_and_server;
					/* t.*,t.a */
					if(__ORA_SESSION->spy_field_result == 2 || __ORA_SESSION->spy_field_result == 3)
                    {
						/* 失败的语句不在走脱敏逻辑 */
#ifdef HAVE_SQL_TREE1 /* 失败的语句不在走脱敏逻辑 这一块注释掉，因为对于多语句一旦不存在的表如果这样做会直接发原语句 */
                        if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
						{
							if(__ORA_SESSION->help_last_ack_errorno != 0)
							{
								__ORA_SESSION->spy_field_result = 0;
								__ORA_SESSION->help_last_ack_errorno = 0;
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
                            	if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
								else
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';
								Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
								if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
									rewrite_packet.packparse_result=NPP_RESULT_BLOCKING_THROW_FORCOUNT;
								goto client2server;
							}
						}
#endif
                    	OraNet8_SqlStmtData * stmt_spy = (OraNet8_SqlStmtData *)__ORA_SESSION->stmt_for_spy;
						int idx_1017 = 0;
						int total_field_cursor = 0;
						short total_field_len = 0;
#ifdef HAVE_SQL_TREE
                        if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
						{
							if(stmt_spy->help_select_field > 0)
							{
								u_char alias_len = 0;
								/* 个数 */
								(*(short*)__ORA_SESSION->mask_field->str)++;
								if(__ORA_SESSION->mask_field->length == 0)
									__ORA_SESSION->mask_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
									//total_field_cursor = __ORA_SESSION->mask_field->length;
									//__ORA_SESSION->mask_field->length =  __ORA_SESSION->mask_field->length + sizeof(short);
							}
							if(stmt_spy->help_select_field > 0)
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&(stmt_spy->help_select_field), sizeof(short));
							for(idx_1017=0; idx_1017<stmt_spy->help_select_field; idx_1017++)
							{
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
									(char*)&(stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len),
									sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
									(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
									stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
								OraNet_DumpSql("net8_fielddesc[%d].fieldname:%s\n",idx_1017,stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname);
							}
								// if(stmt_spy->help_select_field > 0)
								// {
								//     total_field_len = __ORA_SESSION->mask_field->length - (total_field_cursor + sizeof(short));
								//      memcpy(__ORA_SESSION->mask_field->str + total_field_cursor, &total_field_len, sizeof(short));
								// }
						}
						else
#endif
						{
							if(stmt_spy->help_select_field > 0)
							{
								u_char alias_len = 0;
								(*(short*)__ORA_SESSION->mask_field->str)++;
								if(__ORA_SESSION->mask_field->length == 0)
									__ORA_SESSION->mask_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
								total_field_cursor = __ORA_SESSION->mask_field->length;
								__ORA_SESSION->mask_field->length =  __ORA_SESSION->mask_field->length + sizeof(short);

								(*(short*)__ORA_SESSION->mask_table_field->str)++;
								if(__ORA_SESSION->mask_table_field->length == 0)
									__ORA_SESSION->mask_table_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
								total_field_cursor = __ORA_SESSION->mask_table_field->length;
								__ORA_SESSION->mask_table_field->length =  __ORA_SESSION->mask_table_field->length + sizeof(short);
							}
							for(idx_1017=0; idx_1017<stmt_spy->help_select_field; idx_1017++)
							{
								if(idx_1017 >= ORANET_MAX_COLUMNCOUNT)
									break;
								if(idx_1017 != 0)
								{
									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)",", strlen((char*)","));
									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)",", strlen((char*)","));
								}
								// if(__ORA_SESSION->nonneed_table != 1)
								// {
								// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
								// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)".", strlen((char*)"."));
								// }
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)".", strlen((char*)"."));

								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
									(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
									stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field,
									(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
									stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
								OraNet_DumpSql("net8_fielddesc[%d].fieldname:%s\n",idx_1017,stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname);
							}
							if(stmt_spy->help_select_field > 0)
							{
								total_field_len = __ORA_SESSION->mask_field->length - (total_field_cursor + sizeof(short));
								memcpy(__ORA_SESSION->mask_field->str + total_field_cursor, &total_field_len, sizeof(short));
								total_field_len = __ORA_SESSION->mask_table_field->length - (total_field_cursor + sizeof(short));
								memcpy(__ORA_SESSION->mask_table_field->str + total_field_cursor, &total_field_len, sizeof(short));
							}
						}
                    }
                    if(__ORA_SESSION->spy_field_result == 2)
                    {
                    	OraNet_DumpSql("ni hao 2\n");
                    	ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
                        if(ret>0)
                        {
                            if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
                            {
                            	memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
                            	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
                            	int idx = 0;
                            	for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
                            	{
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            		memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            	}
                            }
                            __ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
                            ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
                                (char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
                                ((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
							attention_cnt = 0;
                        }
                        if(__ORA_SESSION->table_index == 0)
                       		__ORA_SESSION->spy_field_result = 3;
                        goto client2server;
                    }
                    if(__ORA_SESSION->spy_field_result == 3)
                    {
						__ORA_SESSION->help_last_ack_errorno = 0;
                	    ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult_Table(__ORA_SESSION,NULL,0);
						((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
                        ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
						__ORA_SESSION->is_spy_flag = 0x00;
						__ORA_SESSION->spy_field_result = 0;
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
						memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
						memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
						__ORA_SESSION->table_index = 0;
						__ORA_SESSION->nonneed_table = 0;
						goto client2server;
                    }
					/* end */
                    if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT) &&
                    ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag>=0 && check_header_ok==1)
                    {
                        /* SPY SQL的应答包已经处理完成了 */
                        /* 使用应答包解析的结果来构造最终的SQL语句 */

                        OraNet_DumpSql("process server->client for SPY\n");
                        /* 检查是否应答包是错误包(SPY语句执行结果是失败) */
                        if(__ORA_SESSION->help_last_ack_errorno != 0)	//oracle查询出来0条时报1403错误
                        {
                            /* 记录错误日志 */
							/* t.*,t.a */
							OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
							OraNet_DumpSql("__ORA_SESSION->mask_table_alias->length:%d\n", __ORA_SESSION->mask_table_alias->length);
							OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n", __ORA_SESSION->help_last_ack_errorno);
							OraNet_DumpSql("sqlProcess->stmtCommon->child_count:%d\n",__ORA_SESSION->sqlProcess.stmtCommon->child_count);
							
							if((__ORA_SESSION->sqlProcess.stmtCommon->child_count <= 1) && /* __ORA_SESSION->spy_field_result == 1 &&*/ (__ORA_SESSION->help_last_ack_errorno == 8156 || __ORA_SESSION->help_last_ack_errorno == 8155 ||__ORA_SESSION->help_last_ack_errorno == 156))
							{
								__ORA_SESSION->help_last_ack_errorno = 0;
								OraNet8_SqlStmtData * stmt = NULL;
								if(((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle > 0)
								{
									stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->stmp_table_hash,((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle);
								}
								else
								{
									stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->newstmt_table,((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_port);
								}
								if(stmt)
								{
									stmt->stmtCommon.error_code = 0;
									Dbfw_TypedVarData_Release(&stmt->stmtCommon.error_msg);
								}
								OraNet_DumpSql("ni hao\n");
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
								memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
								memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
								__ORA_SESSION->table_index = 0;
								__ORA_SESSION->nonneed_table = 0;
#ifdef HAVE_SQL_TREE
                                if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
								{
								    GetTableFromSqlTree((void*)__ORA_SESSION);
								}
								else
#endif
								{
									Dbfw_GetTableAndAlisa(__ORA_SESSION);
								}
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
								ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
								if(ret>0)
								{
									if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
									{
										memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
										((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
										int idx = 0;
										for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
										{
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
											memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
										}
									}
									__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
									ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
										(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
										((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
									attention_cnt = 0;
								}
								if(__ORA_SESSION->table_index == 0)
								{
									__ORA_SESSION->spy_field_result = 3;
								}
								else
								{
									__ORA_SESSION->spy_field_result = 2;
								}
								goto client2server;
							}
							/* end */
							else
							{

								Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"SPY SQL Fail , errno=%d , errMsg=%s",
									((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.cmd0401_header.error_no,
									((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.option_cmd0401_data.message
									);
								/* 失败的SPY SQL情况下跳过SQL语句改写 */
								/* 直接换回之前的STMT */
								if(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak)
								{
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
									if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
									else
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';
								}
								__ORA_SESSION->help_last_ack_errorno = 0;
								ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
								if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
									rewrite_packet.packparse_result=NPP_RESULT_BLOCKING_THROW_FORCOUNT;
								
							}
                        }
                        else
                        {
                            ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult(__ORA_SESSION,NULL,0);
							
							/* 换回之前的STMT */
							((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
                            ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
							__ORA_SESSION->is_spy_flag = 0x00;
							__ORA_SESSION->help_last_ack_errorno = 0;                   
						}
                        /* 正式发送客户端的请求数据 */
                        goto client2server;
                    }
					
	#endif
#endif
                }
                else if(strcasecmp((char *)db_type,"mysql")==0)
                {
#ifdef ENABLE_MYSQL
					int  parse_mysql_flag = 1;
                    if(__ORA_SESSION->mysql_capability_flag_1_client.client_ssl == 1 
                       && __ORA_SESSION->mysql_capability_flag_1_server.client_ssl == 1)
                    {
						#ifdef ENABLE_SSL
						if(frontend_ssl_state == SSL_STATE_CTX_FAIL || frontend_ssl_state == SSL_STATE_HANDSHAKE_FAIL)
						{
							parse_mysql_flag = 0;
						}
						if(backend_ssl_state == SSL_STATE_CTX_FAIL || backend_ssl_state == SSL_STATE_HANDSHAKE_FAIL)
						{
							parse_mysql_flag = 0;
						}
						#else
                        if(__ORA_SESSION->log_flag == 0)
                        {
                            __ORA_SESSION->log_flag = 1;
                        	Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__
                        	    ,(char*)"find mysql ssl session,bypass");
                    	}
						parse_mysql_flag = 0;
						#endif
                    }
                    if(parse_mysql_flag)
                    {
    					    /* 刘思成开始添加 */
    					ret_compress_for_mysql = MYSQL_Uncompress(tcp_info,buff,len,MYSQL2USER);
    					if(ret_compress_for_mysql != -2)/* 非断包 */
    					{
    						if (ret_compress_for_mysql == 0)/* 非压缩 */
    						{
    							tcp_buffer_size = MYSQL_AddTcpPackageToBuffer(buff,len,tcp_info,MYSQL2USER);
    	#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                                        /* 测试篡改返回包 */
                                if(buff_cursor<len)
                                    __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                                else
                                    __ORA_SESSION->tamper_data_addr = (u_char*)buff;
    	#endif
    						}
    						else
    									/* 压缩 */
    						{
    							tcp_buffer_size = MYSQL_AddTcpPackageToBuffer(__ORA_SESSION->mysql_dyna_uncompress_buff,__ORA_SESSION->mysql_dyna_uncompress_buff_size,tcp_info,MYSQL2USER);
    							ZFree(__ORA_SESSION->mysql_dyna_uncompress_buff);
    							__ORA_SESSION->mysql_dyna_uncompress_buff_size =0;
    						}
    							
    						do{
    							tns_pack_data = MYSQL_Package_PreProcess(tcp_info,MYSQL2USER,(u_int*)&tns_package_size);
    							if(tns_package_size>0)
    							{
    								check_header_ok = 1;
    								parse_ret = MYSQL_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,MYSQL2USER,&rewrite_packet);
    	#ifdef HAVE_SQL_MODIFY_ENGINE
    		#ifdef HAVE_SQL_SPY
                                    if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT))
                                    {
                                        /* 正在进行SPY处理，不能执行NPP_SqlProcess */
                                        OraNet_DumpSql("[MYSQL RESPONSE] SPY SQL\n");
                                    }
    								else if(__ORA_SESSION->is_spy_flag==2)
    								{
                                        OraNet_DumpSql("[MYSQL RESPONSE] SPY SQL type 2\n");
    									/* 获取中间结果集 */
                                        //parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
    								}
                                    else
                                    {
                                        parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
                                    }
    		#else
                                    parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
    		#endif  /* HAVE_SQL_SPY */
                                    #ifdef ENABLE_RESULTSET_MASK
									Dbsc_Mysql_Update_Header(tns_pack_data,tns_package_size);
									Dbsc_Mysql_Save_Response(__ORA_SESSION,tns_pack_data,tns_package_size);
									#endif
    	#else
    								parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
    	#endif	/* HAVE_SQL_MODIFY_ENGINE */
							    	if(rewrite_packet.packparse_result==NPP_RESULT_SWITCHOFF || rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
										__ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF || __ORA_SESSION->help_parse_result==NPP_RESULT_BLOCKING_THROW)
											__ORA_SESSION->respon_switchoff_moresql = NPP_RESULT_SWITCHOFF;
    								if(tns_pack_data!=NULL)
    									ZFree(tns_pack_data);
    								}
    							}
    							while(tns_package_size>0);
    	#ifdef HAVE_SQL_MODIFY_ENGINE
    		#ifdef HAVE_SQL_SPY
                                /* 
                                    在SPY模式下，不要转发通讯包到客户端 
                                    重要的是检查:((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp==0 表示通讯包已经结束了
                                */
							   OraNet_DumpSql("555__ORA_SESSION->is_spy_flag:%d\n",__ORA_SESSION->is_spy_flag);
							    OraNet_DumpSql("555__ORA_SESSION->wait_spy_result:%d\n",__ORA_SESSION->wait_spy_result);
								OraNet_DumpSql("555__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
							   OraNet_DumpSql("((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag:%d\n",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag);
                                OraNet_DumpSql("check_header_ok:%d\n",check_header_ok);
								OraNet_DumpSql("__ORA_SESSION->more_sql_spy_noend:%d\n",__ORA_SESSION->more_sql_spy_noend);
								OraNet_DumpSql("__ORA_SESSION->spy_sql_type:%d\n",__ORA_SESSION->spy_sql_type);
								if(__ORA_SESSION->stmt_for_spy)
									OraNet_DumpSql("((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp:%d\n",((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp);
								if(__ORA_SESSION->is_spy_flag>0 && (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag<=0 ||check_header_ok==0))
                        			goto receive_client_and_server;
								if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_field_result == 0 || __ORA_SESSION->spy_field_result == 4 || __ORA_SESSION->spy_field_result == 2 || __ORA_SESSION->spy_field_result == 3) && __ORA_SESSION->wait_spy_result == 1)
									goto receive_client_and_server;
									/* t.*,t.a */
					if(__ORA_SESSION->spy_field_result == 2 || __ORA_SESSION->spy_field_result == 3)
                    {
                    	OraNet8_SqlStmtData * stmt_spy = (OraNet8_SqlStmtData *)__ORA_SESSION->stmt_for_spy;
						int idx_1017 = 0;
						int total_field_cursor = 0;
						short total_field_len = 0;
#ifdef HAVE_SQL_TREE
                        if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
						{
						if(stmt_spy->help_select_field > 0)
						{
							u_char alias_len = 0;
							/* 个数 */
							(*(short*)__ORA_SESSION->mask_field->str)++;
							if(__ORA_SESSION->mask_field->length == 0)
								__ORA_SESSION->mask_field->length = sizeof(short);
							alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&alias_len, sizeof(char));
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
	                            //total_field_cursor = __ORA_SESSION->mask_field->length;
	                            //__ORA_SESSION->mask_field->length =  __ORA_SESSION->mask_field->length + sizeof(short);
	                        }
	                        if(stmt_spy->help_select_field > 0)
	                            Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&(stmt_spy->help_select_field), sizeof(short));
	                        for(idx_1017=0; idx_1017<stmt_spy->help_select_field; idx_1017++)
							{
	                            Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
	                                (char*)&(stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len),
	                                sizeof(char));
	                            Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
	                                (char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
	                                stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
	                            OraNet_DumpSql("net8_fielddesc[%d].fieldname:%s\n",idx_1017,stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname);
	                        }
	                        // if(stmt_spy->help_select_field > 0)
	                        // {
	                        //     total_field_len = __ORA_SESSION->mask_field->length - (total_field_cursor + sizeof(short));
	                        //      memcpy(__ORA_SESSION->mask_field->str + total_field_cursor, &total_field_len, sizeof(short));
	                        // }
						}
						else
#endif
					{
							if(stmt_spy->help_select_field > 0)
							{
								u_char alias_len = 0;
								(*(short*)__ORA_SESSION->mask_field->str)++;
								if(__ORA_SESSION->mask_field->length == 0)
									__ORA_SESSION->mask_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
								total_field_cursor = __ORA_SESSION->mask_field->length;
								__ORA_SESSION->mask_field->length =  __ORA_SESSION->mask_field->length + sizeof(short);

								(*(short*)__ORA_SESSION->mask_table_field->str)++;
								if(__ORA_SESSION->mask_table_field->length == 0)
									__ORA_SESSION->mask_table_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
								total_field_cursor = __ORA_SESSION->mask_table_field->length;
								__ORA_SESSION->mask_table_field->length =  __ORA_SESSION->mask_table_field->length + sizeof(short);
							
							}
						for(idx_1017=0; idx_1017<stmt_spy->help_select_field; idx_1017++)
						{
							if(idx_1017 >= ORANET_MAX_COLUMNCOUNT)
								break;
							if(idx_1017 != 0)
							{
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)",", strlen((char*)","));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)",", strlen((char*)","));
							}
							// if(__ORA_SESSION->nonneed_table != 1)
							// {
							// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
							// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)".", strlen((char*)"."));
							// }
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)".", strlen((char*)"."));

							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
								(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
								stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field,
								(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
								stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
							OraNet_DumpSql("net8_fielddesc[%d].fieldname:%s\n",idx_1017,stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname);
						}
						if(stmt_spy->help_select_field > 0)
						{
							total_field_len = __ORA_SESSION->mask_field->length - (total_field_cursor + sizeof(short));
							memcpy(__ORA_SESSION->mask_field->str + total_field_cursor, &total_field_len, sizeof(short));
							total_field_len = __ORA_SESSION->mask_table_field->length - (total_field_cursor + sizeof(short));
							memcpy(__ORA_SESSION->mask_table_field->str + total_field_cursor, &total_field_len, sizeof(short));
						}
						}
                    }
                    if(__ORA_SESSION->spy_field_result == 2)
                    {
                    	OraNet_DumpSql("ni hao 2\n");
                    	ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
                        if(ret>0)
                        {
                            if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
                            {
                            	memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
                            	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
                            	int idx = 0;
                            	for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
                            	{
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            		memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            	}
                            }
                            __ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
                            ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
                                (char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
                                ((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
							attention_cnt = 0;
                        }
                        if(__ORA_SESSION->table_index == 0)
                       		__ORA_SESSION->spy_field_result = 3;
                        goto client2server;
                    }
                    if(__ORA_SESSION->spy_field_result == 3)
                    {
						__ORA_SESSION->help_last_ack_errorno = 0;
                	    ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult_Table(__ORA_SESSION,NULL,0);
						((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
                        ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
						__ORA_SESSION->is_spy_flag = 0x00;
						__ORA_SESSION->spy_field_result = 0;
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
						memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
						memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
						__ORA_SESSION->table_index = 0;
						__ORA_SESSION->nonneed_table = 0;
						goto client2server;
                    }
					/* end */
								if(__ORA_SESSION->more_sql_spy_noend)
                        			goto receive_client_and_server;
                                if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT))
                                {
                                    if((((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp>0) && (((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp != DBFW_MYSQL_RESP_EOF_1))
                                    {
                                        /* 应答包还没有处理结束 */
                                        //continue;
										/* bug 12318, 出现字段后没有eof包 */
										if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp == DBFW_MYSQL_RESP_RESULTSETROW && ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag == 1)
										{}
										else
                                        	goto receive_client_and_server;
                                    }
                                    /* SPY SQL的应答包已经处理完成了 */
                                    /* 使用应答包解析的结果来构造最终的SQL语句 */

                                    OraNet_DumpSql("process server->client for SPY\n");
									OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n", __ORA_SESSION->help_last_ack_errorno);
									OraNet_DumpSql("__ORA_SESSION->need_spy_count:%d\n",__ORA_SESSION->need_spy_count);
                                    /* 检查是否应答包是错误包(SPY语句执行结果是失败) */
                                    if(__ORA_SESSION->help_last_ack_errorno != 0)
                                    {
										/* t.*,t.a */
										OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
										OraNet_DumpSql("__ORA_SESSION->mask_table_alias->length:%d\n", __ORA_SESSION->mask_table_alias->length);
										OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n", __ORA_SESSION->help_last_ack_errorno);
										if((__ORA_SESSION->help_last_ack_errorno == 1054 || __ORA_SESSION->help_last_ack_errorno == 1060)&& __ORA_SESSION->need_spy_count==0)
										{
											__ORA_SESSION->help_last_ack_errorno = 0;
											OraNet8_SqlStmtData * stmt = NULL;
											if(((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle > 0)
											{
												stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->stmp_table_hash,((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle);
											}
											else
											{
												stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->newstmt_table,((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_port);
											}
											if(stmt)
											{
												stmt->stmtCommon.error_code = 0;
												Dbfw_TypedVarData_Release(&stmt->stmtCommon.error_msg);
											}
											OraNet_DumpSql("ni hao\n");
											Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
											memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
											memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
											__ORA_SESSION->table_index = 0;
											__ORA_SESSION->nonneed_table = 0;
			#ifdef HAVE_SQL_TREE
											if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
											{
												GetTableFromSqlTree((void*)__ORA_SESSION);
											}
											else
			#endif
											{
											Dbfw_GetTableAndAlisa(__ORA_SESSION);
											}
											Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
											Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
											ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
											if(ret>0)
											{
												if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
												{
													memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
													((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
													int idx = 0;
													for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
													{
														((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
														((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
														memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
													}
												}
												__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
												ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
													(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
													((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
												attention_cnt = 0;
											}
											if(__ORA_SESSION->table_index == 0)
											{
												__ORA_SESSION->spy_field_result = 3;
											}
											else
											{
												__ORA_SESSION->spy_field_result = 2;
											}
											goto client2server;
										}
										/* end */
										else
										{
											__ORA_SESSION->help_last_ack_errorno = 0;
											/* 记录错误日志 */
											Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"SPY SQL Fail , errno=%d , errMsg=%s,dbf_runtime_type=%d",
												((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.cmd0401_header.error_no,
												((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.option_cmd0401_data.message,
												__SGA_RTBUF.data.perform_control->dbf_runtime_type
												);
											/* 失败的SPY SQL情况下跳过SQL语句改写 */
											/* 直接换回之前的STMT */
											((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
											if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
												((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
											else
												((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
											((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
											((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
											((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
											((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
											((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';

											ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
											if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
											{
												rewrite_packet.packparse_result=NPP_RESULT_BLOCKING_THROW_FORCOUNT;
											}
										}
                                    }
                                    else
                                    {
                                        ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult(__ORA_SESSION,NULL,0);
                                        /* 换回之前的STMT */
                                        ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
                                    }
                                    __ORA_SESSION->is_spy_flag = 0x00;
                                    /* 正式发送客户端的请求数据 */
                                    goto client2server;
                                }
    							else if(__ORA_SESSION->is_spy_flag==2)
    							{
                                    if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp>0)
                                    {
                                        /* 应答包还没有处理结束 */
                                        //continue;
                                        goto receive_client_and_server;
                                    }
    								
    								Copy_Stmt2TlogStmt(__ORA_SESSION);
    								ret = Dbfw_TLog_LevelSQL_Cache(&__ORA_SESSION->Tlog);
    								ret = NPP_HandleTlog(0,__ORA_SESSION);
    								
    							    /* 生成通讯包 */
                                    ret = Dbfw_SqlModifyPacket(__ORA_SESSION,(void*)tns_pack_data,(int)tns_package_size,
                                        (char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_last_bak)->stmtCommon.sql_text_ori.value,
                                        ((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_last_bak)->stmtCommon.sql_text_ori.length,0);
    								
    								/* 换回之前的stmt */
    								ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
    								__ORA_SESSION->is_spy_flag = 0x00;

    								/* 正式发送原客户端的请求数据 */
    								goto client2server;
    							}
    		#endif		/* HAVE_SQL_SPY */
    	#endif	/* HAVE_SQL_MODIFY_ENGINE */
    					}
						#ifdef ENABLE_RESULTSET_MASK
						if(check_header_ok == 0)
						{
							continue;
						}
						#endif
    						   /* 刘思成添加结束 */

                   }
#endif
                }
                else if(strcasecmp((char *)db_type,"db2")==0)
                {
#ifdef ENABLE_DB2
                    tcp_buffer_size = DB2_AddTcpPackageToBuffer(buff,len,tcp_info,DB22USER);
                    do{
                        tns_pack_data = DB2_Package_PreProcess(tcp_info,DB22USER,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
							check_header_ok = 1;
                            parse_ret = DB2_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,DB22USER,&rewrite_packet);
#ifdef HAVE_SQL_MODIFY_ENGINE
#ifdef HAVE_SQL_SPY
							if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT))
							{
								/* 正在进行SPY处理，不能执行NPP_SqlProcess */
								OraNet_DumpSql("[MYSQL RESPONSE] SPY SQL\n");
							}
							else if(__ORA_SESSION->is_spy_flag==2)
							{
								OraNet_DumpSql("[MYSQL RESPONSE] SPY SQL type 2\n");
								/* 获取中间结果集 */
							}
							else
							{
								parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
							}
#else
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
#endif	/* HAVE_SQL_SPY */
#else
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
#endif	/* HAVE_SQL_MODIFY_ENGINE */

                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#ifdef HAVE_SQL_MODIFY_ENGINE
#ifdef HAVE_SQL_SPY
                    /* 
                        在SPY模式下，不要转发通讯包到客户端 
                        重要的是检查:((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp==0 表示通讯包已经结束了
                    */
				   	OraNet_DumpSql("__ORA_SESSION->is_spy_flag:%d\n",__ORA_SESSION->is_spy_flag);
					OraNet_DumpSql("check_header_ok:%d\n",check_header_ok);
					OraNet_DumpSql("__ORA_SESSION->wait_spy_result:%d\n",__ORA_SESSION->wait_spy_result);
					OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
					OraNet_DumpSql("__ORA_SESSION->spy_sql_type:%d\n",__ORA_SESSION->spy_sql_type);
					OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n",__ORA_SESSION->help_last_ack_errorno);
					OraNet_DumpSql("((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag:%d\n",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag);
                    if(__ORA_SESSION->is_spy_flag>0 && (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag<=0 ||check_header_ok==0))
                    	goto receive_client_and_server;
					if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_field_result == 4 || __ORA_SESSION->spy_field_result == 2 || __ORA_SESSION->spy_field_result == 3) && __ORA_SESSION->wait_spy_result == 1)
						goto receive_client_and_server;
					/* t.*,t.a */
					if(__ORA_SESSION->spy_field_result == 2 || __ORA_SESSION->spy_field_result == 3)
                    {
                    	OraNet8_SqlStmtData * stmt_spy = (OraNet8_SqlStmtData *)__ORA_SESSION->stmt_for_spy;
						int idx_1017 = 0;
						int total_field_cursor = 0;
						short total_field_len = 0;
#ifdef HAVE_SQL_TREE
                        if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
						{
						if(stmt_spy->help_select_field > 0)
						{
							u_char alias_len = 0;
							/* 个数 */
							(*(short*)__ORA_SESSION->mask_field->str)++;
							if(__ORA_SESSION->mask_field->length == 0)
								__ORA_SESSION->mask_field->length = sizeof(short);
							alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&alias_len, sizeof(char));
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
	                            //total_field_cursor = __ORA_SESSION->mask_field->length;
	                            //__ORA_SESSION->mask_field->length =  __ORA_SESSION->mask_field->length + sizeof(short);
	                        }
	                        if(stmt_spy->help_select_field > 0)
	                            Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&(stmt_spy->help_select_field), sizeof(short));
	                        for(idx_1017=0; idx_1017<stmt_spy->help_select_field; idx_1017++)
							{
	                            Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
	                                (char*)&(stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len),
	                                sizeof(char));
	                            Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
	                                (char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
	                                stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
	                            OraNet_DumpSql("net8_fielddesc[%d].fieldname:%s\n",idx_1017,stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname);
	                        }
	                        // if(stmt_spy->help_select_field > 0)
	                        // {
	                        //     total_field_len = __ORA_SESSION->mask_field->length - (total_field_cursor + sizeof(short));
	                        //      memcpy(__ORA_SESSION->mask_field->str + total_field_cursor, &total_field_len, sizeof(short));
	                        // }
						}
						else
#endif
						{
							if(stmt_spy->help_select_field > 0)
							{
								u_char alias_len = 0;
								(*(short*)__ORA_SESSION->mask_field->str)++;
								if(__ORA_SESSION->mask_field->length == 0)
									__ORA_SESSION->mask_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
								total_field_cursor = __ORA_SESSION->mask_field->length;
								__ORA_SESSION->mask_field->length =  __ORA_SESSION->mask_field->length + sizeof(short);

								(*(short*)__ORA_SESSION->mask_table_field->str)++;
								if(__ORA_SESSION->mask_table_field->length == 0)
									__ORA_SESSION->mask_table_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
								total_field_cursor = __ORA_SESSION->mask_table_field->length;
								__ORA_SESSION->mask_table_field->length =  __ORA_SESSION->mask_table_field->length + sizeof(short);
							
							}
							for(idx_1017=0; idx_1017<stmt_spy->help_select_field; idx_1017++)
							{
								if(idx_1017 >= ORANET_MAX_COLUMNCOUNT)
									break;
								if(idx_1017 != 0)
								{
									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)",", strlen((char*)","));
									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)",", strlen((char*)","));
								}
								// if(__ORA_SESSION->nonneed_table != 1)
								// {
								// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
								// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)".", strlen((char*)"."));
								// }
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)".", strlen((char*)"."));

								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
									(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
									stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field,
									(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
									stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
								OraNet_DumpSql("net8_fielddesc[%d].fieldname:%s\n",idx_1017,stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname);
							}
							if(stmt_spy->help_select_field > 0)
							{
								total_field_len = __ORA_SESSION->mask_field->length - (total_field_cursor + sizeof(short));
								memcpy(__ORA_SESSION->mask_field->str + total_field_cursor, &total_field_len, sizeof(short));

								total_field_len = __ORA_SESSION->mask_table_field->length - (total_field_cursor + sizeof(short));
								memcpy(__ORA_SESSION->mask_table_field->str + total_field_cursor, &total_field_len, sizeof(short));
							}
						}
                    }
                    if(__ORA_SESSION->spy_field_result == 2)
                    {
                    	OraNet_DumpSql("ni hao 2\n");
                    	ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
                        if(ret>0)
                        {
                            if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
                            {
                            	memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
                            	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
                            	int idx = 0;
                            	for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
                            	{
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            		memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            	}
                            }
                            __ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
                            ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
                                (char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
                                ((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
							attention_cnt = 0;
                        }
                        if(__ORA_SESSION->table_index == 0)
                       		__ORA_SESSION->spy_field_result = 3;
                        goto client2server;
                    }
                    if(__ORA_SESSION->spy_field_result == 3)
                    {
						/* 这块也会出现报错的情况，暂时没处理，另外create select 的语句是不能直接改为select语句的 */
						__ORA_SESSION->help_last_ack_errorno = 0;
                	    ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult_Table(__ORA_SESSION,NULL,0);
						((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
                        ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
						__ORA_SESSION->is_spy_flag = 0x00;
						__ORA_SESSION->spy_field_result = 0;
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
						memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
						memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
						__ORA_SESSION->table_index = 0;
						__ORA_SESSION->nonneed_table = 0;
						goto client2server;
                    }
					/* end */
                    if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT))
                    {

                        /* SPY SQL的应答包已经处理完成了 */
                        /* 使用应答包解析的结果来构造最终的SQL语句 */
                        OraNet_DumpSql("process server->client for SPY\n");
                        /* 检查是否应答包是错误包(SPY语句执行结果是失败) */
                        if(__ORA_SESSION->help_last_ack_errorno != 0)
                        {
							/* t.*,t.a */
										OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
										OraNet_DumpSql("__ORA_SESSION->mask_table_alias->length:%d\n", __ORA_SESSION->mask_table_alias->length);
										OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n", __ORA_SESSION->help_last_ack_errorno);
										if(__ORA_SESSION->help_last_ack_errorno == -203)
										{
											__ORA_SESSION->help_last_ack_errorno = 0;
											OraNet8_SqlStmtData * stmt = NULL;
											if(((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle > 0)
											{
												stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->stmp_table_hash,((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle);
											}
											else
											{
												stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->newstmt_table,((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_port);
											}
											if(stmt)
											{
												stmt->stmtCommon.error_code = 0;
												Dbfw_TypedVarData_Release(&stmt->stmtCommon.error_msg);
											}
											OraNet_DumpSql("ni hao\n");
											Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
											memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
											memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
											__ORA_SESSION->table_index = 0;
											__ORA_SESSION->nonneed_table = 0;
			#ifdef HAVE_SQL_TREE
											if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
											{
												GetTableFromSqlTree((void*)__ORA_SESSION);
											}
											else
			#endif
											{
											Dbfw_GetTableAndAlisa(__ORA_SESSION);
											}
											Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
											Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
											ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
											if(ret>0)
											{
												if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
												{
													memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
													((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
													int idx = 0;
													for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
													{
														((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
														((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
														memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
													}
												}
												__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
												ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
													(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
													((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
												attention_cnt = 0;
											}
											if(__ORA_SESSION->table_index == 0)
											{
												__ORA_SESSION->spy_field_result = 3;
											}
											else
											{
												__ORA_SESSION->spy_field_result = 2;
											}
											goto client2server;
										}
										/* end */
										else
										{
							__ORA_SESSION->help_last_ack_errorno = 0;
                            /* 记录错误日志 */
                            Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"SPY SQL Fail , errno=%d , errMsg=%s",
                                ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.cmd0401_header.error_no,
                                ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.option_cmd0401_data.message
                                );
                            /* 失败的SPY SQL情况下跳过SQL语句改写 */
                            /* 直接换回之前的STMT */
                            ((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
                            if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
							else
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';

                            ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
							if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
							{
								OraNet_DumpSql("NPP_RESULT_BLOCKING_THROW_FORCOUNT\n");
								rewrite_packet.packparse_result = NPP_RESULT_BLOCKING_THROW_FORCOUNT;
							}
										}
                        }
                        else
                        {
                            ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult(__ORA_SESSION,NULL,0);
                            /* 换回之前的STMT */
                            ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
							__ORA_SESSION->result_mask = 1;
							__ORA_SESSION->spy_field_result = 4;
							__ORA_SESSION->help_last_ack_errorno = 0;
                        }
                        __ORA_SESSION->is_spy_flag = 0x00;
                        /* 正式发送客户端的请求数据 */
						OraNet_DumpSql("client2server\n");
                        goto client2server;
                    }
					else if(__ORA_SESSION->is_spy_flag==2)
					{
						Copy_Stmt2TlogStmt(__ORA_SESSION);
						ret = Dbfw_TLog_LevelSQL_Cache(&__ORA_SESSION->Tlog);
						ret = NPP_HandleTlog(0,__ORA_SESSION);
						
					    /* 生成通讯包 */
                        ret = Dbfw_SqlModifyPacket(__ORA_SESSION,(void*)tns_pack_data,(int)tns_package_size,
                            (char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_last_bak)->stmtCommon.sql_text_ori.value,
                            ((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_last_bak)->stmtCommon.sql_text_ori.length,0);
						
						/* 换回之前的stmt */
						ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
						__ORA_SESSION->is_spy_flag = 0x00;

						/* 正式发送原客户端的请求数据 */
						goto client2server;
					}
					if(__ORA_SESSION->spy_field_result == 4 && __ORA_SESSION->help_last_ack_errorno != 0)
					{
						if(__ORA_SESSION->help_last_ack_errorno != 0)	//oracle查询出来0条时报1403错误
                        {
							OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
                  			OraNet_DumpSql("__ORA_SESSION->mask_table_alias->length:%d\n", __ORA_SESSION->mask_table_alias->length);
                		    OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n", __ORA_SESSION->help_last_ack_errorno);
							if((__ORA_SESSION->help_last_ack_errorno==-203))
							{
								/* 发送这个也不行，可能需要改opnqry里的某数据，不知道，换用不整体取，开始就单表取的方法 */
								/* 先发送上一个错误请求的RDBCMM包，然后在发送语句 */
								// if(attention_cnt == 0)
								// {
								// 	for(int i=0; i<__ORA_SESSION->rewrite_net_packet->packet_num; i++)
								// 	{
								// 		if(__ORA_SESSION->rewrite_net_packet->packet_size[i] > 0)
								// 		{
								// 			__ORA_SESSION->rewrite_net_packet->packet_size[i] = 0;
								// 			ZFree(__ORA_SESSION->rewrite_net_packet->packet_data[i]);
								// 		}
								// 	}
									
								// 	__ORA_SESSION->rewrite_net_packet->packet_size[0] = 0x0a;
								// 	__ORA_SESSION->rewrite_net_packet->packet_data[0] = (u_char*)ZMalloc(__ORA_SESSION->rewrite_net_packet->packet_size[0]);
								// 	memcpy((char*)__ORA_SESSION->rewrite_net_packet->packet_data[0],(char*)db2_rdbcmm, 10);
								// 	__ORA_SESSION->rewrite_net_packet->packet_num = 1;
								// 	attention_cnt = 1;

								// 	goto client2server;
								// }
								// attention_cnt = 0;
								__ORA_SESSION->help_last_ack_errorno = 0;
								OraNet8_SqlStmtData * stmt = NULL;
								if(((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle > 0)
								{
									stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->stmp_table_hash,((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle);
								}
								else
								{
									stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->newstmt_table,((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_port);
								}
								if(stmt)
								{
									stmt->stmtCommon.error_code = 0;
									Dbfw_TypedVarData_Release(&stmt->stmtCommon.error_msg);
								}
								OraNet_DumpSql("ni hao\n");
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
								memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
								memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
								__ORA_SESSION->table_index = 0;
								__ORA_SESSION->nonneed_table = 0;

								Dbfw_GetTableAndAlisa(__ORA_SESSION);
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
								ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,1);
								if(ret>0)
								{
									if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
									{
										OraNet_DumpSql("tcpbuff_bak is null\n");
										memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
										((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
										int idx = 0;
										for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
										{
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
											memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
										}
									}
									__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
									ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
										(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
										((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
									attention_cnt = 0;
								}
								if(__ORA_SESSION->table_index == 0)
								{
									__ORA_SESSION->spy_field_result = 3;
								}
								else
								{
									__ORA_SESSION->spy_field_result = 2;
								}
								goto client2server;
							}
							else
							{
								
								__ORA_SESSION->spy_field_result = 0;

								rewrite_packet.packparse_result=NPP_RESULT_BLOCKING_THROW_FORCOUNT;

							}
                        }
                        
                        /* 正式发送客户端的请求数据 */
						OraNet_DumpSql(" ###### client2server #####\n");
                        //goto client2server;	
					}
					
		#endif		/* HAVE_SQL_SPY */
	#endif	/* HAVE_SQL_MODIFY_ENGINE */
#endif
                }
                else if(strcasecmp((char *)db_type,"dameng")==0)
                {
#ifdef ENABLE_DM
                    tcp_buffer_size = DM_AddTcpPackageToBuffer(buff,len,tcp_info,DM2USER);
                    do{
                        tns_pack_data = DM_Package_PreProcess(tcp_info,DM2USER,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
	#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
	#endif
                            parse_ret = DM_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,DM2USER,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }
				else if (strcasecmp((char *)db_type,"pstgre")==0)
				{
#ifdef ENABLE_PGSQL
					tcp_buffer_size = PG_AddTcpPackageToBuffer(buff,len,tcp_info,PG2USER);
					do{
						tns_pack_data = PG_Package_PreProcess(tcp_info,PG2USER,(u_int*)&tns_package_size);
						if(tns_package_size>0)
						{
	#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
	#endif
							check_header_ok = 1;
							parse_ret = PG_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,PG2USER,&rewrite_packet);
	#ifdef HAVE_SQL_MODIFY_ENGINE
		#ifdef HAVE_SQL_SPY
							if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT))
							{
								/* 正在进行SPY处理，不能执行NPP_SqlProcess */
								OraNet_DumpSql("[MYSQL RESPONSE] SPY SQL\n");
							}
							else if(__ORA_SESSION->is_spy_flag==2)
							{
								OraNet_DumpSql("[MYSQL RESPONSE] SPY SQL type 2\n");
								/* 获取中间结果集 */
								//parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
							}
							else
							{
								parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
							}
		#else
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
		#endif  /* HAVE_SQL_SPY */
	#else
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
	#endif	/* HAVE_SQL_MODIFY_ENGINE */
							if(rewrite_packet.packparse_result==NPP_RESULT_SWITCHOFF || rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
							__ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF || __ORA_SESSION->help_parse_result==NPP_RESULT_BLOCKING_THROW)
								__ORA_SESSION->respon_switchoff_moresql = NPP_RESULT_SWITCHOFF;

							//parse_ret = 1;
							if(tns_pack_data!=NULL)
								ZFree(tns_pack_data);
						}
					}
					while(tns_package_size>0);
#endif 
#ifdef HAVE_SQL_MODIFY_ENGINE
	#ifdef HAVE_SQL_SPY
					/* 
						在SPY模式下，不要转发通讯包到客户端 
						重要的是检查:((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp==0 表示通讯包已经结束了
					*/
					OraNet_DumpSql("__ORA_SESSION->is_spy_flag:%d\n",__ORA_SESSION->is_spy_flag);
					OraNet_DumpSql("check_header_ok:%d\n",check_header_ok);
					OraNet_DumpSql("__ORA_SESSION->wait_spy_result:%d\n",__ORA_SESSION->wait_spy_result);
					OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
					OraNet_DumpSql("__ORA_SESSION->spy_sql_type:%d\n",__ORA_SESSION->spy_sql_type);
					OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n",__ORA_SESSION->help_last_ack_errorno);
					if(__ORA_SESSION->is_spy_flag>0 && (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag<=0 ||check_header_ok==0 || __ORA_SESSION->wait_spy_result == 1))
						goto receive_client_and_server;
					if(__ORA_SESSION->spy_field_result == 4 && __ORA_SESSION->is_spy_flag == 0 && __ORA_SESSION->wait_spy_result == 1 && __ORA_SESSION->help_last_ack_errorno == 0)
					{
						/* 处理整体spy，返回字段和结束 包不在一个tcp的情况 */
					}
					else if( (__ORA_SESSION->spy_field_result == 4 || __ORA_SESSION->spy_field_result == 2 || __ORA_SESSION->spy_field_result == 3) && __ORA_SESSION->wait_spy_result == 1)
						goto receive_client_and_server;
					/* t.*,t.a */
					if(__ORA_SESSION->spy_field_result == 2 || __ORA_SESSION->spy_field_result == 3)
                    {
                    	OraNet8_SqlStmtData * stmt_spy = (OraNet8_SqlStmtData *)__ORA_SESSION->stmt_for_spy;
						int idx_1017 = 0;
						int total_field_cursor = 0;
						short total_field_len = 0;
#ifdef HAVE_SQL_TREE
                        if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
						{
							if(stmt_spy->help_select_field > 0)
							{
								u_char alias_len = 0;
								/* 个数 */
								(*(short*)__ORA_SESSION->mask_field->str)++;
								if(__ORA_SESSION->mask_field->length == 0)
									__ORA_SESSION->mask_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
									//total_field_cursor = __ORA_SESSION->mask_field->length;
									//__ORA_SESSION->mask_field->length =  __ORA_SESSION->mask_field->length + sizeof(short);
	                        }
	                        if(stmt_spy->help_select_field > 0)
	                            Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&(stmt_spy->help_select_field), sizeof(short));
	                        for(idx_1017=0; idx_1017<stmt_spy->help_select_field; idx_1017++)
							{
	                            Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
	                                (char*)&(stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len),
	                                sizeof(char));
	                            Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
	                                (char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
	                                stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
	                            OraNet_DumpSql("net8_fielddesc[%d].fieldname:%s\n",idx_1017,stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname);
	                        }
	                        // if(stmt_spy->help_select_field > 0)
	                        // {
	                        //     total_field_len = __ORA_SESSION->mask_field->length - (total_field_cursor + sizeof(short));
	                        //      memcpy(__ORA_SESSION->mask_field->str + total_field_cursor, &total_field_len, sizeof(short));
	                        // }
						}
						else
#endif
						{
							OraNet_DumpSql("===spy_field_result field count:%d,stmt:%p\n",stmt_spy->help_select_field,stmt_spy);
							if(stmt_spy->help_select_field > 0)
							{
								u_char alias_len = 0;
								(*(short*)__ORA_SESSION->mask_field->str)++;
								if(__ORA_SESSION->mask_field->length == 0)
									__ORA_SESSION->mask_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
								total_field_cursor = __ORA_SESSION->mask_field->length;
								__ORA_SESSION->mask_field->length =  __ORA_SESSION->mask_field->length + sizeof(short);

								(*(short*)__ORA_SESSION->mask_table_field->str)++;
								if(__ORA_SESSION->mask_table_field->length == 0)
									__ORA_SESSION->mask_table_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
								total_field_cursor = __ORA_SESSION->mask_table_field->length;
								__ORA_SESSION->mask_table_field->length =  __ORA_SESSION->mask_table_field->length + sizeof(short);
							
							}
							for(idx_1017=0; idx_1017<stmt_spy->help_select_field; idx_1017++)
							{
								if(idx_1017 >= ORANET_MAX_COLUMNCOUNT)
									break;
								if(idx_1017 != 0)
								{
									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)",", strlen((char*)","));
									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)",", strlen((char*)","));
								}
								// if(__ORA_SESSION->nonneed_table != 1)
								// {
								// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
								// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)".", strlen((char*)"."));
								// }
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)".", strlen((char*)"."));

								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
									(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
									stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);

								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field,
									(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
									stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
								OraNet_DumpSql("net8_fielddesc[%d].fieldname:%s\n",idx_1017,stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname);
							}
							if(stmt_spy->help_select_field > 0)
							{
								total_field_len = __ORA_SESSION->mask_field->length - (total_field_cursor + sizeof(short));
								memcpy(__ORA_SESSION->mask_field->str + total_field_cursor, &total_field_len, sizeof(short));

								total_field_len = __ORA_SESSION->mask_table_field->length - (total_field_cursor + sizeof(short));
								memcpy(__ORA_SESSION->mask_table_field->str + total_field_cursor, &total_field_len, sizeof(short));
							}
						}
                    }
                    if(__ORA_SESSION->spy_field_result == 2)
                    {
                    	OraNet_DumpSql("ni hao 2\n");
                    	ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
                        if(ret>0)
                        {
                            if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
                            {
                            	memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
                            	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
                            	int idx = 0;
                            	for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
                            	{
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            		memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            	}
                            }
                            __ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
                            ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
                                (char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
                                ((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
							attention_cnt = 0;
                        }
                        if(__ORA_SESSION->table_index == 0)
                       		__ORA_SESSION->spy_field_result = 3;
                        goto client2server;
                    }
                    if(__ORA_SESSION->spy_field_result == 3)
                    {
						__ORA_SESSION->help_last_ack_errorno = 0;
                	    ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult_Table(__ORA_SESSION,NULL,0);
						((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
                        ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
						__ORA_SESSION->is_spy_flag = 0x00;
						__ORA_SESSION->spy_field_result = 0;
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
						memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
						memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
						__ORA_SESSION->table_index = 0;
						__ORA_SESSION->nonneed_table = 0;
						goto client2server;
                    }
					/* end */
					if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT) &&
					((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag>=0 && check_header_ok==1)
					{
						/* SPY SQL的应答包已经处理完成了 */
						/* 使用应答包解析的结果来构造最终的SQL语句 */

						OraNet_DumpSql("process server->client for SPY\n");
						/* 检查是否应答包是错误包(SPY语句执行结果是失败) */
						if(__ORA_SESSION->help_last_ack_errorno != 0) //oracle查询出来0条时报1403错误
						{
							/* t.*,t.a */
										OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
										OraNet_DumpSql("__ORA_SESSION->mask_table_alias->length:%d\n", __ORA_SESSION->mask_table_alias->length);
										OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n", __ORA_SESSION->help_last_ack_errorno);
										if(__ORA_SESSION->help_last_ack_errorno == 42702)
										{
											__ORA_SESSION->help_last_ack_errorno = 0;
											OraNet8_SqlStmtData * stmt = NULL;
											if(((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle > 0)
											{
												stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->stmp_table_hash,((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle);
											}
											else
											{
												stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->newstmt_table,((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_port);
											}
											if(stmt)
											{
												stmt->stmtCommon.error_code = 0;
												Dbfw_TypedVarData_Release(&stmt->stmtCommon.error_msg);
											}
											OraNet_DumpSql("ni hao\n");
											Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
											memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
											memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
											__ORA_SESSION->table_index = 0;
											__ORA_SESSION->nonneed_table = 0;
			#ifdef HAVE_SQL_TREE
											if(__ORA_SESSION->filter_sesscommon.sql_parser_tree == 1)
											{
												GetTableFromSqlTree((void*)__ORA_SESSION);
											}
											else
			#endif
											{
											Dbfw_GetTableAndAlisa(__ORA_SESSION);
											}
											Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
											Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
											ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
											if(ret>0)
											{
												if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
												{
													memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
													((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
													int idx = 0;
													for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
													{
														((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
														((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
														memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
													}
												}
												__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
												ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
													(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
													((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
												attention_cnt = 0;
											}
											if(__ORA_SESSION->table_index == 0)
											{
												__ORA_SESSION->spy_field_result = 3;
											}
											else
											{
												__ORA_SESSION->spy_field_result = 2;
											}
											goto client2server;
										}
										/* end */
										else
										{
							__ORA_SESSION->help_last_ack_errorno = 0;
							/* 记录错误日志 */
							Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"SPY SQL Fail , errno=%d , errMsg=%s",
								((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.cmd0401_header.error_no,
								((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.option_cmd0401_data.message
								);
							/* 失败的SPY SQL情况下跳过SQL语句改写 */
							/* 直接换回之前的STMT */
                            ((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
                            if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
							else
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';

							ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
							if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
									rewrite_packet.packparse_result=NPP_RESULT_BLOCKING_THROW_FORCOUNT;
										}
						}
						else
						{
							ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult(__ORA_SESSION,NULL,0);
							/* 换回之前的STMT */
							((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
							ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
							__ORA_SESSION->is_spy_flag = 0x00;
							__ORA_SESSION->spy_field_result = 4;
							__ORA_SESSION->help_last_ack_errorno = 0;
						}
						/* 正式发送客户端的请求数据 */
						goto client2server;
					}
					if(__ORA_SESSION->spy_field_result == 4 && __ORA_SESSION->help_last_ack_errorno != 0)
					{
						if(__ORA_SESSION->help_last_ack_errorno != 0)	//oracle查询出来0条时报1403错误
                        {
							OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
                  			OraNet_DumpSql("__ORA_SESSION->mask_table_alias->length:%d\n", __ORA_SESSION->mask_table_alias->length);
                		    OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n", __ORA_SESSION->help_last_ack_errorno);
							if((__ORA_SESSION->help_last_ack_errorno==42702))
							{
								__ORA_SESSION->help_last_ack_errorno = 0;
								OraNet8_SqlStmtData * stmt = NULL;
								if(((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle > 0)
								{
									stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->stmp_table_hash,((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle);
								}
								else
								{
									stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->newstmt_table,((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_port);
								}
								if(stmt)
								{
									stmt->stmtCommon.error_code = 0;
									Dbfw_TypedVarData_Release(&stmt->stmtCommon.error_msg);
								}
								OraNet_DumpSql("ni hao\n");
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
								memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
								memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
								__ORA_SESSION->table_index = 0;
								__ORA_SESSION->nonneed_table = 0;

								Dbfw_GetTableAndAlisa(__ORA_SESSION);
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
								ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,1);
								if(ret>0)
								{
									if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
									{
										OraNet_DumpSql("tcpbuff_bak is null\n");
										memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
										((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
										int idx = 0;
										for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
										{
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
											memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
										}
									}
									__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
									ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
										(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
										((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
									attention_cnt = 0;
								}
								if(__ORA_SESSION->table_index == 0)
								{
									__ORA_SESSION->spy_field_result = 3;
								}
								else
								{
									__ORA_SESSION->spy_field_result = 2;
								}
								goto client2server;
							}
							else
							{
								
								if(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak)
								{
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
									if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
									else
									{
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';
									}
								}
								
								ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
								__ORA_SESSION->help_last_ack_errorno = 0;
								__ORA_SESSION->spy_field_result = 0;
								if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
									rewrite_packet.packparse_result = NPP_RESULT_BLOCKING_THROW_FORCOUNT;

								if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
								{
									memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
									((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
									int idx = 0;
									for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
									{
										((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
										((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
										memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
									}
								}
								else
								{
									OraNet_DumpSql("tcpbuff_bak is null\n");
								}
								
								goto client2server;

							}
                        }
                        
                        /* 正式发送客户端的请求数据 */
						OraNet_DumpSql(" ###### client2server #####\n");
                        //goto client2server;	
					}
	#endif
#endif
				}
				else if (strcasecmp((char *)db_type,"kbase")==0)
				{
#ifdef ENABLE_KINGBASE
					tcp_buffer_size = PG_AddTcpPackageToBuffer(buff,len,tcp_info,PG2USER);
					do{
						tns_pack_data = PG_Package_PreProcess(tcp_info,PG2USER,(u_int*)&tns_package_size);
						if(tns_package_size>0)
						{
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
							parse_ret = PG_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,PG2USER,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
							if(tns_pack_data!=NULL)
								ZFree(tns_pack_data);
							if(rewrite_packet.packparse_result==NPP_RESULT_SWITCHOFF || rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
							__ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF || __ORA_SESSION->help_parse_result==NPP_RESULT_BLOCKING_THROW)
								__ORA_SESSION->respon_switchoff_moresql = NPP_RESULT_SWITCHOFF;
						}
					}
					while(tns_package_size>0);
#endif 
				}
                /* 2015-08-06 */
                else if(strcasecmp((char *)db_type,"oscar")==0)
                {
#ifdef ENABLE_OSCAR
                    tcp_buffer_size = OSCAR_AddTcpPackageToBuffer(buff,len,tcp_info,OSCAR2USER);
                    do{
                        tns_pack_data = OSCAR_Package_PreProcess(tcp_info,OSCAR2USER,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
                            parse_ret = OSCAR_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,OSCAR2USER,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
                            if(tns_pack_data!=NULL)
                                ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#endif
                }
				/* 2015-08-13 */
				else if(strcasecmp((char *)db_type,"ifx")==0)
				{
#ifdef ENABLE_IIF
					tcp_buffer_size = IFX_AddTcpPackageToBuffer(buff,len,tcp_info,IIF2USER);
					do{
						tns_pack_data = IFX_Package_PreProcess(tcp_info,IIF2USER,(u_int*)&tns_package_size);
#ifdef HAVE_SQL_MODIFY_ENGINE
						if(((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_cursor == 0
							&& ((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->buffer_size_tcppackage >0)
						{
							/* informix 的断包判断是在preprocess 函数，所以要设置断包，否则会转发 */
							rewrite_packet.packet_broken_flag = -1;
						}
						else
						{
							rewrite_packet.packet_broken_flag = 0;
						}
#endif

						if(tns_package_size>0)
						{
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
							check_header_ok = 1;
							parse_ret = IFX_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,IIF2USER,&rewrite_packet);
#ifdef HAVE_SQL_MODIFY_ENGINE
#ifdef HAVE_SQL_SPY
							if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT))
							{
								/* 正在进行SPY处理，不能执行NPP_SqlProcess */
								OraNet_DumpSql("[MYSQL RESPONSE] SPY SQL\n");
							}
							else if(__ORA_SESSION->is_spy_flag==2)
							{
								OraNet_DumpSql("[MYSQL RESPONSE] SPY SQL type 2\n");
								/* 获取中间结果集 */
								//parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
							}
							else
							{
								parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,IIF2USER);
							}
#else
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,IIF2USER);
#endif	/* HAVE_SQL_SPY */
#else
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,IIF2USER);
#endif	/* HAVE_SQL_MODIFY_ENGINE */
							if(tns_pack_data!=NULL)
								ZFree(tns_pack_data);
						}
					}
					while(tns_package_size>0);
#endif
#ifdef HAVE_SQL_MODIFY_ENGINE
#ifdef HAVE_SQL_SPY
					/* 
						在SPY模式下，不要转发通讯包到客户端 
						重要的是检查:((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp==0 表示通讯包已经结束了
					*/
				OraNet_DumpSql("__ORA_SESSION->is_spy_flag:%d\n",__ORA_SESSION->is_spy_flag);
					OraNet_DumpSql("check_header_ok:%d\n",check_header_ok);
					OraNet_DumpSql("__ORA_SESSION->wait_spy_result:%d\n",__ORA_SESSION->wait_spy_result);
					OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
					OraNet_DumpSql("__ORA_SESSION->spy_sql_type:%d\n",__ORA_SESSION->spy_sql_type);
					OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n",__ORA_SESSION->help_last_ack_errorno);
					if(__ORA_SESSION->is_spy_flag>0 && (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag<=0 ||check_header_ok==0))
						goto receive_client_and_server;
					/* t.*,t.a */
					if(__ORA_SESSION->spy_field_result == 2 || __ORA_SESSION->spy_field_result == 3)
                    {
                    	OraNet8_SqlStmtData * stmt_spy = (OraNet8_SqlStmtData *)__ORA_SESSION->stmt_for_spy;
						int idx_1017 = 0;
						int total_field_cursor = 0;
						short total_field_len = 0;
						if(stmt_spy->help_select_field > 0)
						{
							u_char alias_len = 0;
							/* 个数 */
							(*(short*)__ORA_SESSION->mask_field->str)++;
							if(__ORA_SESSION->mask_field->length == 0)
								__ORA_SESSION->mask_field->length = sizeof(short);
							alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&alias_len, sizeof(char));
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
							total_field_cursor = __ORA_SESSION->mask_field->length;
							__ORA_SESSION->mask_field->length =  __ORA_SESSION->mask_field->length + sizeof(short);

							(*(short*)__ORA_SESSION->mask_table_field->str)++;
							if(__ORA_SESSION->mask_table_field->length == 0)
								__ORA_SESSION->mask_table_field->length = sizeof(short);
							alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)&alias_len, sizeof(char));
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
							total_field_cursor = __ORA_SESSION->mask_table_field->length;
							__ORA_SESSION->mask_table_field->length =  __ORA_SESSION->mask_table_field->length + sizeof(short);
							
						}
						for(idx_1017=0; idx_1017<stmt_spy->help_select_field; idx_1017++)
						{
							if(idx_1017 != 0)
							{
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)",", strlen((char*)","));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)",", strlen((char*)","));
							}
							// if(__ORA_SESSION->nonneed_table != 1)
							// {
							// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
							// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)".", strlen((char*)"."));
							// }
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)".", strlen((char*)"."));

							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
								(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
								stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
							Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field,
								(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
								stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
							OraNet_DumpSql("net8_fielddesc[%d].fieldname:%s\n",idx_1017,stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname);
						}
						if(stmt_spy->help_select_field > 0)
						{
							total_field_len = __ORA_SESSION->mask_field->length - (total_field_cursor + sizeof(short));
							memcpy(__ORA_SESSION->mask_field->str + total_field_cursor, &total_field_len, sizeof(short));

							total_field_len = __ORA_SESSION->mask_table_field->length - (total_field_cursor + sizeof(short));
							memcpy(__ORA_SESSION->mask_table_field->str + total_field_cursor, &total_field_len, sizeof(short));
						}
                    }
                    if(__ORA_SESSION->spy_field_result == 2)
                    {
                    	OraNet_DumpSql("ni hao 2\n");
                    	ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
                        if(ret>0)
                        {
                            if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
                            {
                            	memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
                            	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
                            	int idx = 0;
                            	for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
                            	{
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            		memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            	}
                            }
                            __ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
                            ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
                                (char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
                                ((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
							attention_cnt = 0;
                        }
                        if(__ORA_SESSION->table_index == 0)
                       		__ORA_SESSION->spy_field_result = 3;
                        goto client2server;
                    }
                    if(__ORA_SESSION->spy_field_result == 3)
                    {
						__ORA_SESSION->help_last_ack_errorno = 0;
                	    ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult_Table(__ORA_SESSION,NULL,0);
						((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
                        ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
						__ORA_SESSION->is_spy_flag = 0x00;
						__ORA_SESSION->spy_field_result = 0;
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
						memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
						memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
						__ORA_SESSION->table_index = 0;
						__ORA_SESSION->nonneed_table = 0;
						goto client2server;
                    }
					/* end */

					if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT) &&
					((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag>=0 && check_header_ok==1)
					{
						/* SPY SQL的应答包已经处理完成了 */
						/* 使用应答包解析的结果来构造最终的SQL语句 */

						OraNet_DumpSql("process server->client for SPY\n");
						/* 检查是否应答包是错误包(SPY语句执行结果是失败) */
						if(__ORA_SESSION->help_last_ack_errorno != 0) //oracle查询出来0条时报1403错误
						{
							if((__ORA_SESSION->help_last_ack_errorno==223 || __ORA_SESSION->help_last_ack_errorno==201))
							{
								
								OraNet8_SqlStmtData * stmt = NULL;
								if(((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle > 0)
								{
									stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->stmp_table_hash,((SessBuf_SessionData_Ora*)__ORA_SESSION->sessdata)->lastused_stmt_handle);
								}
								else
								{
									stmt = (OraNet8_SqlStmtData *)ZHashGet(__ORA_SESSION->newstmt_table,((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->client_port);
								}
								if(stmt)
								{
									stmt->stmtCommon.error_code = 0;
									Dbfw_TypedVarData_Release(&stmt->stmtCommon.error_msg);
								}
								OraNet_DumpSql("ni hao\n");
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
								memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
								memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
								__ORA_SESSION->table_index = 0;
								__ORA_SESSION->nonneed_table = 0;
								Dbfw_GetTableAndAlisa(__ORA_SESSION);
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
								Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
								if(__ORA_SESSION->help_last_ack_errorno==201)
									ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
								else
									ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,1);
								if(ret>0)
								{
									if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
									{
										memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
										((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
										int idx = 0;
										for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
										{
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
											memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
										}
									}
									__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
									ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
										(char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
										((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
									attention_cnt = 0;
								}
								if(__ORA_SESSION->table_index == 0)
								{
									__ORA_SESSION->spy_field_result = 3;
								}
								else
								{
									__ORA_SESSION->spy_field_result = 2;
								}
								__ORA_SESSION->help_last_ack_errorno = 0;
								goto client2server;
							}
							else
							{
								__ORA_SESSION->help_last_ack_errorno = 0;
								/* 记录错误日志 */
								Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"SPY SQL Fail , errno=%d , errMsg=%s",
									((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.cmd0401_header.error_no,
									((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.option_cmd0401_data.message
									);
								/* 失败的SPY SQL情况下跳过SQL语句改写 */
								/* 直接换回之前的STMT */
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
								if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
								else
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';

								ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
								if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
										rewrite_packet.packparse_result=NPP_RESULT_BLOCKING_THROW_FORCOUNT;
							}
						}
						else
						{
							ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult(__ORA_SESSION,NULL,0);
							/* 换回之前的STMT */
							((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
							ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
							__ORA_SESSION->is_spy_flag = 0x00;
						}
						/* 正式发送客户端的请求数据 */
						goto client2server;
					}
#endif
#endif

				}
				else if(strcasecmp((char *)db_type,"cachdb")==0)
				{
#ifdef ENABLE_CACHEDB
					tcp_buffer_size = CacheDB_AddTcpPackageToBuffer(buff,len,tcp_info,CACHEDB2USER);
					do{
						tns_pack_data = CacheDB_Package_PreProcess(tcp_info,CACHEDB2USER,(u_int*)&tns_package_size);
						if(tns_package_size>0)
						{
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
							check_header_ok = 1;
							parse_ret = CacheDB_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,CACHEDB2USER,&rewrite_packet);
#ifdef HAVE_SQL_MODIFY_ENGINE
							if(Dbfw_ResponNeedProcess(__ORA_SESSION) == 1)
								parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,CACHEDB2USER);
#else
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,CACHEDB2USER);
#endif
							if(tns_pack_data!=NULL)
								ZFree(tns_pack_data);
						}
					}
					while(tns_package_size>0);
#endif

#ifdef HAVE_SQL_MODIFY_ENGINE
#ifdef HAVE_SQL_SPY
					/* 
						在SPY模式下，不要转发通讯包到客户端 
						重要的是检查:((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp==0 表示通讯包已经结束了
					*/
					OraNet_DumpSql("__ORA_SESSION->is_spy_flag:%d\n",__ORA_SESSION->is_spy_flag);
					OraNet_DumpSql("check_header_ok:%d\n",check_header_ok);
					OraNet_DumpSql("__ORA_SESSION->wait_spy_result:%d\n",__ORA_SESSION->wait_spy_result);
					OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
					OraNet_DumpSql("__ORA_SESSION->spy_sql_type:%d\n",__ORA_SESSION->spy_sql_type);
					OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n",__ORA_SESSION->help_last_ack_errorno);
					OraNet_DumpSql("__ORA_SESSION->mask_info.spy_mode:%d\n",__ORA_SESSION->mask_info.spy_mode);
					OraNet_DumpSql("((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag:%d\n",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag);

					/* 整体spy，当出现段包，或者tns段包没有解析，或者spy返回的数据未完整，需要再次取包 */
					if((__ORA_SESSION->mask_info.spy_mode == 2 || __ORA_SESSION->mask_info.spy_mode == 4) && (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag<=0 || check_header_ok==0 || __ORA_SESSION->wait_spy_result == 1))
						goto receive_client_and_server;
					if((__ORA_SESSION->mask_info.spy_mode == 2 || __ORA_SESSION->mask_info.spy_mode == 3) &&
					(__ORA_SESSION->mask_info.cmd == 6912 || __ORA_SESSION->mask_info.cmd == 256))
					{
						/* cachedb 当出现错误的时候，是先返回一个我错了，然后在发送请求你怎么错了，然后在返回怎么错了 */
						OraNet_DumpSql("send get error info\n");
						for(i = 0; i < socks; i++) 
						{
							select_ret = mysend(ssl_sd ? ssl_sd[i] : NULL, sd[i], cache_data,17);
						}
						((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->last_req_cmd = 20293;
		
						goto server2client;
					}
					ret = Dbfw_GetTableField_ForOneTable_All(__ORA_SESSION);
					if(ret >= 1)
						goto client2server;
					
					/* 整体取 */
					if(__ORA_SESSION->mask_info.spy_mode == 2)
					{
						if(__ORA_SESSION->help_last_ack_errorno != 0)
						{
							if(__ORA_SESSION->help_last_ack_errorno == 27 || __ORA_SESSION->help_last_ack_errorno == 1)
							{
                                OraNet_DumpSql("get dan biao \n");
								/* 走单表取逻辑 */
								ret =  Dbfw_GetTableField_ForOneTable(__ORA_SESSION,2);
								if(ret >= 1)
									goto client2server;
							}
						}
						else
						{
							ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult(__ORA_SESSION,NULL,0);
							/* 换回之前的STMT */
							((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
							ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
							__ORA_SESSION->is_spy_flag = 0x00;
							__ORA_SESSION->mask_info.spy_mode = 3;
						}
						goto client2server;
					}
					/* 整体执行 */
					if(__ORA_SESSION->mask_info.spy_mode == 3)
					{
						if(__ORA_SESSION->help_last_ack_errorno != 0)
						{
							if(__ORA_SESSION->help_last_ack_errorno == 27 || __ORA_SESSION->help_last_ack_errorno == 1)
							{
                                OraNet_DumpSql("get dan biao \n");
								/* 走单表取逻辑 */
								ret =  Dbfw_GetTableField_ForOneTable(__ORA_SESSION);
								if(ret >= 1)
									goto client2server;
							}
							else
							{
								/* 取回原语句，根据模式来决定是放行还是拦截 */
							}
						}
					}
					__ORA_SESSION->mask_info.spy_mode = 0;
#endif
#endif
				}
				else if(strcasecmp((char *)db_type,"teradata")==0)
				{
#ifdef ENABLE_TERADATA
					tcp_buffer_size = Tera_AddTcpPackageToBuffer(buff,len,tcp_info,TERA2USER);
					do{
						tns_pack_data = Tera_Package_PreProcess(tcp_info,TERA2USER,(u_int*)&tns_package_size);
						if(tns_package_size>0)
						{
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
							parse_ret = Tera_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,TERA2USER,&rewrite_packet,NULL);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,TERA2USER);
							if(rewrite_packet.packparse_result==NPP_RESULT_SWITCHOFF || rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
							__ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF || __ORA_SESSION->help_parse_result==NPP_RESULT_BLOCKING_THROW)
								__ORA_SESSION->respon_switchoff_moresql = NPP_RESULT_SWITCHOFF;
							if(tns_pack_data!=NULL)
								ZFree(tns_pack_data);
						}
					}
					while(tns_package_size>0);
#endif
				}
				else if(strcasecmp((char *)db_type,"hive")==0)
				{
#ifdef ENABLE_HIVE
					tcp_buffer_size = Hive_AddTcpPackageToBuffer(buff,len,tcp_info,HIVE2USER);
					do{
						tns_pack_data = Hive_Package_PreProcess(tcp_info,HIVE2USER,(u_int*)&tns_package_size);
						if(tns_package_size>0)
						{
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
							check_header_ok = 1;
							parse_ret = Hive_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,HIVE2USER,&rewrite_packet);
							    	#ifdef HAVE_SQL_MODIFY_ENGINE
    		#ifdef HAVE_SQL_SPY
                                    if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT))
                                    {
                                        OraNet_DumpSql("[Hive RESPONSE] SPY SQL\n");
										if(csc_tmp == 1)
										{
											memcpy(data+50, tns_pack_data+59,16);
											memcpy(data+73, tns_pack_data+82,16);
											memcpy(data1+52, tns_pack_data+59,16);
											memcpy(data1+75, tns_pack_data+82,16);
										}
                                    }
    								else if(__ORA_SESSION->is_spy_flag==2)
    								{
                                        OraNet_DumpSql("[Hive RESPONSE] SPY SQL type 2\n");
    								}
                                    else
                                    {
                                        parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
                                    }
    		#else
                                    parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
    		#endif  /* HAVE_SQL_SPY */
                                    #ifdef ENABLE_RESULTSET_MASK
									Dbsc_Mysql_Update_Header(tns_pack_data,tns_package_size);
									Dbsc_Mysql_Save_Response(__ORA_SESSION,tns_pack_data,tns_package_size);
									#endif
    	#else
    								parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
    	#endif	/* HAVE_SQL_MODIFY_ENGINE */
							if(tns_pack_data!=NULL)
								ZFree(tns_pack_data);
						}
					}
					while(tns_package_size>0);
					#ifdef HAVE_SQL_MODIFY_ENGINE
    		#ifdef HAVE_SQL_SPY
			OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
								OraNet_DumpSql("__ORA_SESSION->spy_close:%d\n",__ORA_SESSION->spy_close);
								OraNet_DumpSql("__ORA_SESSION->more_sql_spy_noend:%d\n",__ORA_SESSION->more_sql_spy_noend);
								OraNet_DumpSql("csc_tmp:%d\n",csc_tmp);
							   OraNet_DumpSql("__ORA_SESSION->is_spy_flag:%d,check_header_ok:%d,__ORA_SESSION->spy_sql_type:%d,break_flag:%d\n",__ORA_SESSION->is_spy_flag,check_header_ok,__ORA_SESSION->spy_sql_type,((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag);
                                if(__ORA_SESSION->is_spy_flag>0 && (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag<=0 ||check_header_ok==0))
                        			goto receive_client_and_server;
								if(__ORA_SESSION->more_sql_spy_noend == 1)
								{
									OraNet_DumpSql("more_sql_spy_noend\n");
                        			goto receive_client_and_server;
								}
								if(__ORA_SESSION->is_spy_flag  >0 && csc_tmp != 3)
								{
									if(csc_tmp == 1)
									{
										for(i = 0; i < socks; i++) 
										{
											select_ret = mysend(ssl_sd ? ssl_sd[i] : NULL, sd[i], data,104);
										}
										csc_tmp = 2;
									}
									else if(csc_tmp == 2)
									{	
										for(i = 0; i < socks; i++) 
										{
											select_ret = mysend(ssl_sd ? ssl_sd[i] : NULL, sd[i], data1,106);
										}
										csc_tmp = 3;
									}
									goto server2client;
								}
					// 			/* t.*,t.a */
					if(__ORA_SESSION->spy_field_result == 2 || __ORA_SESSION->spy_field_result == 3)
                    {
                    	OraNet8_SqlStmtData * stmt_spy = (OraNet8_SqlStmtData *)__ORA_SESSION->stmt_for_spy;
						int idx_1017 = 0;
						int total_field_cursor = 0;
						short total_field_len = 0;

						{
							OraNet_DumpSql("===spy_field_result field count:%d,stmt:%p\n",stmt_spy->help_select_field,stmt_spy);
							OraNet_DumpSql("table_or_alias_name len:%d\n",strlen((char*)__ORA_SESSION->table_or_alias_name));
							OraNet_DumpSql("__ORA_SESSION->mask_table_alias->length:%d\n",__ORA_SESSION->mask_table_alias->length);
							if(stmt_spy->help_select_field > 0)
							{
								u_char alias_len = 0;
								(*(short*)__ORA_SESSION->mask_field->str)++;
								if(__ORA_SESSION->mask_field->length == 0)
									__ORA_SESSION->mask_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
								total_field_cursor = __ORA_SESSION->mask_field->length;
								__ORA_SESSION->mask_field->length =  __ORA_SESSION->mask_field->length + sizeof(short);

								(*(short*)__ORA_SESSION->mask_table_field->str)++;
								if(__ORA_SESSION->mask_table_field->length == 0)
									__ORA_SESSION->mask_table_field->length = sizeof(short);
								alias_len = strlen((char*)__ORA_SESSION->table_or_alias_name);
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)&alias_len, sizeof(char));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, alias_len);
								total_field_cursor = __ORA_SESSION->mask_table_field->length;
								__ORA_SESSION->mask_table_field->length =  __ORA_SESSION->mask_table_field->length + sizeof(short);
							
							}
							for(idx_1017=0; idx_1017<stmt_spy->help_select_field; idx_1017++)
							{
								if(idx_1017 >= ORANET_MAX_COLUMNCOUNT)
									break;
								if(idx_1017 != 0)
								{
									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)",", strlen((char*)","));
									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)",", strlen((char*)","));
								}
								// if(__ORA_SESSION->nonneed_table != 1)
								// {
								// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
								// 	Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field, (char*)".", strlen((char*)"."));
								// }
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)__ORA_SESSION->table_or_alias_name, strlen((char*)__ORA_SESSION->table_or_alias_name));
								Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field, (char*)".", strlen((char*)"."));
								if(strncasecmp((char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,(char*) __ORA_SESSION->table_name, strlen((char*)__ORA_SESSION->table_name)) == 0)
								{
									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
										(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname + strlen((char*)__ORA_SESSION->table_name),
										stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len - strlen((char*)__ORA_SESSION->table_name));

									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field,
										(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname + strlen((char*)__ORA_SESSION->table_name),
										stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len - strlen((char*)__ORA_SESSION->table_name));
								}
								else
								{
									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_field,
										(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
										stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);

									Dbfw_DynStr_Append_Mem(__ORA_SESSION->mask_table_field,
										(char*)stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname,
										stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname_len);
								}
								OraNet_DumpSql("table_name:%s\n",(char*) __ORA_SESSION->table_name);
								OraNet_DumpSql("net8_fielddesc[%d].fieldname:%s\n",idx_1017,stmt_spy->cmd_1017.cmd1017_data.net8_fielddesc[idx_1017].fieldname);
							}
							if(stmt_spy->help_select_field > 0)
							{
								total_field_len = __ORA_SESSION->mask_field->length - (total_field_cursor + sizeof(short));
								memcpy(__ORA_SESSION->mask_field->str + total_field_cursor, &total_field_len, sizeof(short));

								total_field_len = __ORA_SESSION->mask_table_field->length - (total_field_cursor + sizeof(short));
								memcpy(__ORA_SESSION->mask_table_field->str + total_field_cursor, &total_field_len, sizeof(short));
							}
						}
                    }
                    if(__ORA_SESSION->spy_field_result == 2)
                    {
                    	OraNet_DumpSql("ni hao 2\n");
						csc_tmp = 1;
                    	ret = Dbfw_PrepareSqlSpy_ForFieldDetect_Table(__ORA_SESSION,2);
                        if(ret>0)
                        {
                            if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
                            {
                            	memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
                            	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
                            	int idx = 0;
                            	for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
                            	{
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            		memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            	}
                            }
                            __ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
                            ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,0,
                                (char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.value,
                                ((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->stmtCommon.sql_text_ori.length,1);
							attention_cnt = 0;
                        }
                        if(__ORA_SESSION->table_index == 0)
                       		__ORA_SESSION->spy_field_result = 3;
                        goto client2server;
                    }
                    if(__ORA_SESSION->spy_field_result == 3)
                    {
						if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
                            {
                            	memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
                            	((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
                            	int idx = 0;
                            	for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
                            	{
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
                            		((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            		memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
                            	}
                            }
						__ORA_SESSION->help_last_ack_errorno = 0;
                	    ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult_Table(__ORA_SESSION,NULL,0);
						((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
                        ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
						__ORA_SESSION->is_spy_flag = 0x00;
						__ORA_SESSION->spy_field_result = 0;
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_field,__ORA_SESSION->mask_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_field,__ORA_SESSION->mask_table_field->length);
						Dbfw_DynStr_Trunc(__ORA_SESSION->mask_table_alias,__ORA_SESSION->mask_table_alias->length);
						memset(__ORA_SESSION->table_or_alias_name,0x00, sizeof(__ORA_SESSION->table_or_alias_name));
						memset(__ORA_SESSION->table_name,0x00, sizeof(__ORA_SESSION->table_name));
						__ORA_SESSION->table_index = 0;
						__ORA_SESSION->nonneed_table = 0;
						goto client2server;
                    }
					/* end */
                                if(__ORA_SESSION->spy_close == 1 && __ORA_SESSION->is_spy_flag > 0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT))
                                {
                                    OraNet_DumpSql("process server->client for hive SPY\n");
                                    if(__ORA_SESSION->help_last_ack_errorno != 0)
                                    {
										__ORA_SESSION->help_last_ack_errorno = 0;
                                        Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"SPY SQL Fail , errno=%d , errMsg=%s",
                                            ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.cmd0401_header.error_no,
                                            ((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.option_cmd0401_data.message
                                            );
    									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
    									if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
    										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
    									else
    										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
    									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
    									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
    									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
    									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
    									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';
                                        ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
										if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
									rewrite_packet.packparse_result=NPP_RESULT_BLOCKING_THROW_FORCOUNT;
                                    }
                                    else
                                    {
										if(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[0] == NULL)
										{

											memcpy(&((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->rewriteinfo_for_request, &__ORA_SESSION->rewriteinfo_for_request, sizeof(Npp_RewriteInfoForRequestPack));
											((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tnspack_num = __ORA_SESSION->tnspack_num;
											int idx = 0;
											for(idx = 0; idx < __ORA_SESSION->tnspack_num; idx++)
											{
												((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx] = __ORA_SESSION->tcpbuff_bak_len[idx];
												((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx] = (u_char*)ZMalloc(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
												memcpy(((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak[idx], __ORA_SESSION->tcpbuff_bak[idx],((OraNet8_Session*)__ORA_SESSION)->rewrite_net_packet->tcpbuff_bak_len[idx]);
											}
										}
										__ORA_SESSION->stmt_for_sqlmodify = __ORA_SESSION->stmt_for_spy;
                                        ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult(__ORA_SESSION,NULL,0);
                                        ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
                                    }
                                    __ORA_SESSION->is_spy_flag = 0x00;
                                    goto client2server;
                                }
    							else if(__ORA_SESSION->spy_close == 1 && __ORA_SESSION->is_spy_flag==2)
    							{
    								Copy_Stmt2TlogStmt(__ORA_SESSION);
    								ret = Dbfw_TLog_LevelSQL_Cache(&__ORA_SESSION->Tlog);
    								ret = NPP_HandleTlog(0,__ORA_SESSION);
                                    ret = Dbfw_SqlModifyPacket(__ORA_SESSION,NULL,(int)tns_package_size,
                                        (char*)((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_last_bak)->stmtCommon.sql_text_ori.value,
                                        ((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_last_bak)->stmtCommon.sql_text_ori.length, 0);
    								ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
    								__ORA_SESSION->is_spy_flag = 0x00;
    								goto client2server;
    							}
								// if(__ORA_SESSION->is_spy_flag  >0)
								// {
								// 	if(csc_tmp == 1)
								// 	{
								// 		for(i = 0; i < socks; i++) 
								// 		{
								// 			select_ret = mysend(ssl_sd ? ssl_sd[i] : NULL, sd[i], data,104);
								// 		}
								// 		csc_tmp = 2;
								// 	}
								// 	else if(csc_tmp == 2)
								// 	{	
								// 		for(i = 0; i < socks; i++) 
								// 		{
								// 			select_ret = mysend(ssl_sd ? ssl_sd[i] : NULL, sd[i], data1,106);
								// 		}
								// 		csc_tmp = 3;
								// 	}
								// 	goto server2client;
								// }
    		#endif		/* HAVE_SQL_SPY */
    	#endif	/* HAVE_SQL_MODIFY_ENGINE */
#endif
				}
				else if(strcasecmp((char *)db_type,"mongodb")==0)
				{
#ifdef ENABLE_MONGODB
					tcp_buffer_size = MONGODB_AddTcpPackageToBuffer(buff,len,tcp_info,ORA2USER);
					do{
						tns_pack_data = MONGODB_Package_PreProcess(tcp_info,ORA2USER,(u_int*)&tns_package_size);
						if(tns_package_size>0)
						{
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
							void* tmp = NULL;
                        	MongoDB_Parse_Result mg_parse_result;
                			Init_MGO_Parse_Result(&mg_parse_result);
							parse_ret = MONGODB_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,ORA2USER,&mg_parse_result,&rewrite_packet,&tmp);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
							Release_MGO_Parse_Result(&mg_parse_result);
							if(tmp)
								free(tmp);
							if(tns_pack_data!=NULL)
								ZFree(tns_pack_data);
						}
					}
					while(tns_package_size>0);
#endif
				}
				else if(strcasecmp((char *)db_type,"impala")==0)
				{
#ifdef ENABLE_IMPALA
					tcp_buffer_size = Impala_AddTcpPackageToBuffer(buff,len,tcp_info,IMPALA2USER);
					do{
						tns_pack_data = Impala_Package_PreProcess(tcp_info,IMPALA2USER,(u_int*)&tns_package_size);
						if(tns_package_size>0)
						{
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
							parse_ret = Impala_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,IMPALA2USER,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,IMPALA2USER);
							if(tns_pack_data!=NULL)
								ZFree(tns_pack_data);
						}
					}
					while(tns_package_size>0);
#endif
				}
				else if(strcasecmp((char *)db_type,"hana")==0)
				{
#ifdef ENABLE_HANA
					tcp_buffer_size = Hana_AddTcpPackageToBuffer(buff,len,tcp_info,HANA2USER);
					do{
						tns_pack_data = Hana_Package_PreProcess(tcp_info,HANA2USER,(u_int*)&tns_package_size);
						if(tns_package_size>0)
						{
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
							check_header_ok = 1;
							parse_ret = Hana_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,HANA2USER,&rewrite_packet,NULL);
							//parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,HANA2USER);
	#ifdef HAVE_SQL_MODIFY_ENGINE
							if(Dbfw_ResponNeedProcess(__ORA_SESSION) == 1)
								parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,HANA2USER);
#else
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,HANA2USER);
#endif
							if(tns_pack_data!=NULL)
								ZFree(tns_pack_data);
						}
					}
					while(tns_package_size>0);
#ifdef HAVE_SQL_MODIFY_ENGINE
#ifdef HAVE_SQL_SPY
                    /* 
                        ��SPYģʽ�£���Ҫת��ͨѶ�����ͻ��� 
                        ��Ҫ���Ǽ��:((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp==0 ��ʾͨѶ���Ѿ�������
                    */
				   	OraNet_DumpSql("__ORA_SESSION->is_spy_flag:%d\n",__ORA_SESSION->is_spy_flag);
					OraNet_DumpSql("check_header_ok:%d\n",check_header_ok);
					OraNet_DumpSql("__ORA_SESSION->wait_spy_result:%d\n",__ORA_SESSION->wait_spy_result);
					OraNet_DumpSql("__ORA_SESSION->spy_field_result:%d\n",__ORA_SESSION->spy_field_result);
					OraNet_DumpSql("__ORA_SESSION->spy_sql_type:%d\n",__ORA_SESSION->spy_sql_type);
					OraNet_DumpSql("__ORA_SESSION->help_last_ack_errorno:%d\n",__ORA_SESSION->help_last_ack_errorno);
					OraNet_DumpSql("__ORA_SESSION->mask_info.spy_mode:%d\n",__ORA_SESSION->mask_info.spy_mode);
					OraNet_DumpSql("((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag:%d\n",((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag);
					if((__ORA_SESSION->mask_info.spy_mode == 2 || __ORA_SESSION->mask_info.spy_mode == 4) && (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag<=0 || check_header_ok==0 /* || __ORA_SESSION->wait_spy_result == 1*/))
						goto receive_client_and_server;
                    //if(__ORA_SESSION->is_spy_flag>0 && (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag<=0 ||check_header_ok==0))
                    //	goto receive_client_and_server;
					ret = Dbfw_GetTableField_ForOneTable_All(__ORA_SESSION);
					if(ret >= 1)
						goto client2server;
					OraNet_DumpSql("next\n");
					/* 整体取 */
					if(__ORA_SESSION->mask_info.spy_mode == 2)
					{
						if(__ORA_SESSION->help_last_ack_errorno != 0)
						{
							if(__ORA_SESSION->help_last_ack_errorno == 268|| __ORA_SESSION->help_last_ack_errorno == 259)
							{
								/* 走单表取逻辑 */
								ret =  Dbfw_GetTableField_ForOneTable(__ORA_SESSION,2);
								if(ret >= 1)
									goto client2server;
							}
							else
							{
								/* 执行原语句 */
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
								if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
								else
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';
								ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
								if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
									rewrite_packet.packparse_result=NPP_RESULT_BLOCKING_THROW_FORCOUNT;
								__ORA_SESSION->mask_info.spy_mode = 0;
								__ORA_SESSION->is_spy_flag = 0;
								__ORA_SESSION->wait_spy_result= 0;
								__ORA_SESSION->spy_field_result = 0;
								__ORA_SESSION->help_last_ack_errorno = 0;
								__ORA_SESSION->spy_sql_type = 0;
							}
						}
						else
						{
							ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult(__ORA_SESSION,NULL,0);
							/* 换回之前的STMT */
							((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
							ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
							__ORA_SESSION->is_spy_flag = 0x00;
							__ORA_SESSION->mask_info.spy_mode = 3;
						}
						goto client2server;
					}
					/* 整体执行 */
					if(__ORA_SESSION->mask_info.spy_mode == 3)
					{
						if(__ORA_SESSION->help_last_ack_errorno != 0)
						{
							if(__ORA_SESSION->help_last_ack_errorno == 268)
							{
								/* 走单表取逻辑 */
								ret =  Dbfw_GetTableField_ForOneTable(__ORA_SESSION);
								if(ret >= 1)
									goto client2server;
							}
							else
							{
								/* 取回原语句，根据模式来决定是放行还是拦截 */
								if(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak)
								{
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
									if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
									else
										((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
									((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';
								}
								ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
								if(__sync_fetch_and_add(&__SGA_RTBUF.data.perform_control->dbf_runtime_type, 0) == DBF_RUNTIME_TYPE_HOLDON)
									rewrite_packet.packparse_result=NPP_RESULT_BLOCKING_THROW_FORCOUNT;
								__ORA_SESSION->mask_info.spy_mode = 0;
								__ORA_SESSION->is_spy_flag = 0;
								__ORA_SESSION->wait_spy_result= 0;
								__ORA_SESSION->spy_field_result = 0;
								__ORA_SESSION->help_last_ack_errorno = 0;
								__ORA_SESSION->spy_sql_type = 0;
							}
						}
					}
					__ORA_SESSION->mask_info.spy_mode = 0;
					

#endif		/* HAVE_SQL_SPY */
#endif	/* HAVE_SQL_MODIFY_ENGINE */
#endif
				}
				else if(strcasecmp((char *)db_type,"gausst")==0)
                {
#ifdef ENABLE_GAUSSDB_T
                    tcp_buffer_size = GaussdbT_AddTcpPackageToBuffer(buff,len,tcp_info,GAUSSDB2USER);
                    do{
                        tns_pack_data = GaussdbT_Package_PreProcess(tcp_info,GAUSSDB2USER,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
							check_header_ok = 1;
                            parse_ret = GaussdbT_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,GAUSSDB2USER,&rewrite_packet,NULL);
#ifdef HAVE_SQL_MODIFY_ENGINE
#ifdef HAVE_SQL_SPY
							if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT))
							{
								/* 正在进行SPY处理，不能执行NPP_SqlProcess */
								OraNet_DumpSql("[MYSQL RESPONSE] SPY SQL\n");
							}
							else if(__ORA_SESSION->is_spy_flag==2)
							{
								OraNet_DumpSql("[MYSQL RESPONSE] SPY SQL type 2\n");
								/* 获取中间结果集 */
								//parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,ORA2USER);
							}
							else
							{
								parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,GAUSSDB2USER);
							}
#else
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,GAUSSDB2USER);
#endif	/* HAVE_SQL_SPY */
#else
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,GAUSSDB2USER);
#endif	/* HAVE_SQL_MODIFY_ENGINE */
                            if(tns_pack_data!=NULL)
                            ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
					#ifdef HAVE_SQL_MODIFY_ENGINE
#ifdef HAVE_SQL_SPY
					/* 
						在SPY模式下，不要转发通讯包到客户端 
						重要的是检查:((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp==0 表示通讯包已经结束了
					*/
					if(__ORA_SESSION->is_spy_flag>0 && (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag<=0 ||check_header_ok==0))
						goto receive_client_and_server;
					if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT) &&
					((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag>=0 && check_header_ok==1)
					{
						/* SPY SQL的应答包已经处理完成了 */
						/* 使用应答包解析的结果来构造最终的SQL语句 */

						OraNet_DumpSql("process server->client for SPY\n");
						/* 检查是否应答包是错误包(SPY语句执行结果是失败) */
						if(__ORA_SESSION->help_last_ack_errorno != 0) //oracle查询出来0条时报1403错误
						{
							/* 记录错误日志 */
							Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"SPY SQL Fail , errno=%d , errMsg=%s",
								((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.cmd0401_header.error_no,
								((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.option_cmd0401_data.message
								);
							/* 失败的SPY SQL情况下跳过SQL语句改写 */
							/* 直接换回之前的STMT */
                            ((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
                            if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
							else
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';

							ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
						}
						else
						{
							ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult(__ORA_SESSION,NULL,0);
							/* 换回之前的STMT */
							((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
							ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
							__ORA_SESSION->is_spy_flag = 0x00;
						}
						/* 正式发送客户端的请求数据 */
						goto client2server;
					}
#endif
#endif
#endif
                }
				else if(strcasecmp((char *)db_type,"redis")==0)
				{
#ifdef ENABLE_REDIS
					tcp_buffer_size = Redis_AddTcpPackageToBuffer(buff,len,tcp_info,REDIS2USER);
					do{
						tns_pack_data = Redis_Package_PreProcess(tcp_info,REDIS2USER,(u_int*)&tns_package_size);
						if(tns_package_size>0)
						{
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
							parse_ret = Redis_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,REDIS2USER,&rewrite_packet);
							parse_ret = NPP_SqlProcess(&rewrite_packet,__ORA_SESSION,REDIS2USER);
							if(rewrite_packet.packparse_result==NPP_RESULT_SWITCHOFF || rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW ||
							__ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF || __ORA_SESSION->help_parse_result==NPP_RESULT_BLOCKING_THROW)
								__ORA_SESSION->respon_switchoff_moresql = NPP_RESULT_SWITCHOFF;
							if(tns_pack_data!=NULL)
								ZFree(tns_pack_data);
						}
					}
					while(tns_package_size>0);
#endif
				}
                else if(strcasecmp((char *)db_type,"zk")==0)
                {
#ifdef ENABLE_ZK
                    tcp_buffer_size = ZooKeeper_AddTcpPackageToBuffer(buff,len,tcp_info,ZK2USER);
                    do{
                        tns_pack_data = ZooKeeper_Package_PreProcess(tcp_info,ZK2USER,(u_int*)&tns_package_size);
                        if(tns_package_size>0)
                        {
#if defined(HAVE_CHERRY) || defined(NEW_TAMPER_FORPROXY)
                            /* 测试篡改返回包 */
                            if(buff_cursor<len)
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff+buff_cursor;
                            else
                                __ORA_SESSION->tamper_data_addr = (u_char*)buff;
#endif
                            check_header_ok = 1;
                            parse_ret = ZooKeeper_PackageParse(tns_pack_data,tns_package_size,0,0,tcp_info,ZK2USER,&rewrite_packet,NULL);

                            if(tns_pack_data!=NULL)
                            ZFree(tns_pack_data);
                        }
                    }
                    while(tns_package_size>0);
#ifdef HAVE_SQL_MODIFY_ENGINE
                    #ifdef HAVE_SQL_SPY
					/*
						在SPY模式下，不要转发通讯包到客户端
						重要的是检查:((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->mysql_help_hasresp==0 表示通讯包已经结束了
					*/
					if(__ORA_SESSION->is_spy_flag>0 && (((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag<=0 ||check_header_ok==0))
						goto receive_client_and_server;
					if(__ORA_SESSION->is_spy_flag>0 && (__ORA_SESSION->spy_sql_type==SPY_SQL_TYPE_FIELD_DETECT) &&
					((SessBuf_SessionData_Ora *)(__ORA_SESSION->sessdata))->break_flag>=0 && check_header_ok==1)
					{
						/* SPY SQL的应答包已经处理完成了 */
						/* 使用应答包解析的结果来构造最终的SQL语句 */

						OraNet_DumpSql("process server->client for SPY\n");
						/* 检查是否应答包是错误包(SPY语句执行结果是失败) */
						if(((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.cmd0401_header.error_no!=0) //oracle查询出来0条时报1403错误
						{
							/* 记录错误日志 */
							Npp_LogError_Format(-1,-1,__FILE__, __LINE__, __FUNCTION__,(char*)"SPY SQL Fail , errno=%d , errMsg=%s",
								((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.cmd0401_header.error_no,
								((OraNet8_SqlStmtData*)(__ORA_SESSION->stmt_for_spy))->cmd_040x.option_cmd0401_data.message
								);
							/* 失败的SPY SQL情况下跳过SQL语句改写 */
							/* 直接换回之前的STMT */
                            ((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.rule_id = 0;
                            if(__NPP_ALL_CONFIG->s_aud_switch == 1 || __NPP_ALL_CONFIG->risk_mode==DBFW_RUNMODE_LEARN)
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '1';
							else
								((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_audit = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.blackorwhite = 0;
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_control = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.result_delevery = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level = '0';
							((OraNet8_SqlStmtData*)(((OraNet8_Session*)__ORA_SESSION)->stmt_last_bak))->stmtCommon.threat_level_bmj = '8';

							ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
						}
						else
						{
							ret = Dbfw_MakeMaskSqlModifyPack_WithFieldDetectResult(__ORA_SESSION,NULL,0);
							/* 换回之前的STMT */
							((OraNet8_SqlStmtData*)__ORA_SESSION->stmt_for_spy)->sqlspy_result = 0x00;
							ret = Dbfw_GetBackStmt_ForSpySql(__ORA_SESSION);
							__ORA_SESSION->is_spy_flag = 0x00;
						}
						/* 正式发送客户端的请求数据 */
						goto client2server;
					}
#endif
#endif
#endif
                }
				else
                {
                    /* unknow */
                }
                /* 2013-7-16：在收到了来自服务器的通讯包的情况下，需要在接收后，继续检查是否有后续的通讯包 */
                //i = i - 1;
            }
            
			/* TODO 登陆风险校验*/
			ret = NPP_ConnectFilter(__ORA_SESSION,&rewrite_packet);
			/* 传入标记:登陆校验、
				传出:
			*/

			/* 处理tlog*/
			ret = NPP_HandleTlog(0,__ORA_SESSION);
			
			
			/* 
                新版本的拦截阻断处理方法(NEW_TAMPER_FORPROXY)
                由于是串联方式，所以包是完整的，直接篡改包头即可
                如果rewrite_packet.tnspack_isfull==0x01表是通讯包缓冲区已经满了，则不能进行篡改，这里可以不进行判断，原因是前面进行了goto server2client处理
            */
            OraNet_DumpSql("rewrite_packet.packparse_result:%d,__ORA_SESSION->help_parse_result:%d,rewrite_packet.is_switchoff:%d,__ORA_SESSION->tamper_template_size:%d\n",rewrite_packet.packparse_result,__ORA_SESSION->help_parse_result,rewrite_packet.is_switchoff,__ORA_SESSION->tamper_template_size);
            if(rewrite_packet.packparse_result==NPP_RESULT_SWITCHOFF || rewrite_packet.packparse_result==NPP_RESULT_SWITCHOFF_FORCOUNT||
            	__ORA_SESSION->help_parse_result == NPP_RESULT_SWITCHOFF || __ORA_SESSION->respon_switchoff_moresql == NPP_RESULT_SWITCHOFF)
            {
                /* 
                    阻断 
                    1:S->C的情况下，应该先将通讯包发出后，再断连接
                */
#ifdef DEBUG_CHERRY
                printf("[S->C] / ProxyMode]OraTnsPackageParse result is switchoff\n");
#endif
#ifdef HAVE_CHERRY
				if(__ORA_SESSION->tamper_template_size>0)
				{
					/* 有篡改包模板(目前只支持Oracle数据库) */
					__ORA_SESSION->help_tamper_flag=DBFW_TAMPER_THROW;
					__ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
					if(ha)
					{
						nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
					}
					/* 发送篡改后的通讯包 */
					for(i = 0; i < socks; i++) 
					{
						if(multi_skip && multi_skip[i]) continue;
						//for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
						{
							//printf("rewrite_packet.tcpbuff_bak_len[%d] = %d\n",j,rewrite_packet.tcpbuff_bak_len[j]);
							{
								select_ret = mysend(ssl_sd[i], sd[i], __ORA_SESSION->tamper_template_data, __ORA_SESSION->tamper_template_size);
							}
							if(select_ret <= 0) 
							{
#ifdef WIN32
								Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
								Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                
								MULTI_SKIP_QUIT
							}
						}
					}
					if(ha)
					{
						nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
					}
				}
#else
                if(buff_cursor<len)
                {
                    select_ret = mysend(ssl_sock, sock, buff+buff_cursor, (len-buff_cursor));
                    if(select_ret <= 0) 
                    {
#ifdef WIN32
                        Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sock);
#else
                        Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sock);
#endif                        
                        goto quit;
                    }
                }
#endif
                rewrite_packet.is_switchoff = 1;
                goto quit;
            }
            else if(rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW || rewrite_packet.packparse_result==NPP_RESULT_BLOCKING_THROW_FORCOUNT ||
                 __ORA_SESSION->help_parse_result == NPP_RESULT_BLOCKING_THROW || __ORA_SESSION->respon_switchoff_moresql == NPP_RESULT_BLOCKING_THROW)
            {
                /* 抛异常，目前暂不支持对应答包的拦截，只能支持阻断 */
#ifdef DEBUG_CHERRY
                printf("[S->C] / ProxyMode]OraTnsPackageParse result is throw -> Switchoff\n");
#endif
                if(__ORA_SESSION->tamper_template_size>0)
                {
                    /* 有篡改包模板(目前只支持Oracle数据库) */
                    __ORA_SESSION->help_tamper_flag=DBFW_TAMPER_THROW;
                    __ORA_SESSION->need_tamper = 1; /* 设置当前包被篡改标记 */
					if(ha)
					{
						nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
					}
                    /* 发送篡改后的通讯包 */
                    for(i = 0; i < socks; i++) 
                    {
                        if(multi_skip && multi_skip[i]) continue;
                        //for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                        {
                            //printf("rewrite_packet.tcpbuff_bak_len[%d] = %d\n",j,rewrite_packet.tcpbuff_bak_len[j]);
                            {
                                select_ret = mysend(ssl_sd[i], sd[i], __ORA_SESSION->tamper_template_data, __ORA_SESSION->tamper_template_size);
                            }
                            if(select_ret <= 0) 
                            {
#ifdef WIN32
                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                
                                MULTI_SKIP_QUIT
                            }
                        }
                    }
					if(ha)
					{
						nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
					}
                }
#ifdef HAVE_CHERRY
                 rewrite_packet.is_switchoff = 1;
                 goto quit;
#endif
            }
			else if(__ORA_SESSION->enc_broken == 1)
            {
            		if(__ORA_SESSION->enc_broken == 1)
            		{
            			OraNet_DumpSql("enc but broken!!!!\n");
            		}else{
                    
                    /* 是重构的新的重定向包 */


                    if(__ORA_SESSION->help_dynaport_env.redirect_package_size_ext2 > 0)
                    
                    for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                    {
                        ZFree(rewrite_packet.tcpbuff_bak[j]);
                        rewrite_packet.tcpbuff_bak_len[j] = 0;
                    }
                    rewrite_packet.tnspack_num = 0;
#ifdef HAVE_SQL_MODIFY_ENGINE
                    /* 准备SQL改写和MASK的数据 */
                    __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
                    /* 清理包改写信息 */
                    Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
                    /* 清理包改写信息 */
                    //memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
#endif
                }
            }
            
//            else if(__ORA_SESSION->enc_tamper_pkg_len > 0)
//            {
//                OraNet_DumpSql("__ORA_SESSION->enc_tamper_pkg_len:%d\n",__ORA_SESSION->enc_tamper_pkg_len);

//                {
//                    
//                    /* 是重构的新的重定向包 */
//                    //if(__ORA_SESSION->help_dynaport_env.redirect_package_size>0)
//                    {
//                        if(ha)
//                        {
//                            nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
//                        }
//                        
//                        {
//						if(ha)
//						{
//							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
//						}
//	                    select_ret = mysend(ssl_sock, sock, __ORA_SESSION->enc_tamper_pkg, __ORA_SESSION->enc_tamper_pkg_len);
//	                    if(select_ret <= 0) 
//	                    {
//#ifdef WIN32
//	                        Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sock);
//#else
//	                        Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sock);
//#endif                        
//	                        goto quit;
//	                    }
//						if(ha)
//						{
//							nppproxy_unregister(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
//						}
//	                }
//                        ZFree(__ORA_SESSION->enc_tamper_pkg);
//                        __ORA_SESSION->enc_tamper_pkg = NULL;
//                        __ORA_SESSION->enc_tamper_pkg_len = 0;
//                        
//                        
//                        
//                        if(ha)
//                        {
//                            nppproxy_unregister(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
//                        }
//                    }

//                    if(__ORA_SESSION->help_dynaport_env.redirect_package_size_ext2 > 0)
//                    
//                    for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
//                    {
//                        ZFree(rewrite_packet.tcpbuff_bak[j]);
//                        rewrite_packet.tcpbuff_bak_len[j] = 0;
//                    }
//                    rewrite_packet.tnspack_num = 0;
//#ifdef HAVE_SQL_MODIFY_ENGINE
//                    /* 准备SQL改写和MASK的数据 */
//                    __ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
//                    /* 清理包改写信息 */
//                    Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
//                    /* 清理包改写信息 */
//                    //memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
//#endif
//                }
//            }
#ifdef HAVE_DYNAPORT
            else if(__ORA_SESSION->is_redirect_pack==1)
            {
            	if(__ORA_SESSION->redirect_break_flag == 1)
            	{
            		/* redirect package break, wait for next tcp package, do nothing */
            	}
            	else
            	{
	            	 /* 是重构的新的重定向包 */
	                if(__ORA_SESSION->help_dynaport_env.redirect_package_size_ext>0)
	                {
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
	                    select_ret = mysend(ssl_sock, sock, __ORA_SESSION->help_dynaport_env.redirect_package_data_ext, __ORA_SESSION->help_dynaport_env.redirect_package_size_ext);
	                    if(select_ret <= 0) 
	                    {
#ifdef WIN32
	                        Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sock);
#else
	                        Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sock);
#endif                        
	                        goto quit;
	                    }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
	                }
	                /* 是重构的新的重定向包 */
	                if(__ORA_SESSION->help_dynaport_env.redirect_package_size>0)
	                {
						if(ha)
						{
							nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}
	                    select_ret = mysend(ssl_sock, sock, __ORA_SESSION->help_dynaport_env.redirect_package_data, __ORA_SESSION->help_dynaport_env.redirect_package_size);
	                    if(select_ret <= 0) 
	                    {
#ifdef WIN32
                        Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sock);
#else
                        Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sock);
#endif                        
	                        goto quit;
	                    }
						if(ha)
						{
							nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
						}

		                if(__ORA_SESSION->help_dynaport_env.redirect_package_size>0)
						{
							ZFree(__ORA_SESSION->help_dynaport_env.redirect_package_data);
							__ORA_SESSION->help_dynaport_env.redirect_package_size = 0;
						}
						if(__ORA_SESSION->help_dynaport_env.redirect_package_size_ext>0)
						{
							ZFree(__ORA_SESSION->help_dynaport_env.redirect_package_data_ext);
							__ORA_SESSION->help_dynaport_env.redirect_package_size_ext= 0;
						}
						if(__ORA_SESSION->help_dynaport_env.ori_package_size_ext>0)
						{
							ZFree(__ORA_SESSION->help_dynaport_env.ori_package_data_ext);
							__ORA_SESSION->help_dynaport_env.ori_package_size_ext= 0;
						}
						if(__ORA_SESSION->help_dynaport_env.ori_package_size>0)
					    {
					        ZFree(__ORA_SESSION->help_dynaport_env.ori_package_data);
					        __ORA_SESSION->help_dynaport_env.ori_package_size = 0;
					    }
		                __ORA_SESSION->is_redirect_pack = 0;
                	}
                }
            }
#endif
            else    /* 与SQL改写包处理有关的逻辑结束 */
            {
				#if defined HAVE_SQL_MODIFY_ENGINE and defined ENABLE_RESULTSET_MASK
				if(rewrite_packet.packet_num>0)
				{
					if(ha)
					{
						nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
					}
					/* 有改写包 */
					OraNet_DumpSql("~~~~~~~~~have response modify packet~~~~~~~~~~~~~~\n");
					OraNet_DumpSql("rewrite_packet.packet_num = %d\n",rewrite_packet.packet_num);
					/* 使用改写后的通讯包发送到服务器 */
					for(j=0;j<rewrite_packet.packet_num;j++)   /* 发送所有包到Server */
					{
						OraNet_DumpSql("send rewrite_packet to server : rewrite_packet.packet_num[%d] = %d\n",j,rewrite_packet.packet_size[j]);
						select_ret = mysend(ssl_sock, sock, rewrite_packet.packet_data[j], rewrite_packet.packet_size[j]);
						if(select_ret <= 0) 
						{
							#ifdef WIN32
							Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sock);
							#else
							Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sock);
							#endif
							goto quit;
						}
						ZFree(rewrite_packet.packet_data[j]);
						rewrite_packet.packet_data[j] = NULL;
						rewrite_packet.packet_size[j] = 0;
					}
					rewrite_packet.packet_num = 0;
					/* 准备SQL改写和MASK的数据 */
					__ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
				}
				else
				{
				#endif
                /* 将来自DB的通讯包返回Client */
				if(rewrite_packet.tnspack_num>0)
				{
					if(__SGA_AC_XSEC_DATABASE->dialect == DBFW_DBTYPE_ORACLE)
						encryp_pkg(__ORA_SESSION, ORA2USER);
					for(j=0;j<rewrite_packet.tnspack_num;j++)   /* 发送所有包到Server */
                        {
                            OraNet_DumpSql("s->c rewrite_packet.tcpbuff_bak_len[%d] = %d\n",j,rewrite_packet.tcpbuff_bak_len[j]);
                            {
                                select_ret = mysend(ssl_sock, sock, rewrite_packet.tcpbuff_bak[j], rewrite_packet.tcpbuff_bak_len[j]);
                            }
                            if(select_ret <= 0) 
                            {
#ifdef WIN32
                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#else
                                Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sd[i]);
#endif                                
                                MULTI_SKIP_QUIT
                            }
                            ZFree(rewrite_packet.tcpbuff_bak[j]);
                            rewrite_packet.tcpbuff_bak_len[j] = 0;
                        }
                        rewrite_packet.tnspack_num = 0;
					if(ha)
					{
						nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
					}
				}
				else
				{
                /* 将来自DB的通讯包返回Client */
                if(buff_cursor<len)
                {
					if(ha)
					{
						nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
					}
                    select_ret = mysend(ssl_sock, sock, buff+buff_cursor, (len-buff_cursor));
                    if(select_ret <= 0) 
                    {
#ifdef WIN32
                        Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,select_ret,__FILE__, __LINE__, __FUNCTION__,sock);
#else
                        Npp_Exception_WithLog(NPP_ERROR_NETWORK_SEND_FAIL,errno,__FILE__, __LINE__, __FUNCTION__,sock);
#endif                        
                        goto quit;
                    }
					if(ha)
					{
						nppproxy_unregister_with_freetis(tis,__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
					}
					}
                }
				#if defined HAVE_SQL_MODIFY_ENGINE and defined ENABLE_RESULTSET_MASK
				}
				#endif
                if(rewrite_packet.is_switchoff==1 && (rewrite_packet.packet_type&0x0400) >0)
                {
                    /* 由于在发送exception包后，Oracle和client之间会交互remark包，因此需要判断最后一次包的类型是否是0x04xx（应答包） */
                    /* 断开连接 */
                    OraNet_DumpSql("============switch off====================\n");
                    goto quit;
                }
				if(rewrite_packet.is_switchoff==1 && (rewrite_packet.packet_type&0x04) >0)
				{
						/* 由于在发送exception包后，Oracle和client之间会交互remark包，因此需要判断最后一次包的类型是否是0x04xx（应答包） */
						/* 断开连接 */
					OraNet_DumpSql("============switch off====================\n");
					goto quit;
				}
            }
            
        }
    }

quit:
	if(ha)
	{
		nppproxy_register(__NPP_ALL_CONFIG->sessionid_fornpc,sga_proxy_flag);
		/* 判断proxy 是否退出 */
		pDbfw_Sga_Sess_ArrayItem p_sess_array_item = NULL;
		p_sess_array_item = Dbfw_Sga_Sess_BindSessArrayItem(__SGA_SESSBUF, __ORA_SESSION->help_session_id);
		if(p_sess_array_item->proxy_pid!=0)
		{
			int my_errno;
			int ret = 0;
			ret = Dbfw_CheckProcessExists(p_sess_array_item->proxy_pid);
			my_errno = errno;
			if(ret < 0) 
			{    
				if(my_errno == ESRCH)
				{     
					Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" nppproxy has quit, sock will clear nppproxy tis, nppproxy pid = %d",p_sess_array_item->proxy_pid);				
				}
				else 
				{    
					Npp_LogError_Format(ret,-1,__FILE__, __LINE__, __FUNCTION__,(char *)" check nppproxy pid exception errno(%d), nppproxy pid = %d",my_errno,p_sess_array_item->proxy_pid);
				}							
			}
			Tis_Slot_Close(tis,__NPP_ALL_CONFIG->sessionid_fornpc);
		}

	}
	//npp退出不再处理tis，由proxy统一处理tis
//	
#ifdef ENABLE_SSL
	if(ssl_sock)
	{
		SSL_shutdown(ssl_sock);
		SSL_free(ssl_sock);
	}
	if(ctx_sock)
		SSL_CTX_free(ctx_sock);
    for(i = 0; i < socks; i++) 
	{
		if(ssl_sd[i])
		{
                SSL_shutdown(ssl_sd[i]);
                SSL_free(ssl_sd[i]);
            }
		if(ctx_2server[i])
		{
			SSL_CTX_free(ctx_2server[i]);
        }
        }
#endif

    if(krb_enc_buff && krb_enc_buff_size > 0)
    {
        ZFree(krb_enc_buff);
    }
    close(sock);
    for(i = 0; i < socks; i++) {
        close(sd[i]);
    }
    if(sd)
        ZFree(sd);
    if(rewrite_packet.packet_num>0)
    {
        for(i=0;i<rewrite_packet.packet_num;i++)
        {
            if(rewrite_packet.packet_size[i]>0)
                ZFree(rewrite_packet.packet_data[i]);
            rewrite_packet.packet_size[i] = 0;
        }        
    }
    rewrite_packet.packet_num = 0;

    if(rewrite_packet.tnspack_num>0)
    {
        for(i=0;i<rewrite_packet.tnspack_num;i++)
        {
            if(rewrite_packet.tcpbuff_bak_len[i]>0)
                ZFree(rewrite_packet.tcpbuff_bak[i]);
            rewrite_packet.tcpbuff_bak_len[i] = 0;
        }        
    }
    rewrite_packet.tnspack_num = 0;
#ifdef HAVE_SQL_MODIFY_ENGINE
    /* 准备SQL改写和MASK的数据 */
    //__ORA_SESSION->rewrite_net_packet = (Npp_RewriteNetPacket*)&rewrite_packet;
    /* 清理包改写信息 */
    //Dbfw_ResetRewriteInfoForRequestPack(__ORA_SESSION);
	/* 清理包改写信息 */
	memset(&rewrite_packet.rewriteinfo_for_request,0x00,sizeof(rewrite_packet.rewriteinfo_for_request));
#endif
	if(__ORA_SESSION && (__ORA_SESSION->filter_sesscommon.s_uss_switch == 1))
	{
		Send_Close_Session(__ORA_SESSION);
	}

    if(strcasecmp((char *)db_type,"oracle")==0)
    {
        /* Oracle */
        OraNet8_CloseSession(tcp_info);
    }
    else if(strcasecmp((char *)db_type,"mssql")==0)
    {
        /* MSSQL */
		OraNet8_CloseSession(tcp_info);
    }
    else if(strcasecmp((char *)db_type,"mysql")==0)
    {
        /* MYSQL */
        OraNet8_CloseSession(tcp_info);
    }
    else if(strcasecmp((char *)db_type,"db2")==0)
    {
        /* DB2 */
        OraNet8_CloseSession(tcp_info);
    }
    else if(strcasecmp((char *)db_type,"dameng")==0)
    {
        /* 达梦 */
        OraNet8_CloseSession(tcp_info);
    }
	else if(strcasecmp((char *)db_type,"pstgre") ==0)
	{
		/*Postgree*/
		OraNet8_CloseSession(tcp_info); 
	}
	else if(strcasecmp((char *)db_type,"kbase") ==0)
	{
		/*Kingbase*/
		OraNet8_CloseSession(tcp_info); 
	}
    else if(strcasecmp((char *)db_type,"oscar") ==0)
    {
        /*oscar*/
        OraNet8_CloseSession(tcp_info); 
    }    
	else if(strcasecmp((char *)db_type,"ifx") ==0)
	{
		/*informix*/
		OraNet8_CloseSession(tcp_info); 
	} 
	else if(strcasecmp((char *)db_type,"cachdb") ==0)
	{
		/*cachedb*/
		OraNet8_CloseSession(tcp_info); 
	}
	else if(strcasecmp((char *)db_type,"hive") ==0)
	{
		/*hive*/
		OraNet8_CloseSession(tcp_info); 
	}    
	else if(strcasecmp((char *)db_type,"teradata") ==0)
	{
		/*teradata*/
		OraNet8_CloseSession(tcp_info); 
	}
	else if(strcasecmp((char *)db_type,"mongodb") ==0)
	{
		/*momgodb*/
		OraNet8_CloseSession(tcp_info); 
	} 
	else if(strcasecmp((char *)db_type,"impala") ==0)
	{
		/*impala*/
		OraNet8_CloseSession(tcp_info); 
	}
	else if(strcasecmp((char *)db_type,"hana") ==0)
	{
		/*hana*/
		OraNet8_CloseSession(tcp_info); 
	}
    else if(strcasecmp((char *)db_type,"gausst") ==0)
    {
        /*hana*/
        OraNet8_CloseSession(tcp_info);
    }
	else if(strcasecmp((char *)db_type,"redis") ==0)
	{
		/*teradata*/
		OraNet8_CloseSession(tcp_info); 
	}
    else
    {
        /* unknow */
    }
#ifdef HAVE_LUA
    if(L)
    	lua_close(L);
#endif
    ZFree(tcp_info);
    if(multi_skip) free(multi_skip);
    if(dump_fd) fclose(dump_fd);
    if(buff) ZFree(buff);
#ifdef DUMP_TCPDATA
    fclose(dump_tcpdata);
#endif
    #ifdef ENABLE_DBSCLOUD
	dbsc_custom_exit();
	#endif
    if(max_connections > 0) {
        INTERLOCK_DEC(cur_connections);
    }






//    	keep_interval = 20;
#endif
    }
    










void xor_data(unsigned char *data, int size) {
    while(size--) *data++ ^= XORBYTE;
}



int array_connect(int sd, in_addr_all *ip, sockaddr_in_all *ipport, sockaddr_in_all *peer, int idx) {
	int     i;
	int length = 0;
	if(AF_INET6 == __SOCK_TYPE)
	{
		length = sizeof(struct sockaddr_in6);
	}else{
		length = sizeof(struct sockaddr_in);
	}

	for(i = idx; ; i++) {
		if(ip) {			
			if(AF_INET6 == __SOCK_TYPE)
			{
				if(!ip[i].in6.s6_addr32[0] && !ip[i].in6.s6_addr32[1]
					 && !ip[i].in6.s6_addr32[2] && !ip[i].in6.s6_addr32[3]) return(-1);
				peer->in6.sin6_addr = ip[i].in6;
			}else{
				if(ip[i].in.s_addr) return(-1);
				peer->in.sin_addr.s_addr = ip[i].in.s_addr;
			}
		} else if(ipport) {
			if(AF_INET6 == __SOCK_TYPE)
			{
				if(!ipport[i].in6.sin6_addr.s6_addr32[0] && !ipport[i].in6.sin6_addr.s6_addr32[1]
					 && !ipport[i].in6.sin6_addr.s6_addr32[2] && !ipport[i].in6.sin6_addr.s6_addr32[3]) return(-1);
				peer->in6.sin6_addr = ipport[i].in6.sin6_addr;
				peer->in6.sin6_port        = ipport[i].in6.sin6_port;
			}else{
				if(!ipport[i].in.sin_addr.s_addr) return(-1);
				peer->in.sin_addr.s_addr = ipport[i].in.sin_addr.s_addr;
				peer->in.sin_port        = ipport[i].in.sin_port;
			}
		}
		/* add by yanghaifeng@schina.cn */
		//fprintf(stderr, "Client %s:%hu\n", inet_ntoa(ipport->sin_addr), ntohs(ipport->sin_port));
		//fprintf(stderr, "Server %s:%hu\n", inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
		/* add end */
		if(connect(sd, (struct sockaddr *)peer, length) < 0) continue;
		break;
	}
	//printf("array_connect ok\n");
	return(0);
}

sockaddr_in_all *create_peer_array(unsigned char *list, u16 default_port) {
	sockaddr_in_all *ret;
	int     i,
			size = 1;
	u16     port;
	unsigned char      *p1,*p2;
	in_addr_all addr;

	for(p2 = list; (p1 = (unsigned char*)strchr((char *)p2, ',')); size++, p2 = p1 + 1);

	ret = (sockaddr_in_all*)calloc(size + 1, sizeof(sockaddr_in_all));
	if(!ret) std_err();

	for(i = 0;;) {
		p1 = (unsigned char *)strchr((char *)list, ',');
		if(p1) *p1 = 0;

		port = default_port;
		//不再切分port，为了兼容IPV6，且没有这种场景
//		p2 = (unsigned char *)strchr((char *)list, ':');
//		if(p2) {
//			*p2 = 0;
//			port = atoi((char*)p2 + 1);
//		}

		while(*list == ' ') list++;
		if(AF_INET6 == __SOCK_TYPE)
		{			
			resolv((char*)list, (in_addr_all*)&ret[i].in6.sin6_addr);
			ret[i].in6.sin6_port        = htons(port);
			ret[i].in6.sin6_family      = AF_INET6;
		}else{
			resolv((char*)list, (in_addr_all*)&ret[i].in.sin_addr);
			ret[i].in.sin_port        = htons(port);
			ret[i].in.sin_family      = AF_INET;
		}

		i++;
		if(!p1) break;
		list = p1 + 1;
	}
	return(ret);
}

void get_sock_ip_port(int sd, u16 *port, in_addr_all *ip) {
	sockaddr_in_all  peer;
	int         psz;

	psz = sizeof(sockaddr_in_all);
	if(getsockname(sd, (struct sockaddr *)&peer, (socklen_t*)&psz)
			< 0) std_err();

	if(AF_INET6 == __SOCK_TYPE)
	{
		if(port) *port = ntohs(peer.in6.sin6_port);
		if(ip) memcpy(&(ip->in6), &(peer.in6.sin6_addr), sizeof(peer.in6.sin6_addr));
	}else{
		if(port) *port = ntohs(peer.in.sin_port);
		if(ip) memcpy(&(ip->in), &(peer.in.sin_addr.s_addr), sizeof(peer.in.sin_addr.s_addr));
	}	
}

void get_peer_ip_port(int sd, u16 *port, in_addr_all *ip) {
	sockaddr_in_all  peer;
	int         psz;

	psz = sizeof(sockaddr_in_all);
	if(getpeername(sd, (struct sockaddr *)&peer, (socklen_t*)&psz) < 0) {
//		peer.sin_addr.s_addr = 0;                   // avoids possible problems
//		peer.sin_port        = 0;
			memset(&peer, 0x0, sizeof(peer));
	}

	if(AF_INET6 == __SOCK_TYPE)
	{
		if(port) *port = ntohs(peer.in6.sin6_port);
		if(ip) memcpy(&(ip->in6), &(peer.in6.sin6_addr), sizeof(peer.in6.sin6_addr));
	}else{
		if(port) *port = ntohs(peer.in.sin_port);
		if(ip) memcpy(&(ip->in), &(peer.in.sin_addr.s_addr), sizeof(peer.in.sin_addr.s_addr));
	}
}



void resolv(char *host, in_addr_all *host_ip) {
	struct      hostent *hp;

	if(inet_pton(__SOCK_TYPE, host, host_ip) != 1) {
		fprintf(stderr, "  resolve hostname %s\n", host);
		hp = gethostbyname2(host, __SOCK_TYPE);
		if(!hp) {
			fprintf(stderr, "\nError: Unable to resolve hostname (%s)\n", host);
			exit(1);
		} else *host_ip = *(in_addr_all *)hp->h_addr;
	}
//	return(host_ip);
}


#ifndef WIN32
    void std_err(void) {
        perror("\nError");
        exit(1);
    }
#endif


