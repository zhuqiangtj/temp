void handle_connections(int sock, int sd_one, int *sd_array, int ha, char *client_mac_str,char *oracle_server_mac_str,char *oracle_server_ip_str, u_short init_session) {


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