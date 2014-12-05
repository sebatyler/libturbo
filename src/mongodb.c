//vim:ts=8

/** @file mongodb.c
    몽고DB 사용 위한 함수들
*/

#include "turbo.h"

/** @fn void	tb_close_mongodb (mongo * mongodb, time_t * mongodb_conn_time)
    @brief	몽고DB 연결 해제
    @param	mongodb			몽고DB connection
    @param	mongodb_conn_time	몽고DB connection 맺은 시간
*/
void	tb_close_mongodb (mongo * mongodb, time_t * mongodb_conn_time)
{
	if (mongodb)
		mongo_destroy(mongodb) ;

	*mongodb_conn_time = 0 ;
}

/** @fn mongo *	tb_open_mongodb_with_auth (server_rec * s, mongo * mongodb, time_t * mongodb_conn_time, const char * host, int port, const char * db, const char * user, const char * password, int timeout, int alive_time)
    @brief	몽고DB 서버 연결 & 인증
    @param	s			server_rec. 메모리 할당, 에러 로깅
    @param	mongodb			이전 몽고DB connection. NULL 이어도 연결함
    @param	mongodb_conn_time	이전 몽고DB connection 맺은 시간
    @param	host			연결할 몽고DB 서버 host
    @param	port			연결할 몽고DB 서버 port
    @param	db			인증할 DB명
    @param	user			인증할 사용자
    @param	password		인증할 사용자 비밀번호
    @param	timeout			connection timeout. ms 단위
    @param	alive_time		connection alive time. s 단위이며 이전 연결 맺은 이후에 해당 시간 만큼 지나면 강제로 연결 끊고 다시 연결 시도함
    @return	연결한 mongodb. 실패시 NULL 반환
*/
mongo *	tb_open_mongodb_with_auth (server_rec * s, mongo * mongodb, time_t * mongodb_conn_time, const char * host, int port, const char * db, const char * user, const char * password, int timeout, int alive_time)
{
	if (! host)
		return	mongodb ;

	time_t		now = time(NULL) ;
	if (*mongodb_conn_time == 0)
		*mongodb_conn_time = now ;

	if (mongodb)
	{
		/* 커넥션 맺은지 alive_time(초) 경과했거나 커넥션 체크 실패시 커넥션 끊고 다시 커넥션 맺기 */
		if (*mongodb_conn_time + alive_time < now || mongo_check_connection(mongodb) != MONGO_OK)
		{
			if (0)
				TB_LOGS_INFO(s, "%s: mongodb reconnect start: host: %s before:%ld now:%ld", __FUNCTION__, host, *mongodb_conn_time, now) ;

			tb_close_mongodb(mongodb, mongodb_conn_time) ;

			mongodb = NULL ;
			*mongodb_conn_time = now ;
		}
		/* 커넥션 살아있으므로 return */
		else
			return	mongodb ;
	}

	int		try = 3 ;
	int		i = 0 ;
	int		connected = 0 ;

	mongodb = apr_pcalloc(s->process->pool, sizeof(mongo)) ;
	mongo_init(mongodb) ;

	do {
		i++ ;
		if (mongo_set_op_timeout(mongodb, timeout) != MONGO_OK)
		{
			TB_LOGS_ERROR(s, "%s: mongodb set_op_timeout error: [%d] [%s]", __FUNCTION__, mongodb->err, mongodb->errstr) ;
			continue ;
		}

		if (mongo_client(mongodb, host, port) != MONGO_OK)
		{
			TB_LOGS_ERROR(s, "%s: mongodb connect error: [%d] [%s]", __FUNCTION__, mongodb->err, mongodb->errstr) ;
			continue ;
		}

		if (db && user && password)
		{
			if (mongo_cmd_authenticate(mongodb, db, user, password) != MONGO_OK)
			{
				TB_LOGS_ERROR(s, "%s: mongodb auth error: db: %s user: %s password: %s [%d] [%s]", __FUNCTION__, db, user, password, mongodb->err, mongodb->errstr) ;
				tb_close_mongodb(mongodb, mongodb_conn_time) ;
				continue ;
			}
		}

		TB_LOGS_INFO(s, "%s: mongodb connected: host: %s %d %d (%ld)", __FUNCTION__, host, port, mongodb->sock, *mongodb_conn_time) ;

		connected = 1 ;

	} while (!connected && i < try) ;

	/* 실패시 끊기 */
	if (connected == 0)
	{
		tb_close_mongodb(mongodb, mongodb_conn_time) ;
		return	NULL ;
	}

	if (*mongodb_conn_time == 0)
		*mongodb_conn_time = now ;

	return	mongodb ;
}

/** @fn mongo *	tb_open_mongodb (server_rec * s, mongo * mongodb, time_t * mongodb_conn_time, const char * host, int port, int timeout, int alive_time)
    @brief	몽고DB 서버 연결
    @param	s			server_rec. 메모리 할당, 에러 로깅
    @param	mongodb			이전 몽고DB connection. NULL 이어도 연결함
    @param	mongodb_conn_time	이전 몽고DB connection 맺은 시간
    @param	host			연결할 몽고DB 서버 host
    @param	port			연결할 몽고DB 서버 port
    @param	timeout			connection timeout. ms 단위
    @param	alive_time		connection alive time. s 단위이며 이전 연결 맺은 이후에 해당 시간 만큼 지나면 강제로 연결 끊고 다시 연결 시도함
    @return	연결한 mongodb. 실패시 NULL 반환
*/
mongo *	tb_open_mongodb (server_rec * s, mongo * mongodb, time_t * mongodb_conn_time, const char * host, int port, int timeout, int alive_time)
{
	return	tb_open_mongodb_with_auth(s, mongodb, mongodb_conn_time, host, port, NULL, NULL, NULL, timeout, alive_time) ;
}

/** @fn bson *	tb_bson_init (request_rec * r, apr_array_header_t * bson_array)
    @brief	bson 할당하고 일괄 해제 위해 array push
    @param	r		request_rec. 메모리 할당
    @param	bson_array	bson push 할 array. 일괄 해제는 직접 구현해야함
    @return	할당한 bson 포인터
*/
bson *	tb_bson_init (request_rec * r, apr_array_header_t * bson_array)
{
	bson *	b = apr_pcalloc(r->pool, sizeof(bson)) ;
	bson_init(b) ;

	if (bson_array)
		APR_ARRAY_PUSH(bson_array, bson *) = b ;

	return	b ;
}

/** @fn void	tb_bson_finish (request_rec * r, bson * b)
    @brief	bson 완료 처리. mongo 함수 호출 하기 전에 반드시 호출해야함
    @param	r	request_rec. 에러 로깅
    @param	b	bson
*/
void	tb_bson_finish (request_rec * r, bson * b)
{
	if (bson_finish(b) != BSON_OK)
		TB_LOG_ERROR(r, "%s: bson_finish error: %d", __FUNCTION__, b->err) ;
}

/** @fn int	tb_bson_int (bson * bson, const char * field, int def)
    @brief	bson에서 integer 값 읽기
    @param	bson	bson
    @param	field	필드명
    @param	def	기본값
    @return	읽은 integer 값
*/
int	tb_bson_int (bson * bson, const char * field, int def)
{
	if (!bson || !field)
		return	def ;

	bson_iterator	it ;
	if (bson_find(&it, bson, field))
		return	bson_iterator_int(&it) ;

	return	def ;
}

/** @fn time_t	tb_bson_time_t (bson * bson, const char * field, time_t def)
    @brief	bson에서 time_t 값 읽기
    @param	bson	bson
    @param	field	필드명
    @param	def	기본값
    @return	읽은 time_t 값
*/
time_t	tb_bson_time_t (bson * bson, const char * field, time_t def)
{
	if (!bson || !field)
		return	def ;

	bson_iterator	it ;
	if (bson_find(&it, bson, field))
		return	bson_iterator_time_t(&it) ;

	return	def ;
}

/** @fn const char *	tb_bson_string (bson * bson, const char * field, const char * def)
    @brief		bson에서 문자열 읽기
    @param		bson	bson
    @param		field	필드명
    @param		def	기본값
    @return		읽은 문자열
*/
const char *	tb_bson_string (bson * bson, const char * field, const char * def)
{
	if (!bson || !field)
		return	def ;

	bson_iterator	it ;
	if (bson_find(&it, bson, field))
		return	bson_iterator_string(&it) ;

	return	def ;
}

/** @fn bson_oid_t *	tb_bson_oid (bson * bson, const char * field)
    @brief		bson에서 oid 읽기
    @param		bson	bson
    @param		field	필드명
    @return		읽은 oid
*/
bson_oid_t *	tb_bson_oid (bson * bson, const char * field)
{
	if (!bson || !field)
		return	NULL ;

	bson_iterator	it ;
	if (bson_find(&it, bson, field))
		return	bson_iterator_oid(&it) ;

	return	NULL ;
}

/** @fn mongo_cursor *	tb_mongo_find_cursor (mongo * mongodb, const char * namespace, bson * query, bson * field, int limit, int skip, int options, apr_array_header_t * mongo_cursor_array)
    @brief	몽고DB 조회하고 cursor 가져오기
    @param	mongodb			몽고DB connection
    @param	namespace		조회할 namespace. [DB명].[컬렉션명] 형태. e.g.) blackjack.audition
    @param	query			조회 조건 bson
    @param	field			조회 필드 bson
    @param	limit			limit
    @param	skip			skip
    @param	options			몽고DB 조회 옵션
    @param	mongo_cursor_array	cursor push 할 array. 일괄 해제는 직접 구현해야함
    @return	cursor. 실패시 NULL 반환
*/
mongo_cursor *	tb_mongo_find_cursor (mongo * mongodb, const char * namespace, bson * query, bson * field, int limit, int skip, int options, apr_array_header_t * mongo_cursor_array)
{
	if (!mongodb || !namespace)
		return	NULL ;

	mongo_cursor *	cursor = mongo_find(mongodb, namespace, query, field, limit, skip, options) ;
	if (! cursor)
		return	NULL ;

	if (mongo_cursor_array)
		APR_ARRAY_PUSH(mongo_cursor_array, mongo_cursor *) = cursor ;

	return	cursor ;
}

/** @fn int	tb_mongo_cursor_int (mongo_cursor * cursor, const char * field, int def)
    @brief	cursor에서 integer 값 읽기
    @param	cursor	cursor
    @param	field	필드명
    @param	def	기본값
    @return	읽은 integer 값
*/
int	tb_mongo_cursor_int (mongo_cursor * cursor, const char * field, int def)
{
	if (! cursor)
		return	def ;

	return	tb_bson_int(&cursor->current, field, def) ;
}

/** @fn time_t	tb_mongo_cursor_time_t (mongo_cursor * cursor, const char * field, time_t def)
    @brief	cursor에서 time_t 값 읽기
    @param	cursor	cursor
    @param	field	필드명
    @param	def	기본값
    @return	읽은 time_t 값
*/
time_t	tb_mongo_cursor_time_t (mongo_cursor * cursor, const char * field, time_t def)
{
	if (! cursor)
		return	def ;

	return	tb_bson_time_t(&cursor->current, field, def) ;
}

/** @fn const char *	tb_mongo_cursor_string (mongo_cursor * cursor, const char * field, const char * def)
    @brief		cursor에서 문자열 읽기
    @param		cursor	cursor
    @param		field	필드명
    @param		def	기본값
    @return		읽은 문자열
*/
const char *	tb_mongo_cursor_string (mongo_cursor * cursor, const char * field, const char * def)
{
	if (! cursor)
		return	def ;

	return	tb_bson_string(&cursor->current, field, def) ;
}

/** @fn bson_oid_t *	tb_mongo_cursor_oid (mongo_cursor * cursor, const char * field)
    @brief		cursor에서 oid 읽기
    @param		cursor	cursor
    @param		field	필드명
    @return		읽은 oid
*/
bson_oid_t *	tb_mongo_cursor_oid (mongo_cursor * cursor, const char * field)
{
	if (! cursor)
		return	NULL ;

	return	tb_bson_oid(&cursor->current, field) ;
}

/** @fn const char *	tb_bson_to_string_raw (apr_pool_t * pool, const char * data, int depth)
    @brief		bson을 문자열로 변환. depth 지정 가능 함수
    @param		pool	메모리 할당 풀
    @param		data	bson data. bson->data
    @param		depth	depth
    @return		문자열
*/
const char *	tb_bson_to_string_raw (apr_pool_t * pool, const char * data, int depth)
{
	if (! data)
		return	"" ;

	bson_iterator		i ;
	const char *		key ;
	int			temp ;
	bson_timestamp_t	ts ;
	char			oidhex[25] ;
	bson			scope;
	apr_array_header_t *	a = apr_array_make(pool, 8, sizeof(char *)) ;
	bson_iterator_from_buffer(&i, data) ;

	while (bson_iterator_next(&i))
	{
		bson_type t = bson_iterator_type(&i);
		if (t == 0)
			break;

		key = bson_iterator_key( &i );

		for ( temp=0; temp<=depth; temp++ )
			APR_ARRAY_PUSH(a, char *) =  "\t" ;
		APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "%s : %d \t ", key, t) ;
		switch ( t ) {
			case BSON_DOUBLE:
				APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "%f" , bson_iterator_double( &i ) );
				break;
			case BSON_STRING:
				APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "%s" , bson_iterator_string( &i ) );
				break;
			case BSON_SYMBOL:
				APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "SYMBOL: %s" , bson_iterator_string( &i ) );
				break;
			case BSON_OID:
				bson_oid_to_string( bson_iterator_oid( &i ), oidhex );
				APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "%s" , oidhex );
				break;
			case BSON_BOOL:
				APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "%s" , bson_iterator_bool( &i ) ? "true" : "false" );
				break;
			case BSON_DATE:
				APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "%ld" , ( long int )bson_iterator_date( &i ) );
				break;
			case BSON_BINDATA:
				APR_ARRAY_PUSH(a, char *) = "BSON_BINDATA" ;
				break;
			case BSON_UNDEFINED:
				APR_ARRAY_PUSH(a, char *) = "BSON_UNDEFINED" ;
				break;
			case BSON_NULL:
				APR_ARRAY_PUSH(a, char *) = "BSON_NULL" ;
				break;
			case BSON_REGEX:
				APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "BSON_REGEX: %s", bson_iterator_regex( &i ) );
				break;
			case BSON_CODE:
				APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "BSON_CODE: %s", bson_iterator_code( &i ) );
				break;
			case BSON_CODEWSCOPE:
				APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "BSON_CODE_W_SCOPE: %s", bson_iterator_code( &i ) );
				bson_iterator_code_scope_init( &i, &scope, 0 );
				APR_ARRAY_PUSH(a, char *) = "\n\t SCOPE: " ;
				APR_ARRAY_PUSH(a, const char *) = tb_bson_to_string(pool, &scope) ;
				bson_destroy( &scope );
				break;
			case BSON_INT:
				APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "%d" , bson_iterator_int( &i ) );
				break;
			case BSON_LONG:
				APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "%ld" , ( uint64_t )bson_iterator_long( &i ) );
				break;
			case BSON_TIMESTAMP:
				ts = bson_iterator_timestamp( &i );
				APR_ARRAY_PUSH(a, char *) = apr_psprintf(pool, "i: %d, t: %d", ts.i, ts.t );
				break;
			case BSON_OBJECT:
			case BSON_ARRAY:
				APR_ARRAY_PUSH(a, char *) = "\n" ;
				APR_ARRAY_PUSH(a, const char *) = tb_bson_to_string_raw(pool, bson_iterator_value(&i), depth + 1) ;
				break;
			default:
				fprintf(stderr, "%s: can't print type : %d\n", __FUNCTION__, t) ;
		}
		APR_ARRAY_PUSH(a, char *) = ( "\n" );
	}

	return	apr_array_pstrcat(pool, a, 0) ;
}

/** @fn const char *	tb_bson_to_string (apr_pool_t * pool, bson * b)
    @brief		bson을 문자열로 변환
    @param		pool	메모리 할당 풀
    @param		b	변환할 bson
    @return		문자열
*/
const char *	tb_bson_to_string (apr_pool_t * pool, bson * b)
{
	if (!b || !b->data)
		return	"" ;

	return	tb_bson_to_string_raw(pool, b->data, 0) ;
}

