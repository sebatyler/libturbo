//vim:ts=8

/** @file postgresql.c
    PostgreSQL 사용 위한 함수들
*/

#include <unistd.h>
#include <sys/timeb.h>
#include "turbo.h"

/** @fn void	tb_close_postgre (PGconn * postgre, time_t * postgre_conn_time)
    @brief	PostgreSQL 연결 해제
    @param	postgre			PostgreSQL connection
    @param	postgre_conn_time	PostgreSQL connection 맺은 시간
*/
void	tb_close_postgre (PGconn * postgre, time_t * postgre_conn_time)
{
	if (postgre)
		PQfinish(postgre) ;

	*postgre_conn_time = 0 ;
}

/* ms 단위로 query timeout 과 timeout check interval 지정 가능. 기본은 10000ms, 5ms */
int	postgre_timeout = 10000 ;
int	postgre_timeout_check_interval = 5 ;

/** @fn void	tb_set_postgre_query_timeout (int timeout, int check_interval)
    @brief	PostgreSQL command, query timeout 설정
    @param	timeout		ms 단위 timeout. timeout 발생하면 PGresult * 반환하는 함수가 NULL 을 반환함. 기본값 5000ms
    @param	check_interval	ms 단위의 timeout check 주기. command, query 를 비동기로 요청한 후 check 주기마다 응답왔는지 체크하여 timeout 판단함. 기본값 5ms
*/
void	tb_set_postgre_query_timeout (int timeout, int check_interval)
{
	if (timeout > 0)
		postgre_timeout = timeout ;
	if (check_interval > 0)
		postgre_timeout_check_interval = check_interval ;
}

/** @fn PGconn *	tb_open_postgre (server_rec * s, PGconn * postgre, time_t * postgre_conn_time, const char * keys[], const char * vals[], int alive_time)
    @brief	PostgreSQL 서버 연결
    @param	s			server_rec. 메모리 할당, 에러 로깅
    @param	postgre			이전 connection. NULL 이어도 연결함
    @param	postgre_conn_time	이전 connection 맺은 시간
    @param	keys			connection option 필드명 목록
    @param	vals			connection option 값 목록
    @param	alive_time		connection alive time. s 단위이며 이전 연결 맺은 이후에 해당 시간 만큼 지나면 강제로 연결 끊고 다시 연결 시도함
    @return	연결한 PGconn. 실패시 NULL 반환
*/
PGconn *	tb_open_postgre (server_rec * s, PGconn * postgre, time_t * postgre_conn_time, const char * keys[], const char * vals[], int alive_time)
{
	time_t	now = time(NULL) ;
	if (*postgre_conn_time == 0)
		*postgre_conn_time = now ;

	const char *	host ;
	int		i = 0 ;
	while ((host = keys[i]))
	{
		if (! strcasecmp(host, "host"))
			break ;
		i++ ;
	}
	host = host ? vals[i] : "" ;

	if (postgre)
	{
		/* 커넥션 맺은지 alive_time(초) 경과했거나 커넥션 체크 실패시 커넥션 끊고 다시 커넥션 맺기 */
		if (*postgre_conn_time + alive_time < now || PQstatus(postgre) != CONNECTION_OK)
		{
			if (0)
				TB_LOGS_ERROR(s, "%s: postgre reconnect start: before:%ld now:%ld", __FUNCTION__, *postgre_conn_time, now) ;

			tb_close_postgre(postgre, postgre_conn_time) ;

			postgre = NULL ;
			*postgre_conn_time = now ;
		}
		/* 커넥션 살아있으므로 return */
		else
			return	postgre ;
	}
	
	int		try = 3 ;
	int		connected = 0 ;
	PGresult *	result = NULL ;
	char 		command [64] ;
	i = 0 ;
	snprintf(_SZ(command), "BEGIN; SET SESSION STATEMENT_TIMEOUT TO %d; COMMIT;", postgre_timeout) ;

	do {
		i++ ;
		postgre = PQconnectdbParams(keys, vals, 0) ;
		if (PQstatus(postgre) != CONNECTION_OK)
		{
			TB_LOGS_ERROR(s, "%s: postgre connect error: [%s]", __FUNCTION__, PQerrorMessage(postgre)) ;
			continue ;
		}

		result = PQexec(postgre, command) ;
		if (! result)
		{
			TB_LOGS_ERROR(s, "%s: postgre set session statement_timeout error: [%s]", __FUNCTION__, PQerrorMessage(postgre)) ;
			tb_close_postgre(postgre, postgre_conn_time) ;
			continue ;
		}

		PQclear(result) ;
		connected = 1 ;

		TB_LOGS_INFO(s, "%s: postgre connected: host: %s %d %ld", __FUNCTION__, host, PQbackendPID(postgre), *postgre_conn_time) ;

	} while (!connected && i < try) ;

	if (connected == 0)
	{
		tb_close_postgre(postgre, postgre_conn_time) ;
		return	NULL ;
	}

	if (*postgre_conn_time == 0)
		*postgre_conn_time = now ;

	return	postgre ;
}

/** @fn PGresult *	tb_postgre_exec_result (request_rec * r, PGconn * postgre, const char * command, apr_array_header_t * postgre_result)
    @brief		PostgreSQL command 실행하고 결과 받아오기
    @param		r		request_rec. 메모리 할당, 에러 로깅
    @param		postgre		connection
    @param		command		실행할 command. sql도 가능
    @param		postgre_result	PGresult push 할 array. 일괄 해제는 직접 구현해야함
    @return		PGresult. 실패시 NULL 반환
*/
PGresult *	tb_postgre_exec_result (request_rec * r, PGconn * postgre, const char * command, apr_array_header_t * postgre_result)
{
	PGresult *	result = NULL ;

	if (!postgre || !command) return result ;

	result = PQexec(postgre, command) ;
	if (result && postgre_result)
		APR_ARRAY_PUSH(postgre_result, PGresult *) = result ;

	int	status = PQresultStatus(result) ;
	if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK)
	{
		TB_LOG_ERROR(r, "%s: command: [%s] error: %s", __FUNCTION__, command, PQerrorMessage(postgre)) ;
		return	NULL ;
	}

	return	result ;
}

static	const char *	params_to_string (apr_pool_t * pool, const char * params[], int params_n)
{
	apr_array_header_t *	a = apr_array_make(pool, params_n, sizeof(char *)) ;
	for (int i = 0; i < params_n; i++)
		APR_ARRAY_PUSH(a, const char *) = params[i] ;

	return	apr_array_pstrcat(pool, a, ',') ;

}

/** @fn PGresult *	tb_postgre_exec_sql_result (request_rec * r, PGconn * postgre, const char * sql, const char * params[], int params_n, apr_array_header_t * postgre_result)
    @brief		PostgreSQL sql 실행하고 결과 받아오기
    @param		r		request_rec. 메모리 할당, 에러 로깅
    @param		postgre		connection
    @param		sql		실행할 sql
    @param		params		파라미터 배열
    @param		params_n	파라미터 갯수
    @param		postgre_result	PGresult push 할 array. 일괄 해제는 직접 구현해야함
    @return		PGresult. 실패시 NULL 반환
*/
PGresult *	tb_postgre_exec_sql_result (request_rec * r, PGconn * postgre, const char * sql, const char * params[], int params_n, apr_array_header_t * postgre_result)
{
	PGresult *	result = NULL ;

	if (!postgre || !sql) return result ;

	result = PQexecParams(postgre, sql, params_n, NULL, params, NULL, NULL, 0) ;
	if (result && postgre_result)
		APR_ARRAY_PUSH(postgre_result, PGresult *) = result ;

	int	status = PQresultStatus(result) ;
	if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK)
	{
		TB_LOG_ERROR(r, "%s: sql: [%s] params: [%s] error: %s", __FUNCTION__, sql, params_to_string(r->pool, params, params_n), PQerrorMessage(postgre)) ;
		return	NULL ;
	}

	return	result ;
}

/** @fn PGresult *	tb_postgre_exec_sql_result_s (server_rec * s, PGconn * postgre, const char * sql, const char * params[], int params_n)
    @brief		PostgreSQL sql 실행하고 결과 받아오기 server_rec 버전. PGresult 사용 후 바로 PQclear() 호출해주어야함
    @param		s		server_rec. 메모리 할당, 에러 로깅
    @param		postgre		connection
    @param		sql		실행할 sql
    @param		params		파라미터 배열
    @param		params_n	파라미터 갯수
    @return		PGresult. 실패시 NULL 반환
*/
PGresult *	tb_postgre_exec_sql_result_s (server_rec * s, PGconn * postgre, const char * sql, const char * params[], int params_n)
{
	PGresult *	result = NULL ;

	if (!postgre || !sql) return result ;

	result = PQexecParams(postgre, sql, params_n, NULL, params, NULL, NULL, 0) ;
	int	status = PQresultStatus(result) ;
	if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK)
	{
		if (result)
			PQclear(result) ;

		TB_LOGS_ERROR(s, "%s: sql: [%s] params: [%s] error: %s", __FUNCTION__, sql, params_to_string(s->process->pool, params, params_n), PQerrorMessage(postgre)) ;
		return	NULL ;
	}

	return	result ;
}

/** @fn int	tb_postgre_affected_rows (request_rec * r, PGconn * postgre, const char * sql, const char * params[], int params_n, apr_array_header_t * postgre_result)
    @brief	PostgreSQL sql 실행하고 적용된 row 수 반환. insert, delete, update에 해당
    @param	r		request_rec. 메모리 할당, 에러 로깅
    @param	postgre		connection
    @param	sql		실행할 sql
    @param	params		파라미터 배열
    @param	params_n	파라미터 갯수
    @param	postgre_result	PGresult push 할 array. 일괄 해제는 직접 구현해야함
    @return	적용된 row 수. 실패시 -1 반환
*/
int	tb_postgre_affected_rows (request_rec * r, PGconn * postgre, const char * sql, const char * params[], int params_n, apr_array_header_t * postgre_result)
{
	PGresult *	result = tb_postgre_exec_sql_result(r, postgre, sql, params, params_n, postgre_result) ;
	return	tb_postgre_result_rows(result) ;
}

/** @fn int	tb_postgre_result_rows (PGresult * result)
    @brief	적용된 row 수 반환. insert, delete, update에 해당
    @param	result	row 수 확인할 PGresult
    @return	적용된 row 수. 실패시 -1 반환
*/
int	tb_postgre_result_rows (PGresult * result)
{
	char *	tuples ;
	if (!result || !(tuples = PQcmdTuples(result)))
		return	-1 ;

	return	atoi(tuples) ;
}

/** @fn int	tb_check_postgre_result (PGresult * result, int rows, int fields)
    @brief	row 수, field 수 확인
    @param	result	확인할 PGresult
    @param	rows	확인할 row 수. 0이면 체크안하고 0보다 크면 row 수가 rows 보다 작으면 FAIL
    @param	fields	확인할 field 수. 0이면 체크안하고 0보다 크면 field 수가 fields 보다 작으면 FAIL
    @return	row 수, field 수 확인시 정상이면 SUCCESS, 하나라도 실패면 FAIL
*/
int	tb_check_postgre_result (PGresult * result, int rows, int fields)
{
	if (! result) return FAIL ;

	if (rows > 0 && PQntuples(result) < rows)
		return	FAIL ;

	if (fields > 0 && PQnfields(result) < fields)
		return	FAIL ;

	return	SUCCESS ;
}

/** @fn int	tb_postgre_transaction_start (request_rec * r, PGconn * postgre, apr_array_header_t * postgre_result)
    @brief	PostgreSQL transaction 시작
    @param	r		request_rec. 메모리 할당, 에러 로깅
    @param	postgre		connection
    @param	postgre_result	PGresult push 할 array. 일괄 해제는 직접 구현해야함
    @return	성공시 SUCCESS, 실패시 FAIL
*/
int	tb_postgre_transaction_start (request_rec * r, PGconn * postgre, apr_array_header_t * postgre_result)
{
	int	fail = 0 ;
	if (postgre)
	{
		if (! tb_postgre_exec_result(r, postgre, "BEGIN", postgre_result))
			fail++ ;
	}

	return	fail ? FAIL : SUCCESS ;
}

/** @fn int	tb_postgre_transaction_end (request_rec * r, PGconn * postgre, int commit, apr_array_header_t * postgre_result)
    @brief	PostgreSQL transaction 종료
    @param	r		request_rec. 메모리 할당, 에러 로깅
    @param	postgre		connection
    @param	commit		1이면 commit. 1이 아니면 rollback
    @param	postgre_result	PGresult push 할 array. 일괄 해제는 직접 구현해야함
    @return	성공시 SUCCESS, 실패시 FAIL. rollback 은 항상 SUCCESS
*/
int	tb_postgre_transaction_end (request_rec * r, PGconn * postgre, int commit, apr_array_header_t * postgre_result)
{
	if (commit)
	{
		if (postgre)
		{
			if (! tb_postgre_exec_result(r, postgre, "COMMIT;", postgre_result))
				return	FAIL ;
		}
	}
	else
	{
		tb_postgre_exec_result(r, postgre, "ROLLBACK;", postgre_result) ;
		TB_LOG_ERROR(r, "%s: rollback: uri: [%s]", __FUNCTION__, r->unparsed_uri) ;
	}

	return	SUCCESS ;
}

/** @fn const char *	tb_postgre_escape_literal (apr_pool_t * pool, PGconn * postgre, const char * str)
    @brief	문자열 escape 처리
    @param	pool	메모리 할당 풀
    @param	postgre	connection
    @param	str	escape 처리할 문자열
    @return	escape 처리된 문자열. pool 에서 할당하므로 free 할 필요없음
*/
const char *	tb_postgre_escape_literal (apr_pool_t * pool, PGconn * postgre, const char * str)
{
	if (!postgre || !str || !*str)
		return	"" ;

	char *	escaped = PQescapeLiteral(postgre, str, strlen(str)) ;
	if (! escaped)
		return	str ;

	char *	result = apr_pstrdup(pool, escaped) ;
	PQfreemem(escaped) ;

	return	result ;
}

/** @fn char	tb_postgre_result_boolean (PGresult * result, int row, int column, char def)
    @brief	PGresult에서 boolean 값 읽기
    @param	result	PGresult
    @param	row	row index. 0부터 시작
    @param	column	column index. 0부터 시작
    @param	def	기본값
    @return	읽은 boolean 값. true면 1, false면 0
*/
char	tb_postgre_result_boolean (PGresult * result, int row, int column, char def)
{
	if (!result || row < 0 || column < 0)
		return	def ;

	return	tb_atob(PQgetvalue(result, row, column), def) ;
}

/** @fn int	tb_postgre_result_integer (PGresult * result, int row, int column, int def)
    @brief	PGresult에서 integer 값 읽기
    @param	result	PGresult
    @param	row	row index. 0부터 시작
    @param	column	column index. 0부터 시작
    @param	def	기본값
    @return	읽은 integer 값
*/
int	tb_postgre_result_integer (PGresult * result, int row, int column, int def)
{
	if (!result || row < 0 || column < 0)
		return	def ;

	return	tb_atoi(PQgetvalue(result, row, column), def) ;
}

/** @fn long	tb_postgre_result_long (PGresult * result, int row, int column, long def)
    @brief	PGresult에서 long 값 읽기
    @param	result	PGresult
    @param	row	row index. 0부터 시작
    @param	column	column index. 0부터 시작
    @param	def	기본값
    @return	읽은 long 값
*/
long	tb_postgre_result_long (PGresult * result, int row, int column, long def)
{
	if (!result || row < 0 || column < 0)
		return	def ;

	return	tb_atol(PQgetvalue(result, row, column), def) ;
}

/** @fn const	char *	tb_postgre_result_string (PGresult * result, int row, int column, const char * def)
    @brief	PGresult에서 문자열 읽기
    @param	result	PGresult
    @param	row	row index. 0부터 시작
    @param	column	column index. 0부터 시작
    @param	def	기본값
    @return	읽은 문자열
*/
const	char *	tb_postgre_result_string (PGresult * result, int row, int column, const char * def)
{
	if (!result || row < 0 || column < 0)
		return	def ;

	char *	val = PQgetvalue(result, row, column) ;
	return	val ? : def ;
}

/** @fn time_t	tb_postgre_result_time_t (PGresult * result, int row, int column, time_t def)
    @brief	PGresult에서 time_t 읽기
    @param	result	PGresult
    @param	row	row index. 0부터 시작
    @param	column	column index. 0부터 시작
    @param	def	기본값
    @return	읽은 time_t 값
*/
time_t	tb_postgre_result_time_t (PGresult * result, int row, int column, time_t def)
{
	if (!result || row < 0 || column < 0)
		return	def ;

	return	tb_atot(PQgetvalue(result, row, column), def) ;
}

/** @fn apr_array_header_t *	tb_pgresult_to_array (apr_pool_t * pool, PGresult * result)
    @brief	PGresult를 array로 변환
    @param	pool	메모리 할당 풀
    @param	result	PGresult
    @return	변환한 array. array의 값은 table이고 table의 key는 필드명. 실패하거나 결과 없는 경우 NULL 반환
*/
apr_array_header_t *	tb_pgresult_to_array (apr_pool_t * pool, PGresult * result)
{
	if (!pool || !result)
		return	NULL ;

	int		rows = PQntuples(result) ;
	int		fields_n = PQnfields(result) ;
	
	if (rows <= 0 || fields_n <= 0)
		return	NULL ;

	apr_array_header_t *	a = apr_array_make(pool, rows, sizeof(apr_table_t *)) ;
	apr_table_t *		t = NULL ;
	int			i, j ;
	const char *		fields[fields_n] ;

	for (i = 0; i < fields_n; i++)
		fields[i] = PQfname(result, i) ;

	for (i = 0; i < rows; i++)
	{
		t = apr_table_make(pool, fields_n) ;

		for (j = 0; j < fields_n; j++)
			apr_table_set(t, fields[j], PQgetvalue(result, i, j)) ;

		APR_ARRAY_PUSH(a, apr_table_t *) = t ;
	}

	if (apr_is_empty_array(a))
		a = NULL ;

	return	a ;
}

