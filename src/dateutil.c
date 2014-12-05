//vim:ts=8

/** @file dateutil.c
  * 날짜 관련 함수들
  */

#include "turbo.h"

/** @fn time_t	tb_date_string_to_time (const char * date)
    @brief	날짜 시간 문자열을 time_t 으로 변환
    @param	date	YYYY-MM-DD hh:mm:ss 형태의 날짜 시간 문자열
    @return	time_t 시간값
*/
time_t	tb_date_string_to_time (const char * date)
{
	struct tm	tm;
	int		year ;
	int		month ;
	sscanf(date, "%4d-%2d-%2d %2d:%2d:%2d", &year, &month, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) ;
	tm.tm_year = year - 1900 ;
	tm.tm_mon = month - 1 ;

	time_t	t = mktime(&tm) ;
	return	t ;
}

/** @fn const char *	tb_string_time_to_string (apr_pool_t * pool, time_t time)
    @brief		time_t 시간값을 문자열로 변환
    @param		pool	메모리 할당 풀
    @param		time	시간값
    @return		YYYY-MM-DD hh:mm:ss 형태의 문자열
*/
const char *	tb_date_time_to_string (apr_pool_t * pool, time_t time)
{
	struct tm	time_tm ;
	localtime_r(&time, &time_tm) ;
	return	apr_psprintf(pool, "%4d-%02d-%02d %02d:%02d:%02d", time_tm.tm_year + 1900, time_tm.tm_mon + 1, time_tm.tm_mday, time_tm.tm_hour, time_tm.tm_min, time_tm.tm_sec) ;
}

/** @fn const char *	tb_date_header_value (apr_pool_t * pool, struct tm time)
    @brief		HTTP Date 헤더의 value 생성
    @param		pool	메모리 할당 풀
    @param		time	시간값
    @return		Date 헤더용 문자열
*/
const char *	tb_date_header_value (apr_pool_t * pool, struct tm time)
{
	char	date [32] ;
	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %Z", &time) ;
	return	apr_pstrdup(pool, date) ;
}

/** @fn const char *	tb_date_extended (apr_pool_t * pool, struct tm time)
    @brief		ISO8601 extended format 의 날짜 시간 문자열 생성
    @param		pool	메모리 할당 풀
    @param		time	시간값
    @return		ISO8601 extended format 문자열. YYYY-MM-DD'T'hh:mm:ss+hh:mm
*/
const char *	tb_date_extended (apr_pool_t * pool, struct tm time)
{
	char	date [32] ;
	strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S%z", &time) ;
	return	apr_pstrdup(pool, date) ;
}

/** @fn const char *	tb_date_basic (apr_pool_t * pool, time_t time, int gmt)
    @brief		ISO8601 basic format 의 날짜 시간 문자열 생성
    @param		pool	메모리 할당 풀
    @param		time	시간값
    @param		gmt	GMT 시간 여부. 1이면 GMT시간, 1이 아니면 로컬시간
    @return		ISO8601 basic format 문자열. YYYYMMDD'T'hh:mm:ssZ
*/
const char *	tb_date_basic (apr_pool_t * pool, time_t time, int gmt)
{
	struct tm	time_tm ;
	if (gmt)
		gmtime_r(&time, &time_tm) ;
	else	localtime_r(&time, &time_tm) ;

	char	date [32] ;
	strftime(date, sizeof(date), "%Y%m%dT%H%M%S%Z", &time_tm) ;
	return	apr_pstrdup(pool, date) ;
}

