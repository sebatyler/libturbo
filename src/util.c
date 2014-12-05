//vim:ts=8

/** @file util.c
    각종 유틸리티 함수들
*/

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/md5.h>

#include "turbo.h"

static int	is_http_reserved (int c)
{

	if(isalnum(c) || c == '.' || c == '_')
		return 0;

	return 1;
}

/** @fn char *	tb_escape_url (apr_pool_t * pool, const char * string)
    @brief	문자열 URL escape
    @param	pool	메모리 할당 풀
    @param	string	문자열
    @return	URL escape 한 문자열
*/
char *	tb_escape_url (apr_pool_t * pool, const char * string)
{
	int	size = 1;
	char	* p;
	char    *cp;
	char    *out;

	for(p = (char *)string ; p[0] ; p++){

		if(is_http_reserved(p[0]))
			size += 3;
		else
			size++;
	}

	out = apr_palloc(pool, size);
	cp = out;
	for(; string[0]; string++){

		if(is_http_reserved(string[0])){

			snprintf(cp, sizeof(char) * 4, "%%%02X", (unsigned char)string[0]);
			cp += 3;
		}
		else{

			cp[0] = string[0];
			cp++;

		}

	}
	cp[0] = '\0';

	return out;
}

/** @fn char *	tb_escape_chars (apr_pool_t * pool, const char * src, const char * chars)
    @brief	지정한 문자를 backslash(\) escape 처리
    @param	pool	메모리 할당 풀
    @param	src	escape 처리할 source 문자열
    @param	chars	escape 처리할 문자 목록
    @return	escape 처리한 문자열. src에 chars에 있는 문자가 하나도 없는 경우 NULL 반환
*/
char *	tb_escape_chars (apr_pool_t * pool, const char * src, const char * chars)
{
	char *	escaped ;
	char *	p ;
	char *	d ;
	int	len ;
	int	replace = 0 ;
	int	i ;
	int	chars_n = strlen(chars) ;

	p = (char *)src ;
	while (*p)
	{
		for (i = 0; i < chars_n; i++)
		{
			if (*p == chars[i])
			{
				replace++ ;
				break ;
			}
		}

		p++ ;
	}

	if (! replace) return NULL ;

	len = p - src ;
	escaped = apr_palloc(pool, len + replace * 2 + 1) ;

	p = (char *)src ;
	d = escaped ;

	while (*p)
	{
		for (i = 0; i < chars_n; i++)
		{
			if (*p == chars[i])
			{
				*d++ = '\\' ;
				break ;
			}
		}

		*d++ = *p++ ;
	}

	*d = '\0' ;

	return	escaped ;
}

/** @fn char *	tb_escape_json (apr_pool_t * pool, const char * src)
    @brief	json escape 처리(\\b \\f \\n \\r \\t \\v ")
    @param	pool	메모리 할당 풀
    @param	src	json escape 처리할 문자열
    @return	escape 처리한 문자열. escape 처리할 문자가 하나도 없는 경우 NULL 반환
*/
char *	tb_escape_json (apr_pool_t * pool, const char * src)
{
	char *	escaped ;
	char *	p ;
	char *	d ;
	int	len ;
	int	replace = 0 ;
	int	i ;

	static	struct
	{
		char	special ;
		char	convert ;
	}	map[] =
	{
		{	'\b',	'b'	},
		{	'\f',	'f'	},
		{	'\n',	'n'	},
		{	'\r',	'r'	},
		{	'\t',	't'	},
		{	'\v',	'v'	},
		{	'\"',	'\"'	},
		{	'\\',	'\\'	},
	} ;
	static	size_t	map_n = _N(map) ;

	p = (char *)src ;
	while (*p)
	{
		for (i = 0; i < map_n; i++)
		{
			if (*p == map[i].special)
			{
				replace++ ;
				break ;
			}
		}

		p++ ;
	}

	if (! replace) return NULL ;

	len = p - src ;
	escaped = apr_palloc(pool, len + replace * 2 + 1) ;

	p = (char *)src ;
	d = escaped ;

	int	skip ;
	while (*p)
	{
		skip = 0 ;
		for (i = 0; i < map_n; i++)
		{
			if (*p == map[i].special)
			{
				*d++ = '\\' ;
				if (*p != map[i].convert)
				{
					*d++ = map[i].convert ;
					p++ ;
					skip = 1 ;
				}
				break ;
			}
		}

		if (! skip)
			*d++ = *p++ ;
	}

	*d = '\0' ;

	return	escaped ;
}

/** @fn char *	tb_json_escaped_string (apr_pool_t * pool, const char * str)
    @brief	json escape 처리. tb_escape_json 과 달리 NULL 반환하지 않음
    @param	pool	메모리 할당 풀
    @param	str	json escape 처리할 문자열
    @return	escape 처리한 문자열
*/
char *	tb_json_escaped_string (apr_pool_t * pool, const char * str)
{
	if (str && *str)
	{
		const char *	escaped = tb_escape_json(pool, str) ;
		if (! escaped) escaped = str ;

		return	apr_psprintf(pool, "%s", escaped) ;
	}
	
	return	NULL ;
}

/** @fn char *	tb_quoted_string (apr_pool_t * pool, const char * str, int null)
    @brief	json escape 처리하고 double quote(")로 감싸기
    @param	pool	메모리 할당 풀
    @param	str	json escape 처리할 문자열
    @param	null	null 출력 여부. 1이면 str 없는 경우 null 반환, 1이 아니면 str 없는 경우 "" 반환
    @return	json escape 처리한 후 double quote 처리한 문자열
*/
char *	tb_quoted_string (apr_pool_t * pool, const char * str, int null)
{
	if (str && *str)
	{
		const char *	json_escaped = tb_json_escaped_string(pool, str) ;
		if (json_escaped)
			return	apr_psprintf(pool, "\"%s\"", json_escaped) ;
	}
	
	return	null ? "null" : "\"\"" ;
}

/** @fn char *	tb_memstr (const char * mem, size_t mem_len, const char * str)
    @brief	strstr의 메모리 버전. strstr과 달리 중간에 NULL 문자 있어도 끝까지 탐색함
    @param	mem	문자열 찾을 메모리 주소
    @param	mem_len	mem의 길이
    @param	str	찾을 문자열
    @return	str이 최초로 나온 위치 반환. 없으면 NULL 반환
*/
char *	tb_memstr (const char * mem, size_t mem_len, const char * str)
{
	char *	p = (char *)mem ;
	char *	e = p + mem_len ;
	size_t	str_len = strlen(str) ;

	int	found = 0 ;
	while (p < e && e - p >= str_len)
	{
		if (! strncmp(p, str, str_len))
		{
			found = 1 ;
			break ;
		}
		p++ ;
	}

	return	found ? p : NULL ;
}

/** @fn const char *	tb_replace_string (apr_pool_t * pool, const char * src, const char * pattern, const char * replace)
    @brief	문자열 replace
    @param	pool	메모리 할당 풀
    @param	src	원본 문자열
    @param	pattern	찾을 패턴 문자열
    @param	replace 변경할 문자열
    @return	replace 처리한 문자열
*/
const char *	tb_replace_string (apr_pool_t * pool, const char * src, const char * pattern, const char * replace)
{
	char *	p = strstr(src, pattern) ;
	if (! p)
		return	src ;

	apr_array_header_t *	a = apr_array_make(pool, 4, sizeof(char *)) ;
	char *			s = apr_pstrdup(pool, src) ;
	int			len = strlen(pattern) ;
	p = s + (p - src) ;

	do {
		*p = '\0' ;
		APR_ARRAY_PUSH(a, const char *) = s ;
		APR_ARRAY_PUSH(a, const char *) = replace ;

		s = p + len ;
	} while ((p = strstr(s, pattern))) ;

	APR_ARRAY_PUSH(a, char *) = s ;

	return	apr_array_pstrcat(pool, a, 0) ;
}

/** @fn char *	tb_strncopy (char * dest, const char * src, size_t n)
    @brief	strncpy의 NULL 문자 종료 버전. strncpy의 경우 NULL 문자 이후에 남은 공간이 있으면 모두 NULL로 채우는데 이 함수는 NULL 문자 복사한 후 바로 리턴함
    @param	dest	복사할 문자열 포인터
    @param	src	원본 문자열
    @param	n	dest의 최대 길이
    @return	복사한 문자열 포인터
*/
char *	tb_strncopy (char * dest, const char * src, size_t n)
{
	int	i;
	for (i = 0; i < n && src[i] != '\0'; i++)
		dest[i] = src[i] ;

	dest[i >= n ? n - 1 : i] = '\0' ;

	return	dest;
}

/** @fn char *	tb_key_value_json_string (apr_pool_t * pool, const char * key, const char * value)
    @brief	json key value 형식 문자열 생성
    @param	pool	메모리 할당 풀
    @param	key	key
    @param	value	value
    @return	json 문자열. value 빈 경우 null 처리
*/
char *	tb_key_value_json_string (apr_pool_t * pool, const char * key, const char * value)
{
	return	apr_psprintf(pool, "\"%s\":%s", key, tb_quoted_string(pool, value, 1)) ;
}

/** @fn char *	tb_key_value_json_string_not_null (apr_pool_t * pool, const char * key, const char * value)
    @brief	json key value 형식 문자열 생성
    @param	pool	메모리 할당 풀
    @param	key	key
    @param	value	value
    @return	json 문자열. value 빈 경우에 "" 처리
*/
char *	tb_key_value_json_string_not_null (apr_pool_t * pool, const char * key, const char * value)
{
	return	apr_psprintf(pool, "\"%s\":%s", key, tb_quoted_string(pool, value, 0)) ;
}

/** @fn char *	tb_key_value_json_direct (apr_pool_t * pool, const char * key, const char * value)
    @brief	json key value 형식 문자열 생성. value는 double quote 처리하지 않고 바로 출력
    @param	pool	메모리 할당 풀
    @param	key	key
    @param	value	value
    @return	json 문자열. value 빈 경우 null 처리
*/
char *	tb_key_value_json_direct (apr_pool_t * pool, const char * key, const char * value)
{
	return	apr_psprintf(pool, "\"%s\":%s", key, value ? : "null") ;
}

/** @fn char *	tb_key_value_json_integer (apr_pool_t * pool, const char * key, int value)
    @brief	json key value 형식 문자열 생성. value integer
    @param	pool	메모리 할당 풀
    @param	key	key
    @param	value	value
    @return	json 문자열
*/
char *	tb_key_value_json_integer (apr_pool_t * pool, const char * key, int value)
{
	return	apr_psprintf(pool, "\"%s\":%d", key, value) ;
}

/** @fn char *	tb_key_value_json_long (apr_pool_t * pool, const char * key, long value)
    @brief	json key value 형식 문자열 생성. value long
    @param	pool	메모리 할당 풀
    @param	key	key
    @param	value	value
    @return	json 문자열
*/
char *	tb_key_value_json_long (apr_pool_t * pool, const char * key, long value)
{
	return	apr_psprintf(pool, "\"%s\":%ld", key, value) ;
}

/** @fn char *	tb_key_value_json_float (apr_pool_t * pool, const char * key, float value)
    @brief	json key value 형식 문자열 생성. value float
    @param	pool	메모리 할당 풀
    @param	key	key
    @param	value	value
    @return	json 문자열
*/
char *	tb_key_value_json_float (apr_pool_t * pool, const char * key, float value)
{
	return	apr_psprintf(pool, "\"%s\":%.2f", key, value) ;
}

/** @fn char *	tb_key_value_json_double (apr_pool_t * pool, const char * key, double value)
    @brief	json key value 형식 문자열 생성. value double
    @param	pool	메모리 할당 풀
    @param	key	key
    @param	value	value
    @return	json 문자열
*/
char *	tb_key_value_json_double (apr_pool_t * pool, const char * key, double value)
{
	return	apr_psprintf(pool, "\"%s\":%.2f", key, value) ;
}

/** @fn char *	tb_key_value_json_boolean (apr_pool_t * pool, const char * key, int value)
    @brief	json key value 형식 문자열 생성. value boolean(true/false)
    @param	pool	메모리 할당 풀
    @param	key	key
    @param	value	value
    @return	json 문자열
*/
char *	tb_key_value_json_boolean (apr_pool_t * pool, const char * key, int value)
{
	return	apr_psprintf(pool, "\"%s\":%s", key, value ? "true" : "false") ;
}

/** @fn char *	tb_key_map_json_string (apr_pool_t * pool, const char * key, apr_array_header_t * a)
    @brief	json key map 형식 문자열 생성. e.g.) "key" : { "sub1" : "sub-value1", "sub2" : "sub-value2" }
    @param	pool	메모리 할당 풀
    @param	key	key
    @param	a	value에 들어갈 값 목록 array. array를 , 로 붙여서 value의 { } 안에 넣음
    @return	json 문자열
*/
char *	tb_key_map_json_string (apr_pool_t * pool, const char * key, apr_array_header_t * a)
{
	if (a && !apr_is_empty_array(a))
		return	apr_psprintf(pool, "\"%s\":{%s}", key, apr_array_pstrcat(pool, a, ',')) ;
	return	apr_psprintf(pool, "\"%s\":{}", key) ;
}

/** @fn char *	tb_map_json_string (apr_pool_t * pool, apr_array_header_t * a)
    @brief	json map 형식 문자열 생성. e.g.) { "sub1" : "sub-value1", "sub2" : "sub-value2" }
    @param	pool	메모리 할당 풀
    @param	a	value에 들어갈 값 목록 array. array를 , 로 붙여서 value의 { } 안에 넣음
    @return	json 문자열
*/
char *	tb_map_json_string (apr_pool_t * pool, apr_array_header_t * a)
{
	if (a && !apr_is_empty_array(a))
		return	apr_psprintf(pool, "{%s}", apr_array_pstrcat(pool, a, ',')) ;
	return	"{}" ;
}

/** @fn char *	tb_key_list_json_string (apr_pool_t * pool, const char * key, apr_array_header_t * a)
    @brief	json key list 형식 문자열 생성. e.g.) "key" : [ 1,2,3,4,5 ]
    @param	pool	메모리 할당 풀
    @param	key	key
    @param	a	value에 들어갈 값 목록 array. array를 , 로 붙여서 value의 [ ] 안에 넣음
    @return	json 문자열
*/
char *	tb_key_list_json_string (apr_pool_t * pool, const char * key, apr_array_header_t * a)
{
	if (a && !apr_is_empty_array(a))
		return	apr_psprintf(pool, "\"%s\":[%s]", key, apr_array_pstrcat(pool, a, ',')) ;
	return	apr_psprintf(pool, "\"%s\":[]", key) ;
}

/** @fn char *	tb_list_json_string (apr_pool_t * pool, apr_array_header_t * a)
    @brief	json list 형식 문자열 생성. e.g.) [ 1,2,3,4,5 ]
    @param	pool	메모리 할당 풀
    @param	a	value에 들어갈 값 목록 array. array를 , 로 붙여서 value의 [ ] 안에 넣음
    @return	json 문자열
*/
char *	tb_list_json_string (apr_pool_t * pool, apr_array_header_t * a)
{
	if (a && !apr_is_empty_array(a))
		return	apr_psprintf(pool, "[%s]", apr_array_pstrcat(pool, a, ',')) ;
	return	"[]" ;
}

/** @fn char *	tb_upper_string (apr_pool_t * pool, const char * str)
    @brief	문자열 대문자 변환
    @param	pool	메모리 할당 풀
    @param	str	변환할 문자열
    @return	대문자 변환한 문자열
*/
char *	tb_upper_string (apr_pool_t * pool, const char * str)
{
	int	len = strlen(str) ;
	char *	dest = apr_palloc(pool, len + 1) ;
	char *	d = dest ;
	char *	s = (char *)str ;
	int	i ;

	for (i = 0; i < len; i++)
		*d++ = toupper(*s++) ;

	*d = '\0' ;

	return	dest ;
}

/** @fn char *	tb_lower_string (apr_pool_t * pool, const char * str)
    @brief	문자열 소문자 변환
    @param	pool	메모리 할당 풀
    @param	str	변환할 문자열
    @return	소문자 변환한 문자열
*/
char *	tb_lower_string (apr_pool_t * pool, const char * str)
{
	int	len = strlen(str) ;
	char *	dest = apr_palloc(pool, len + 1) ;
	char *	d = dest ;
	char *	s = (char *)str ;
	int	i ;

	for (i = 0; i < len; i++)
		*d++ = tolower(*s++) ;

	*d = '\0' ;

	return	dest ;
}

/** @fn char *	tb_boolean_string_by_char (char c)
    @brief	boolean 문자열 생성
    @param	c	boolean 판단할 값
    @return	boolean 문자열. true/false
*/
char *	tb_boolean_string_by_char (char c)
{
	if (c)
		return	"true" ;
	
	return	"false" ;
}

/** @fn char *	tb_boolean_string (const char * str)
    @brief	boolean 문자열 생성
    @param	str	boolean 판단할 문자열. str의 첫번째값을 사용하여 판단
    @return	boolean 문자열. true/false
*/
char *	tb_boolean_string (const char * str)
{
	if (! str)
		return	"false" ;

	return	tb_boolean_string_by_char(*str) ;
}

char 	tb_boolean (const char * str)
{
	if (! str)
		return	0 ;
	
	return	*str ;
}

/** @fn int	tb_table_integer (apr_table_t * t, const char * name, int def)
    @brief	table에서 integer 값 읽기
    @param	t	table
    @param	name	table에서 읽을 key
    @param	def	기본값
    @return	integer value
*/
int	tb_table_integer (apr_table_t * t, const char * name, int def)
{
	if (! t)
		return	def ;

	const char *	val = apr_table_get(t, name) ;
	if (val && isdigit(*val))
		return	atoi(val) ;

	return	def ;
}

/** @fn const char *	tb_table_string (apr_table_t * t, const char * name, const char * def)
    @brief	table에서 문자열 읽기
    @param	t	table
    @param	name	table에서 읽을 key
    @param	def	기본값
    @return	문자열
*/
const char *	tb_table_string (apr_table_t * t, const char * name, const char * def)
{
	if (! t)
		return	def ;

	const char *	val = apr_table_get(t, name) ;
	if (val)
		return	val ;

	return	def ;
}

/** @fn int	tb_atoi (const char * src, int def)
    @brief	atoi wrapping
    @param	src	변환할 문자열
    @param	def	기본값
    @return	integer value
*/
int	tb_atoi (const char * src, int def)
{
	return	src ? atoi(src) : def ;
}

/** @fn long	tb_atol (const char * src, long def)
    @brief	atol wrapping
    @param	src	변환할 문자열
    @param	def	기본값
    @return	long value
*/
long	tb_atol (const char * src, long def)
{
	return	src ? atol(src) : def ;
}

/** @fn double	tb_atof (const char * src, double def)
    @brief	atof wrapping
    @param	src	변환할 문자열
    @param	def	기본값
    @return	double value
*/
double	tb_atof (const char * src, double def)
{
	return	src ? atof(src) : def ;
}

/** @fn time_t	tb_atot (const char * src, time_t def)
    @brief	문자열을 time_t로 변환
    @param	src	변환할 문자열
    @param	def	기본값
    @return	time_t value
*/
time_t	tb_atot (const char * src, time_t def)
{
	return	src && *src ? tb_date_string_to_time(src) : def ;
}

/** @fn char	tb_atob (const char * src, char def)
    @brief	문자열을 boolean으로 변환. true면 1, false면 0
    @param	src	변환할 문자열
    @param	def	기본값
    @return	char value
*/
char	tb_atob (const char * src, char def)
{
	if (! src)
		return	def ;

	if (*src == 't')
		return	1 ;
	else if (*src == 'f')
		return	0 ;

	return	def ;
}

/** @fn const char *	tb_random_string (apr_pool_t * pool, int n)
    @brief	랜덤 문자열 생성. 알파벳, 숫자 조합
    @param	pool	메모리 할당 풀
    @param	n	생성할 문자열 길이
    @return	랜덤 문자열
*/
const char *	tb_random_string (apr_pool_t * pool, int n)
{
	int	i ;
	char	str[n + 1] ;

	int	mod = 'z' - 'a' + 1 + '9' - '0' + 1 ;
	int	alpha = 'z' - 'a' + 1 ;
	int	r ;

	for (i = 0; i < n; i++)
	{
		r = random() % mod ;
		if (r < alpha)
			str[i] = 'a' + r ;
		else
			str[i] = '0' + (r - alpha) ;
	}
	str[n] = '\0' ;

	return	apr_pstrdup(pool, str) ;
}

struct	ADD_PARAM_T
{
	apr_array_header_t *	a ;
	apr_pool_t *		pool ;
} ;

static	int	add_param_to_array (void * rec, const char * key, const char * value)
{
	struct ADD_PARAM_T *	add = (struct ADD_PARAM_T *)rec ;
	if (!add->a || !add->pool || !key)
		return	1 ;

	value = value ? : "" ;
	APR_ARRAY_PUSH(add->a, const char *) = apr_psprintf(add->pool, "%s=%s", key, tb_escape_url(add->pool, value)) ;

	return	1 ;
}

/** @fn const char *	tb_table_to_url (apr_pool_t * pool, apr_table_t * t)
    @brief	table을 URL 형태로 변환. key=value 형태이며 value 는 URL escape 처리함
    @param	pool	메모리 할당 풀
    @param	t	table
    @return	URL 형태의 문자열
*/
const char *	tb_table_to_url (apr_pool_t * pool, apr_table_t * t)
{
	if (! t)
		return	"" ;

	apr_array_header_t *	a = apr_array_make(pool, 4, sizeof(char *)) ;
	struct ADD_PARAM_T	add = { .a = a, .pool = pool } ;

	apr_table_do(add_param_to_array, &add, t, NULL) ;
	return	apr_array_pstrcat(pool, a, '&') ;
}

/** @fn const char *	tb_sha256_hash (apr_pool_t * pool, const char * str)
    @brief	sha256 hash 문자열 생성
    @param	pool	메모리 할당 풀
    @param	str	hash 생성할 문자열
    @return	생성된 문자열
*/
const char *	tb_sha256_hash (apr_pool_t * pool, const char * str)
{
	unsigned char	hash[SHA256_DIGEST_LENGTH] ;
	SHA256_CTX	sha256 ;
	SHA256_Init(&sha256) ;
	SHA256_Update(&sha256, str, strlen(str)) ;
	SHA256_Final(hash, &sha256) ;

	int	i = 0 ;
	char *	result = apr_pcalloc(pool, SHA256_DIGEST_LENGTH * 2 + 1) ;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(&result[i * 2], "%02x", hash[i]) ;

	return	result ;
}

/** @fn const char *	tb_sha1_hash_raw (apr_pool_t * pool, const char * str, size_t str_len)
    @brief	sha1 hash 문자열 생성
    @param	pool	메모리 할당 풀
    @param	str	hash 생성할 문자열
    @param	str_len	hash 생성할 문자열의 길이
    @return	생성된 문자열
*/
const char *	tb_sha1_hash_raw (apr_pool_t * pool, const char * str, size_t str_len)
{
	unsigned char	hash[SHA_DIGEST_LENGTH] ;
	SHA_CTX	sha1 ;
	SHA1_Init(&sha1) ;
	SHA1_Update(&sha1, str, str_len) ;
	SHA1_Final(hash, &sha1) ;

	int	i = 0 ;
	char *	result = apr_pcalloc(pool, SHA_DIGEST_LENGTH * 2 + 1) ;
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		sprintf(&result[i * 2], "%02x", hash[i]) ;

	return	result ;
}

/** @fn const char *	tb_sha1_hash (apr_pool_t * pool, const char * str)
    @brief	sha1 hash 문자열 생성. str의 길이를 명시하는 tb_sha1_hash_raw와 달리 strlen을 통해서 길이를 측정함
    @param	pool	메모리 할당 풀
    @param	str	hash 생성할 문자열
    @return	생성된 문자열
*/
const char *	tb_sha1_hash (apr_pool_t * pool, const char * str)
{
	return	tb_sha1_hash_raw(pool, str, strlen(str)) ;
}

/** @fn const char *	tb_md5_hash_raw (apr_pool_t * pool, const char * str, size_t str_len)
    @brief	md5 hash 문자열 생성
    @param	pool	메모리 할당 풀
    @param	str	hash 생성할 문자열
    @param	str_len	hash 생성할 문자열의 길이
    @return	생성된 문자열
*/
const char *	tb_md5_hash_raw (apr_pool_t * pool, const char * str, size_t str_len)
{
	unsigned char	hash[MD5_DIGEST_LENGTH] ;
	MD5_CTX		ctx ;
	MD5_Init(&ctx) ;
	MD5_Update(&ctx, str, str_len) ;
	MD5_Final(hash, &ctx) ;

	int	i = 0 ;
	char *	result = apr_pcalloc(pool, MD5_DIGEST_LENGTH * 2 + 1) ;
	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		sprintf(&result[i * 2], "%02x", hash[i]) ;

	return	result ;
}

/** @fn const char *	tb_md5_hash (apr_pool_t * pool, const char * str)
    @brief	md5 hash 문자열 생성. str의 길이를 명시하는 tb_md5_hash_raw와 달리 strlen을 통해서 길이를 측정함
    @param	pool	메모리 할당 풀
    @param	str	hash 생성할 문자열
    @return	생성된 문자열
*/
const char *	tb_md5_hash (apr_pool_t * pool, const char * str)
{
	return	tb_md5_hash_raw(pool, str, strlen(str)) ;
}

/** @fn const void *	tb_hmac_hash (apr_pool_t * pool, const void * key, int key_len, const void * str, int str_len, int sha1, int binary)
    @brief		HMAC hash 생성
    @param		pool	메모리 할당 풀
    @param		key	HMAC key
    @param		key_len key 길이
    @param		str	HMAC value
    @param		str_len	value 길이
    @param		sha1	1이면 sha1, 1이 아니면 sha256 사용
    @param		binary	1이면 binary 데이터, 1이 아니면 문자열
    @return		생성한 HMAC hash 포인터. 실패시 NULL 반환
*/
const void *	tb_hmac_hash (apr_pool_t * pool, const void * key, int key_len, const void * str, int str_len, int sha1, int binary)
{
	unsigned char *	k = (unsigned char *)key ;
	unsigned char *	data = (unsigned char *)str ;
	int		data_len = str_len ;
	unsigned char *	result ;
	unsigned int	result_len = sha1 ? 20 : 32 ;

	result = HMAC(sha1 ? EVP_sha1() : EVP_sha256(), k, key_len, data, data_len, NULL, NULL);
	if (result)
	{
		if (binary)
			return	result ;

		int	i;
		char *	md_string = apr_pcalloc(pool, result_len * 2 + 1) ;
		for (i = 0; i < result_len; i++)
			sprintf(&md_string[i * 2], "%02x", (unsigned int)result[i]) ;

		return	md_string ;
	}

	return	NULL ;
}

/** @fn const char *	tb_curtail_string (apr_pool_t * pool, const char * src, int curtail_n, const char * postfix)
    @brief	유니코드 기반 문자열 줄이기
    @param	pool		메모리 할당 풀
    @param	src		원본 문자열
    @param	curtail_n	줄일 길이
    @param	postfix		길이를 줄인 경우 뒤에 붙일 문자열. NULL 이거나 빈 문자열이면 아무것도 안붙인다.
    @return	src의 길이가 curtail_n 보다 작거나 같으면 src를 그대로 반환하고 curtail_n 보다 크면 curtail_n까지로 줄이고 postfix를 붙인 문자열을 반환한다.
*/
const char *	tb_curtail_string (apr_pool_t * pool, const char * src, int curtail_n, const char * postfix)
{
	if (!src || curtail_n <= 0)
		return	src ;

	const	char *	s = src ;
	size_t		src_len = strlen(src) ;

	if (src_len <= curtail_n)
		return	src ;

	char *		dest = apr_palloc(pool, sizeof(char) * src_len + 1) ;
	char *		d = dest ;
	size_t		n = src_len ;
	size_t		l = curtail_n ;

	while (*s && n>1 && l>0)
	{
		if (*s & 0x80)
		{
			/* 유니코드 길이 확보 */
			if (l < 3)
				break ;

			*d++ = *s++, n--, l-- ;

			while (n>1 && (*s&0xc0)==0x80)
				*d++ = *s++, n--, l-- ;
		}
		else	*d++ = *s++, n--, l-- ;
	}

	if (*s && postfix && *postfix)
		while (n>1 && postfix && *postfix)
			*d++ = *postfix++, n-- ;

	*d = '\0' ;

	return	dest ;
}
