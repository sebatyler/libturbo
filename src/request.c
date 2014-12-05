//vim:ts=8

/** @file request.c
    http request parsing 함수
*/

#include "turbo.h"
#include <http_core.h>
#include <sys/types.h>
#include <unistd.h>

static	void	request_parse_multipart (request_rec * r, REQUEST_PARSE_T * rp)
{
	const char *	content_type = apr_table_get(r->headers_in, "Content-Type") ? : "" ;

	/* Content-Type 헤더에서 구분자를 읽고 이 구분자를 사용하여 body 를 parsing.
	   header example) Content-Type: multipart/form-data; boundary=----WebKitFormBoundarybkPVQ2XhzZ75QktL"
	 */

	char *	p = strstr(content_type, "boundary") ;
	if (! p)
		return ;

	char	delimiter[128] ;
	sscanf(p, "boundary=%[^ \r\n]", delimiter) ;

	if (! *delimiter)
		return ;

	if (ap_setup_client_block(r, REQUEST_CHUNKED_ERROR) || !ap_should_client_block(r))
		return ;

	char *		content = apr_pcalloc(r->pool, r->remaining)  ;
	size_t		content_n = 0 ;
	char         	buf[4096] ;
	apr_off_t    	len ;

	/* request body 읽기 */
	rp->multipart_size = r->remaining ;
	while((len = ap_get_client_block(r, buf, _N(buf) - 1)) > 0)
	{
		memcpy(content + content_n, buf, len) ;
		content_n += len ;
	}
	rp->multipart_read_n = content_n ;

	/* 경고 */
	if (rp->multipart_read_n < rp->multipart_size)
		TB_LOG_WARN(r, "%s: multipart read [%ld/%ld] failed.", __FUNCTION__, rp->multipart_read_n, rp->multipart_size) ;

	char *	s = content ;
	int	delimiter_n = strlen(delimiter) ;
	char	key [128] ;
	char	value [512] ;
	char	name [256] ;
	char	filename [256] ;
	char	type [128] ;
	int	newline_n ;

	/* binary 데이터여서 strstr 사용하면 중간에 잘릴 수 있어서 tb_memstr 사용함 */
	while ((p = tb_memstr(s, content_n - (s - content), delimiter)))
	{
		s = p + delimiter_n ;

		*key = '\0' ;
		*value = '\0' ;
		*type = '\0' ;
		*filename = '\0' ;

		do {
			newline_n = 0 ;
			while (*s == '\r' || *s == '\n')
			{
				if (*s == '\n')
					newline_n++ ;
				s++ ;
			}

			if (newline_n > 1)
			{
				/* multipart file */
				if (*filename)
				{
					rp->multipart.content_type = apr_pstrdup(r->pool, type) ;
					rp->multipart.filename = apr_pstrdup(r->pool, filename) ;
					rp->multipart.key = apr_pstrdup(r->pool, key) ;
					rp->multipart.data = s ;

					p = tb_memstr(s, content_n - (s - content), delimiter) ;
					if (p)
					{
						rp->multipart.data_n = p - s ;
						s = p ;
					}
					else
					{
						rp->multipart.data_n = content_n - (s - content) ;
						s += rp->multipart.data_n ;
					}

					/* for debug */
					apr_table_set(rp->params, key, filename) ;
					break ;
				}

				/* multipart file 아닌 경우에는 query parameter 로 취급함 */
				char *	e = strstr(s, delimiter) ;
				if (e)
				{
					while (*e != '\r' && *e != '\n')
						e-- ;

					while (*e == '\r' || *e == '\n')
						e-- ;
					e++ ;

					*e = '\0' ;
					tb_strncopy(value, s, _N(value)) ;
				}
				else
					*value = '\0' ;

				if (strstr(value, delimiter))
					*value = '\0' ;

				if (*key && *value)
					apr_table_set(rp->params, key, value) ;
			}
			else
			{
				if (sscanf(s, "%[^:]:%[^\r\n]", name, buf) < 2)
					break ;

				s += strlen(name) + strlen(buf) + 1 ;

				if (! strcmp(name, "Content-Disposition"))
				{
					if ((p = strstr(buf, "filename=")))
						sscanf(p, "filename=\"%[^\"]\"", filename) ;

					if ((p = strstr(buf, "name=")))
						sscanf(p, "name=\"%[^\"]\"", key) ;
				}
				else if (! strcmp(name, "Content-Type"))
				{
					p = buf ;
					while (*p && *p == ' ')
						p++ ;
					strcpy(type, p) ;
				}
			}
		} while (newline_n < 2) ;
	}

	return ;
}

/** @fn REQUEST_PARSE_T		request_params_parse (request_rec * r)
    @brief	GET, POST, multipart 파라미터 파싱
    @param	r	request_rec
    @return	파싱한 REQUEST_PARSE_T
*/
REQUEST_PARSE_T		request_params_parse (request_rec * r)
{
	REQUEST_PARSE_T	rp = { .params = apr_table_make(r->pool, 4) } ;
	char *		query_string = r->args ;
	char *		param_value ;
	char *		param_name ;
	char *		p ;

	/* GET */
	while (query_string && (param_value=strsep(&query_string, "&")))
	{
		param_name = strsep(&param_value, "=") ;
		ap_unescape_url(param_name) ;
		if (param_value)
		{
			for (p=param_value; (p=strchr(p, '+')); *p=' ') ;
			ap_unescape_url(param_value) ;
		}
		else	param_value = "" ;
		apr_table_mergen(rp.params, param_name, param_value) ;
	}

	/* POST */
	const char *	content_type = apr_table_get(r->headers_in, "Content-Type") ? : "" ;
	if (! strncmp(content_type, "application/x-www-form-urlencoded", 33))
	{
		apr_array_header_t *	post = NULL ;
		int			res = ap_parse_form_data(r, NULL, &post, -1, 2097152) ;
		if (res != OK || !post) return rp ;

		char *			buffer ;
		apr_off_t		len ;
		apr_size_t		size ;
		ap_form_pair_t *	pair ;

		while (! apr_is_empty_array(post))
		{
			pair = (ap_form_pair_t *)apr_array_pop(post) ;
			apr_brigade_length(pair->value, 1, &len) ;
			size = (apr_size_t)len ;
			buffer = apr_palloc(r->pool, size + 1) ;
			apr_brigade_flatten(pair->value, buffer, &size) ;
			buffer[len] = '\0' ;

			apr_table_mergen(rp.params, pair->name, buffer) ;
		}
	}
	/* multipart */
	else if (! strncmp(content_type, "multipart/form-data", 19))
		request_parse_multipart(r, &rp) ;

	return	rp ;
}

/** @fn int	tb_match_uri (request_rec * r, const char * input_uri, const char * uri, apr_table_t * params)
    @brief	Java Spring 스타일 URL 매칭 여부 확인하고 매칭시 파라미터 추가
    @param	r		request_rec.
    @param	input_uri	입력한 URI. 일반적으로 r->args 전달하면 됨
    @param	uri		매칭 확인 URI. {} 로 변수 지정하고 파라미터로 뽑을 수 있으며 .json 도 허용함
    @param	params		{} 매칭시 파라미터 추가할 table
    @return	매칭시 SUCCESS, 매칭 실패시 FAIL
*/
int	tb_match_uri (request_rec * r, const char * input_uri, const char * uri, apr_table_t * params)
{
	int	len = strlen(uri) ;
	char *	i = (char *)input_uri ;
	char *	u = (char *)uri ;
	char	key [128] ;
	char *	k ;
	char	value [256] ;
	char *	v ;

	while (*i && *u && (*u == '{' || *i++ == *u++))
	{
		/* {variable} 탐색하면서 params 에 추가하기 */
		if (*u == '{')
		{
			/* key 읽기 */
			u++ ;
			k = key ;
			while (*u && *u != '}')
			{
				*k++ = *u++ ;
			}

			if (*u == '}')
			{
				u++ ;
				*k = '\0' ;
			}
			else	return	FAIL ;

			/* value 읽기 */
			v = value ;
			while (*i && *i != '/')
			{
				*v++ = *i++ ;
			}

			if (*i == '/' || *i == '\0')
			{
				*v = '\0' ;
			}
			else	return	FAIL ;

			if (0) TB_LOG_ERROR(r, "%s: key: [%s] value: [%s]", __FUNCTION__, key, value) ;

			if (params)
				apr_table_set(params, key, value) ;
		}
	}

	/* .json 허용 */
	if (len == u - uri && (*i == '\0' || !strcmp(i, ".json")))
	{
		return	SUCCESS ;
	}

	return	FAIL ;
}
