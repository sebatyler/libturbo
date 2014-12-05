//vim:ts=8

/** @file turbo.h
    공통 header file. libturbo 사용시 반드시 include 해야함
*/
#ifndef __TURBO_H__
#define	__TURBO_H__

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "http_log.h"
#include "apr_tables.h"

#include <sys/stat.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>

#include <wand/magick_wand.h>

#define	TB_LOG_ERROR(r, args...)	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ## args)
#define	TB_LOG_WARN(r, args...)		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, ## args)
#define	TB_LOG_INFO(r, args...)		ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, ## args)
#define	TB_LOGS_ERROR(s, args...)	ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, ## args)
#define	TB_LOGS_WARN(s, args...)	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, ## args)
#define	TB_LOGS_INFO(s, args...)	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, ## args)

#define _N(x)			(sizeof(x)/sizeof(*(x)))
#define _SZ(x)			x, (sizeof(x)/sizeof(*(x)))

#define FAIL			-1
#define SUCCESS			0

typedef struct
{
	struct
	{
		const char *	content_type ;
		const char *	filename ;
		const char *	key ;
		const char *	data ;
		size_t		data_n ;
	}	multipart ;
	size_t	multipart_size ;
	size_t	multipart_read_n ;

	apr_table_t *	params ;
} REQUEST_PARSE_T ;

typedef	struct
{
	long		status ;
	const char *	body ;
	const char *	data ;
} AWS_RESPONSE_T ;

/* request.c */
REQUEST_PARSE_T		request_params_parse (request_rec * r) ;
int	tb_match_uri (request_rec * r, const char * input_uri, const char * uri, apr_table_t * params) ;

/* util.c */
char *	tb_escape_url (apr_pool_t * pool, const char * string) ;
char *	tb_escape_chars (apr_pool_t * pool, const char * src, const char * chars) ;
char *	tb_escape_json (apr_pool_t * pool, const char * src) ;
char *	tb_json_escaped_string (apr_pool_t * pool, const char * str) ;
char *	tb_quoted_string (apr_pool_t * pool, const char * str, int null) ;
char *	tb_memstr (const char * mem, size_t mem_len, const char * str) ;
const char *	tb_replace_string (apr_pool_t * pool, const char * src, const char * pattern, const char * replace) ;
char *	tb_strncopy (char * dest, const char * src, size_t n) ;
char *	tb_key_value_json_string (apr_pool_t * pool, const char * key, const char * value) ;
char *	tb_key_value_json_string_not_null (apr_pool_t * pool, const char * key, const char * value) ;
char *	tb_key_value_json_direct (apr_pool_t * pool, const char * key, const char * value) ;
char *	tb_key_value_json_integer (apr_pool_t * pool, const char * key, int value) ;
char *	tb_key_value_json_long (apr_pool_t * pool, const char * key, long value) ;
char *	tb_key_value_json_float (apr_pool_t * pool, const char * key, float value) ;
char *	tb_key_value_json_double (apr_pool_t * pool, const char * key, double value) ;
char *	tb_key_value_json_boolean (apr_pool_t * pool, const char * key, int value) ;
char *	tb_key_map_json_string (apr_pool_t * pool, const char * key, apr_array_header_t * a) ;
char *	tb_map_json_string (apr_pool_t * pool, apr_array_header_t * a) ;
char *	tb_key_list_json_string (apr_pool_t * pool, const char * key, apr_array_header_t * a) ;
char *	tb_list_json_string (apr_pool_t * pool, apr_array_header_t * a) ;
char *	tb_upper_string (apr_pool_t * pool, const char * str) ;
char *	tb_lower_string (apr_pool_t * pool, const char * str) ;
char *	tb_boolean_string_by_char (char c) ;
char *	tb_boolean_string (const char * str) ;
char 	tb_boolean (const char * str) ;
int	tb_table_integer (apr_table_t * t, const char * name, int def) ;
const char *	tb_table_string (apr_table_t * t, const char * name, const char * def) ;
int	tb_atoi (const char * src, int def) ;
long	tb_atol (const char * src, long def) ;
double	tb_atof (const char * src, double def) ;
time_t	tb_atot (const char * src, time_t def) ;
char	tb_atob (const char * src, char def) ;
const char *	tb_random_string (apr_pool_t * pool, int n) ;
const char *	tb_table_to_url (apr_pool_t * pool, apr_table_t * t) ;
const char *	tb_sha256_hash (apr_pool_t * pool, const char * str) ;
const char *	tb_sha1_hash_raw (apr_pool_t * pool, const char * str, size_t str_len) ;
const char *	tb_sha1_hash (apr_pool_t * pool, const char * str) ;
const char *	tb_md5_hash_raw (apr_pool_t * pool, const char * str, size_t str_len) ;
const char *	tb_md5_hash (apr_pool_t * pool, const char * str) ;
const void *	tb_hmac_hash (apr_pool_t * pool, const void * key, int key_len, const void * str, int str_len, int sha1, int binary) ;
const char *	tb_curtail_string (apr_pool_t * pool, const char * src, int curtail_n, const char * postfix) ;

/* dateutil.c */
time_t	tb_date_string_to_time (const char * date) ;
const char *	tb_date_time_to_string (apr_pool_t * pool, time_t time) ;
const char *	tb_date_header_value (apr_pool_t * pool, struct tm time) ;
const char *	tb_date_extended (apr_pool_t * pool, struct tm time) ;
const char *	tb_date_basic (apr_pool_t * pool, time_t time, int gmt) ;

/* aws.c */
const char *	tb_aws_signature (apr_pool_t * pool, const char * key, const char * str, int sha1) ;
void	tb_aws_init (const char * access_key, const char * secret_key) ;
void	tb_ses_init (const char * email_sender) ;
int	tb_ses_send (request_rec * r, const char * email, const char * subject, const char * content, int html, int real) ;
void	tb_s3_init (const char * bucket) ;
int	tb_s3_upload (request_rec * r, const char * path, const char * data, size_t data_n, const char * content_type, int public_read) ;
int	tb_s3_delete (request_rec * r, const char * path) ;
int	tb_s3_move (request_rec * r, const char * src_path, const char * dest_path, int public_read) ;
int	tb_sqs_send (request_rec * r, const char * endpoint, const char * body) ;
void	tb_sns_push_init (const char * ios_arn, const char * android_arn) ;
AWS_RESPONSE_T *	tb_sns_add_push_key_raw (request_rec * r, const char * user_data, const char * mobile_type, const char * device_key) ;
const char *	tb_sns_parse_arn (apr_pool_t * pool, const char * body) ;
const char *	tb_sns_add_push_key (request_rec * r, const char * user_data, const char * mobile_type, const char * device_key) ;
int	tb_sns_arn_delete (request_rec * r, const char * sns_arn) ;
AWS_RESPONSE_T *	tb_sns_push_send (request_rec * r, const char * mobile_type, const char * sns_arn, const char * message, int badge, apr_table_t * custom, int real) ;
AWS_RESPONSE_T *	tb_sns_push_publish (request_rec * r, const char * mobile_type, const char * sns_arn, const char * message, apr_table_t * custom, int real) ;
int	tb_sns_set_endpoint_attributes (request_rec * r, const char * sns_arn, const char * key, const char * value) ;
void	tb_cf_signer_init (const char * key_pair_id, char * private_key) ;
void	tb_cf_signer_final (void) ;
const char *	tb_cf_signer_get_url (apr_pool_t * pool, const char * base_url, time_t expire) ;

/* image.c */
void		tb_image_init () ;
void		tb_image_final () ;
const char *	tb_image_resize_crop (apr_pool_t * pool, const char * data, size_t data_n, size_t * result_len, int width, int height) ;


#endif

