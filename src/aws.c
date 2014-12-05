//vim:ts=8

/** @file aws.c
    AWS 사용 위한 함수들
*/

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <curl/curl.h>

#include "apr_base64.h"
#include "turbo.h"

static struct	CURL_DATA
{
	apr_pool_t *		pool ;
	apr_array_header_t *	a ;
} curl_data ;

static size_t	curl_read_response (void * ptr, size_t size, size_t nmemb, struct CURL_DATA * data)
{
	APR_ARRAY_PUSH(data->a, const char *) = apr_pstrdup(data->pool, ptr) ;
	return	size * nmemb;
}

struct	PUT_DATA
{
	const char *	data ;
	size_t		len ;
} ;

static size_t	curl_read_put_data (void * ptr, size_t size, size_t nmemb, void * put_data)
{
	struct	PUT_DATA *	userdata = (struct PUT_DATA *)put_data ;
	size_t			curl_size = nmemb * size;
	size_t			to_copy = (userdata->len < curl_size) ? userdata->len : curl_size;
	memcpy(ptr, userdata->data, to_copy);
	userdata->len -= to_copy;
	userdata->data += to_copy;

	return	to_copy;
}

/** @fn const char *	tb_aws_signature (apr_pool_t * pool, const char * key, const char * str, int sha1)
    @brief		AWS signature 생성
    @param		pool	메모리 할당 풀
    @param		key	signature 생성 위한 HMAC key
    @param		str	signature 생성 위한 HMAC value
    @param		sha1	1이면 sha1, 1이 아니면 sha256 사용
    @return		생성한 signature 문자열에 대한 포인터. 실패시 NULL 반환
*/
const char *	tb_aws_signature (apr_pool_t * pool, const char * key, const char * str, int sha1)
{
	int		key_len = strlen(key) ;
	unsigned char *	data = (unsigned char *)str ;
	int		data_len = strlen(str) ;
	unsigned char *	result ;
	unsigned int	result_len = sha1 ? 20 : 32 ;
	char		signature[64] ;

	result = (unsigned char *)tb_hmac_hash(pool, key, key_len, data, data_len, sha1, 1) ;
	if (result && apr_base64_encode(signature, (const char *)result, result_len) > 0)
		return	apr_pstrdup(pool, signature) ;

	return	NULL ;
}

static	const void *	generate_hmac_sha256 (apr_pool_t * pool, const void * key, int key_len, const void * str, int str_len, int binary)
{
	return	tb_hmac_hash(pool, key, key_len, str, str_len, 0, binary) ;
}

static	char	aws_access_key [64] ;
static	char 	aws_secret_key [128] ;
static	char	ses_email_sender [64] ;
static	char	s3_bucket [128] ;

/** @fn void	tb_aws_init (const char * access_key, const char * secret_key)
    @brief	AWS 초기화 : access key, secret key 등록
    @param	access_key	AWS access key
    @param	secret_key	AWS secret key
*/
void	tb_aws_init (const char * access_key, const char * secret_key)
{
	tb_strncopy(aws_access_key, access_key, _N(aws_access_key)) ;
	tb_strncopy(aws_secret_key, secret_key, _N(aws_secret_key)) ;
}

/** @fn void	tb_ses_init (const char * email_sender)
    @brief	AWS SES 초기화 : 발신 email 등록
    @param	email_sender	발신 email
*/
void	tb_ses_init (const char * email_sender)
{
	tb_strncopy(ses_email_sender, email_sender, _N(ses_email_sender)) ;
}

/** @fn int	tb_ses_send (request_rec * r, const char * email, const char * subject, const char * content, int html, int real)
    @brief	AWS SES email 발송
    @param	r	request_rec. 메모리 할당, 에러 로깅
    @param	email	수신 email 계정
    @param	subject	메일 제목
    @param	content	메일 본문
    @param	html	1이면 html 형식, 1이 아니면 일반 text
    @param	real	1이면 메일 발송, 1이 아니면 메일 발송하지 않고 SUCCESS 반환
    @return	성공시 SUCCESS, 실패시 FAIL
*/
int	tb_ses_send (request_rec * r, const char * email, const char * subject, const char * content, int html, int real)
{
	if (!email || !subject || !content || !*aws_access_key || !*aws_secret_key)
		return	FAIL ;

	/* 리얼에서만 메일 발송 */
	if (! real)
		return	SUCCESS ;

	/*
	Signature 값 생성: AWS Secret Key 를 Key 로 하고 Date 헤더로 설정할 현재 시간값을 Value 로 해서 
	HMAC SHA256 으로 암호화하고 그 값을 다시 Base64 인코딩하면 된다. 

	1. signature 값 생성 예제
		echo -en "Fri, 13 Sep 2013 06:53:00 +0000" | openssl dgst -sha256 -hmac "zdjsyjiNav5xUkK8RylI3pZToPQX/4CfgfRUS9uQ" -binary|base64

	2. signature 값을 사용한 이메일 전송 예제
		curl -H"Date: Fri, 13 Sep 2013 06:53:00 +0000" -H"X-Amzn-Authorization: AWS3-HTTPS AWSAccessKeyId=AKIAJC7NWNQSWX5FXUHQ, Algorithm=HmacSHA256, SignedHeaders=Date, Signature=Goy6n7eAvX/LsA/GgkLmXeUI7AAA7A0qRmHZ6/NxrZc=" "https://email.us-east-1.amazonaws.com/?Action=SendEmail&Source=hello%40i-um.net&Destination.ToAddresses.member.1=seba%40i-um.net&Message.Subject.Data=This%20is%20the%20subject%20line.&Message.Body.Text.Data=Hello.%20I%20hope%20you%20are%20having%20a%20good%20day."
	*/

	time_t		now = time(NULL) ;
	struct tm	now_tm ;
	localtime_r(&now, &now_tm) ;
	const char *	date = tb_date_header_value(r->pool, now_tm) ;
	const char *	signature = tb_aws_signature(r->pool, aws_secret_key, date, 0) ;
	if (! signature)
		return	FAIL ;

	CURL *		curl ;
	CURLcode	res ;

	curl_global_init(CURL_GLOBAL_DEFAULT) ;
	curl = curl_easy_init() ;
	if (! curl)
		return	FAIL ;

	/* Header 추가 */
	struct curl_slist *	header = NULL ;
	header = curl_slist_append(header, "Content-Type: application/x-www-form-urlencoded") ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Date: %s", date)) ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "X-Amzn-Authorization: AWS3-HTTPS AWSAccessKeyId=%s, Algorithm=HmacSHA256, SignedHeaders=Date, Signature=%s", aws_access_key, signature)) ;
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header) ;

	/* URL 설정 */
	const char *	url = "https://email.us-east-1.amazonaws.com/" ;
	curl_easy_setopt(curl, CURLOPT_URL, url) ;
	curl_easy_setopt(curl, CURLOPT_POST, 1) ;

	char *		post_data = apr_psprintf(r->pool, "Action=SendEmail&Source=%s&Destination.ToAddresses.member.1=%s&Message.Subject.Data=%s&Message.Body.%s.Data=%s", tb_escape_url(r->pool, ses_email_sender), tb_escape_url(r->pool, email), tb_escape_url(r->pool, subject), html ? "Html" : "Text", tb_escape_url(r->pool, content)) ;
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data) ;

	/* 인증서 확인 skip */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L) ;
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L) ;

	/* timeout 설정 */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10) ;

	/* response 데이터 구조 초기화 */
	curl_data.pool = r->pool ;
	curl_data.a = apr_array_make(r->pool, 4, sizeof(char *)) ;

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_read_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &curl_data);

	res = curl_easy_perform(curl) ;
	if (res != CURLE_OK)
	{
		TB_LOG_ERROR(r, "%s: curl_easy_perform URL: [%s] failed: %s: post: [%s]", __FUNCTION__, url, curl_easy_strerror(res), post_data) ;
		return	FAIL ;
	}

	curl_slist_free_all(header) ;
	curl_easy_cleanup(curl) ;
	curl_global_cleanup() ;

	const char *	response = apr_array_pstrcat(r->pool, curl_data.a, 0) ;
	if (strncmp(response, "<SendEmailResponse", 18))
	{
		TB_LOG_ERROR(r, "%s: send email to [%s] response is not succeeded: [%s]", __FUNCTION__, email, response) ;
		return	FAIL ;
	}

	return	SUCCESS ;
}

/** @fn void	tb_s3_init (const char * bucket)
    @brief	AWS S3 초기화 : 버킷 등록
    @param	bucket	bucket 이름
*/
void	tb_s3_init (const char * bucket)
{
	tb_strncopy(s3_bucket, bucket, _N(s3_bucket)) ;
}

/** @fn int	tb_s3_upload (request_rec * r, const char * path, const char * data, size_t data_n, const char * content_type, int public_read)
    @brief	AWS S3로 파일 업로드
    @param	r		request_rec. 메모리 할당, 에러 로깅
    @param	path		파일명 포함한 경로
    @param	data		파일 데이터
    @param	data_n		데이터 사이즈
    @param	content_type	데이터 Content-Type
    @param	public_read	1이면 public 권한으로 업로드, 1이 아니면 private 권한으로 업로드
    @return	성공시 SUCCESS, 실패시 FAIL
*/
int	tb_s3_upload (request_rec * r, const char * path, const char * data, size_t data_n, const char * content_type, int public_read)
{
	if (!path || data_n <= 0 || !*aws_access_key || !*aws_secret_key)
		return	FAIL ;

	time_t		now = time(NULL) ;
	struct tm	now_tm ;
	localtime_r(&now, &now_tm) ;

	const char *	date = tb_date_header_value(r->pool, now_tm) ;

	/* 참고: http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationExamples */
	const char *	string_to_sign = apr_psprintf(r->pool, "PUT\n\n%s\n%s\n%s/%s/%s", content_type, date, public_read ? "x-amz-acl:public-read\n" : "", s3_bucket, path) ;
	const char *	signature = tb_aws_signature(r->pool, aws_secret_key, string_to_sign, 1) ;
	if (! signature)
		return	FAIL ;

	CURL *		curl ;
	CURLcode	res ;

	curl_global_init(CURL_GLOBAL_DEFAULT) ;
	curl = curl_easy_init() ;
	if (! curl)
	{
		curl_global_cleanup() ;
		return	FAIL ;
	}

	/* Header 추가 */
	struct curl_slist *	header = NULL ;
	const char *		host = apr_psprintf(r->pool, "%s.s3.amazonaws.com", s3_bucket) ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Host: %s", host)) ;
	if (public_read) header = curl_slist_append(header, "x-amz-acl: public-read") ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Content-Type: %s", content_type)) ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Content-Length: %ld", data_n)) ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Date: %s", date)) ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Authorization: AWS %s:%s", aws_access_key, signature)) ;
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header) ;

	const char *	url = apr_psprintf(r->pool, "http://%s/%s", host, path) ;
	curl_easy_setopt(curl, CURLOPT_URL, url) ;

	curl_easy_setopt(curl, CURLOPT_READFUNCTION, curl_read_put_data) ;
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1) ;
	curl_easy_setopt(curl, CURLOPT_PUT, 1) ;

	struct	PUT_DATA	put_data = { .data = data, .len = data_n } ;
	curl_easy_setopt(curl, CURLOPT_READDATA, &put_data) ;
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, data_n) ;

	/* timeout 설정 */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10) ;

	int	ret = FAIL ;
	do {
		res = curl_easy_perform(curl) ;
		if (res != CURLE_OK)
		{
			TB_LOG_ERROR(r, "%s: curl_easy_perform URL: [%s] failed: %s", __FUNCTION__, url, curl_easy_strerror(res)) ;
			break ;
		}

		long	response_code = 0 ;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) ;
		if (response_code != 200)
		{
			TB_LOG_ERROR(r, "%s: response failed: %ld: URL: [%s]", __FUNCTION__, response_code, url) ;
			break ;
		}

		ret = SUCCESS ;
	} while (0) ;

	curl_slist_free_all(header) ;
	curl_easy_cleanup(curl) ;
	curl_global_cleanup() ;

	return	ret ;
}

/** @fn	int	tb_s3_delete (request_rec * r, const char * path)
    @brief	AWS S3 파일 삭제
    @param	r	request_rec. 메모리 할당, 에러 로깅
    @param	path	파일명 포함한 경로
    @return	성공시 SUCCESS, 실패시 FAIL. 삭제할 파일이 없는 경우에도 SUCCESS
*/
int	tb_s3_delete (request_rec * r, const char * path)
{
	if (!path || !*aws_access_key || !*aws_secret_key)
		return	FAIL ;

	time_t		now = time(NULL) ;
	struct tm	now_tm ;
	localtime_r(&now, &now_tm) ;

	const char *	date = tb_date_header_value(r->pool, now_tm) ;

	/* 참고: http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationExamples */
	const char *	string_to_sign = apr_psprintf(r->pool, "DELETE\n\n\n%s\n/%s/%s", date, s3_bucket, path) ;
	const char *	signature = tb_aws_signature(r->pool, aws_secret_key, string_to_sign, 1) ;
	if (! signature)
		return	FAIL ;

	CURL *		curl ;
	CURLcode	res ;

	curl_global_init(CURL_GLOBAL_DEFAULT) ;
	curl = curl_easy_init() ;
	if (! curl)
	{
		curl_global_cleanup() ;
		return	FAIL ;
	}

	/* Header 추가 */
	struct curl_slist *	header = NULL ;
	const char *		host = apr_psprintf(r->pool, "%s.s3.amazonaws.com", s3_bucket) ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Host: %s", host)) ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Date: %s", date)) ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Authorization: AWS %s:%s", aws_access_key, signature)) ;
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header) ;

	const char *	url = apr_psprintf(r->pool, "http://%s/%s", host, path) ;
	curl_easy_setopt(curl, CURLOPT_URL, url) ;
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE") ;

	/* timeout 설정 */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10) ;

	int	ret = FAIL ;
	do {
		res = curl_easy_perform(curl) ;
		if (res != CURLE_OK)
		{
			TB_LOG_ERROR(r, "%s: curl_easy_perform URL: [%s] failed: %s", __FUNCTION__, url, curl_easy_strerror(res)) ;
			break ;
		}

		long	response_code = 0 ;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) ;
		if (response_code != 200 && response_code != 204)
		{
			TB_LOG_ERROR(r, "%s: response failed: %ld: URL: [%s]", __FUNCTION__, response_code, url) ;
			break ;
		}

		ret = SUCCESS ;
	} while (0) ;

	curl_slist_free_all(header) ;
	curl_easy_cleanup(curl) ;
	curl_global_cleanup() ;

	return	ret ;
}

/** @fn	int	tb_s3_move (request_rec * r, const char * src_path, const char * dest_path, int public_read)
    @brief	AWS S3 파일 이동
    @param	r		request_rec. 메모리 할당, 에러 로깅
    @param	src_path	파일명 포함한 원본 경로
    @param	dest_path	파일명 포함한 대상 경로
    @param	public_read	1이면 public 권한, 1이 아니면 private 권한을 이동할 파일에 부여함
    @return	성공시 SUCCESS, 실패시 FAIL
*/
int	tb_s3_move (request_rec * r, const char * src_path, const char * dest_path, int public_read)
{
	if (!src_path || !dest_path || !*aws_access_key || !*aws_secret_key)
		return	FAIL ;

	time_t		now = time(NULL) ;
	struct tm	now_tm ;
	localtime_r(&now, &now_tm) ;

	const char *	date = tb_date_header_value(r->pool, now_tm) ;
	const char *	src_full_path = apr_psprintf(r->pool, "/%s/%s", s3_bucket, src_path) ;
	const char *	dest_full_path = apr_psprintf(r->pool, "/%s/%s", s3_bucket, dest_path) ;

	/* 참고: http://docs.aws.amazon.com/AmazonS3/latest/dev/CopyingObjectUsingREST.html */
	const char *	string_to_sign = apr_psprintf(r->pool, "PUT\n\n\n%s\n%sx-amz-copy-source:%s\nx-amz-storage-class:REDUCED_REDUNDANCY\n%s", date, public_read ? "x-amz-acl:public-read\n" : "", src_full_path, dest_full_path) ;
	const char *	signature = tb_aws_signature(r->pool, aws_secret_key, string_to_sign, 1) ;
	if (! signature)
		return	FAIL ;

	CURL *		curl ;
	CURLcode	res ;

	curl_global_init(CURL_GLOBAL_DEFAULT) ;
	curl = curl_easy_init() ;
	if (! curl)
	{
		curl_global_cleanup() ;
		return	FAIL ;
	}

	/* Header 추가 */
	struct curl_slist *	header = NULL ;
	const char *		host = apr_psprintf(r->pool, "%s.s3.amazonaws.com", s3_bucket) ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Host: %s", host)) ;
	if (public_read) header = curl_slist_append(header, "x-amz-acl: public-read") ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "x-amz-copy-source: %s", src_full_path)) ;
	header = curl_slist_append(header, "x-amz-storage-class: REDUCED_REDUNDANCY") ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Authorization: AWS %s:%s", aws_access_key, signature)) ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Date: %s", date)) ;
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header) ;

	const char *	url = apr_psprintf(r->pool, "http://%s/%s", host, dest_path) ;
	curl_easy_setopt(curl, CURLOPT_URL, url) ;

	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1) ;
	curl_easy_setopt(curl, CURLOPT_PUT, 1) ;
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, 0) ;

	/* timeout 설정 */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10) ;

	int	ret = FAIL ;
	do {
		res = curl_easy_perform(curl) ;
		if (res != CURLE_OK)
		{
			TB_LOG_ERROR(r, "%s: curl_easy_perform URL: [%s] failed: %s", __FUNCTION__, url, curl_easy_strerror(res)) ;
			break ;
		}

		long	response_code = 0 ;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) ;
		if (response_code != 200)
		{
			TB_LOG_ERROR(r, "%s: response failed: %ld: URL: [%s]", __FUNCTION__, response_code, url) ;
			break ;
		}

		ret = SUCCESS ;
	} while (0) ;

	curl_slist_free_all(header) ;
	curl_easy_cleanup(curl) ;
	curl_global_cleanup() ;

	if (ret == SUCCESS)
		ret = tb_s3_delete(r, src_path) ;

	return	ret ;
}

enum
{
	AWS_SERVICE_SQS = 0,
	AWS_SERVICE_SNS,

	AWS_SERVICE_NUMBER
} ;

static	struct
{
	const char *	name ;
	const char *	domain ;
	const char *	version ;
} aws_service_list [] =
{
	[AWS_SERVICE_SQS] = {	"sqs",	"sqs.ap-northeast-1.amazonaws.com",	"2012-11-05"	},
	[AWS_SERVICE_SNS] = {	"sns",	"sns.ap-northeast-1.amazonaws.com",	"2010-03-31"	},
} ;

static	AWS_RESPONSE_T *	send_aws_request (request_rec * r, int service, const char * path, const char * params_url)
{
	if (service < 0 || service >= AWS_SERVICE_NUMBER || !path || !params_url)
		return	NULL ;

	/* 참고
		http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/MakingRequests_MakingQueryRequestsArticle.html
		http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
	*/

	time_t		now = time(NULL) ;
	struct tm	now_tm ;
	localtime_r(&now, &now_tm) ;

	const char *	timestamp = tb_date_extended(r->pool, now_tm) ;
	const char *	query = apr_psprintf(r->pool, "%s&AWSAccessKeyId=%s&Version=%s&Timestamp=%s&SignatureVersion=4&SignatureMethod=HmacSHA256", params_url, aws_access_key, aws_service_list[service].version, timestamp) ;
	const char *	gmt_date = tb_date_basic(r->pool, now, 1) ;
	const char *	date_short = apr_psprintf(r->pool, "%.8s", gmt_date) ;
	const char *	hashed_payload = tb_sha256_hash(r->pool, query) ;
	const char *	canonical_request = apr_psprintf(r->pool, "POST\n%s\n\ncontent-type:application/x-www-form-urlencoded\nhost:%s\n\ncontent-type;host\n%s", path, aws_service_list[service].domain, hashed_payload) ; 

	const char *	hashed_canonical_request = tb_sha256_hash(r->pool, canonical_request) ;
	const char *	credential_scope = apr_psprintf(r->pool, "%s/ap-northeast-1/%s/aws4_request", date_short, aws_service_list[service].name) ;
	const char *	string_to_sign = apr_psprintf(r->pool, "AWS4-HMAC-SHA256\n%.15sZ\n%s\n%s", gmt_date, credential_scope, hashed_canonical_request) ;

	const char *		k_secret = apr_psprintf(r->pool, "AWS4%s", aws_secret_key) ;
	const unsigned char *	k_date = generate_hmac_sha256(r->pool, k_secret, strlen(k_secret), date_short, strlen(date_short), 1) ;
	const unsigned char *	k_region = generate_hmac_sha256(r->pool, k_date, 32, "ap-northeast-1", 14, 1) ;
	const unsigned char *	k_service = generate_hmac_sha256(r->pool, k_region, 32, aws_service_list[service].name, strlen(aws_service_list[service].name), 1) ;
	const unsigned char *	k_signing = generate_hmac_sha256(r->pool, k_service, 32, "aws4_request", 12, 1) ;

	const char *	signature = generate_hmac_sha256(r->pool, k_signing, 32, string_to_sign, strlen(string_to_sign), 0) ;
	if (! signature)
		return	NULL ;

	CURL *		curl ;
	CURLcode	res ;

	curl_global_init(CURL_GLOBAL_DEFAULT) ;
	curl = curl_easy_init() ;
	if (! curl)
		return	NULL ;

	/* Header 추가 */
	struct curl_slist *	header = NULL ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Host: %s", aws_service_list[service].domain)) ;
	header = curl_slist_append(header, "Content-Type: application/x-www-form-urlencoded") ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "x-amz-date: %s", timestamp)) ;
	header = curl_slist_append(header, apr_psprintf(r->pool, "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host, Signature=%s", aws_access_key, credential_scope, signature)) ;
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header) ;

	const char *	url = apr_psprintf(r->pool, "http://%s%s", aws_service_list[service].domain, path) ;
	curl_easy_setopt(curl, CURLOPT_URL, url) ;
	curl_easy_setopt(curl, CURLOPT_POST, 1) ;

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query) ;

	/* timeout 설정 */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10) ;

	/* response 데이터 구조 초기화 */
	curl_data.pool = r->pool ;
	curl_data.a = apr_array_make(r->pool, 4, sizeof(char *)) ;

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_read_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &curl_data);

	AWS_RESPONSE_T *	response = NULL ;
	res = curl_easy_perform(curl) ;
	if (res == CURLE_OK)
	{
		response = apr_palloc(r->pool, sizeof(AWS_RESPONSE_T)) ;
		response->body = apr_array_pstrcat(r->pool, curl_data.a, 0) ;

		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &(response->status)) ;
		if (response->status != 200)
			TB_LOG_ERROR(r, "%s: response failed: %ld: URL: [%s] POST: [%s] response: [%s]", __FUNCTION__, response->status, url, query, response->body) ;
	}
	else
		TB_LOG_ERROR(r, "%s: curl_easy_perform URL: [%s] POST: [%s] failed: %s", __FUNCTION__, url, query, curl_easy_strerror(res)) ;

	curl_slist_free_all(header) ;
	curl_easy_cleanup(curl) ;
	curl_global_cleanup() ;

	return	response ;
}

/** @fn int	tb_sqs_send (request_rec * r, const char * endpoint, const char * body)
    @brief	AWS SQS 메세지 발송
    @param	r		request_rec. 메모리 할당, 에러 로깅
    @param	endpoint	메세지 쌓을 SQS endpoint. e.g.) /123456789/test_sqs/
    @param	body		메시지 본문
    @return	성공시 SUCCESS, 실패시 FAIL
*/
int	tb_sqs_send (request_rec * r, const char * endpoint, const char * body)
{
	if (!endpoint || !body)
		return	FAIL ;

	AWS_RESPONSE_T *	res = send_aws_request(r, AWS_SERVICE_SQS, endpoint, apr_psprintf(r->pool, "Action=SendMessage&MessageBody=%s", tb_escape_url(r->pool, body))) ;
	if (!res || res->status != 200)
		return	FAIL ;

	return	SUCCESS ;
}

enum
{
	MOBILE_TYPE_IPHONE = 0,
	MOBILE_TYPE_ANDROID,

	MOBILE_TYPE_NUMBER
} ;

static	char 	push_arn [MOBILE_TYPE_NUMBER][128] ; 

/** @fn void	tb_sns_push_init (const char * ios_arn, const char * android_arn)
    @brief	AWS SNS Push 초기화 : iOS, Android 푸시 발송 위한 ARN 등록
    @param	ios_arn		iOS ARN
    @param	android_arn	Android ARN
*/
void	tb_sns_push_init (const char * ios_arn, const char * android_arn)
{
	tb_strncopy(push_arn[MOBILE_TYPE_IPHONE], ios_arn, _N(*push_arn)) ;
	tb_strncopy(push_arn[MOBILE_TYPE_ANDROID], android_arn, _N(*push_arn)) ;
}

static	int	get_mobile_type (const char * mobile_type)
{
	int	type = -1 ;
	if (! strcasecmp(mobile_type, "IPHONE"))
		type = MOBILE_TYPE_IPHONE ;
	else if (! strcasecmp(mobile_type, "ANDROID"))
		type = MOBILE_TYPE_ANDROID ;

	return	type ;
}

/** @fn AWS_RESPONSE_T *	tb_sns_add_push_key_raw (request_rec * r, const char * user_data, const char * mobile_type, const char * device_key)
    @brief		SNS Push 발송 위한 device key 추가
    @param		r		request_rec. 메모리 할당, 에러 로깅
    @param		user_data	사용자 구분 위한 데이터
    @param		mobile_type	iOS, Android 구분 위한 값. IPHONE / ANDROID 둘 중 하나의 값이어야함
    @param		device_key	device key
    @return		성공시 AWS_RESPONSE_T 포인터 반환, 실패시 NULL 반환
*/
AWS_RESPONSE_T *	tb_sns_add_push_key_raw (request_rec * r, const char * user_data, const char * mobile_type, const char * device_key)
{
	if (!user_data || !mobile_type || !device_key)
		return	NULL ;

	int	type = get_mobile_type(mobile_type) ;
	if (type == -1 || !*push_arn[type])
		return	NULL ;

	const char *	arn = push_arn[type] ;
	return	 send_aws_request(r, AWS_SERVICE_SNS, "/", apr_psprintf(r->pool, "PlatformApplicationArn=%s&Action=CreatePlatformEndpoint&CustomUserData=%s&Token=%s", tb_escape_url(r->pool, arn), tb_escape_url(r->pool, user_data), tb_escape_url(r->pool, device_key))) ;
}

/** @fn const char *	tb_sns_parse_arn (apr_pool_t * pool, const char * body)
    @brief		SNS device key 등록 후 받은 응답에서 arn 뽑아내기
    @param		pool	메모리 풀
    @param		body	device key 등록 API 호출의 응답 body
    @return		sns arn. 실패시 NULL
*/
const char *	tb_sns_parse_arn (apr_pool_t * pool, const char * body)
{
	if (!pool || !body)
		return	NULL ;

	static const	char	arn_start[] = "<EndpointArn>" ;
	char *			s = strstr(body, arn_start) ;
	if (! s)
		return	NULL ;

	char	buf [256] ;
	s += strlen(arn_start) ;
	sscanf(s, "%[^<]", buf) ;

	return	apr_pstrdup(pool, buf) ;
}

/** @fn const char *	tb_sns_add_push_key (request_rec * r, const char * user_data, const char * mobile_type, const char * device_key)
    @brief		SNS Push 발송 위한 device key 추가
    @param		r		request_rec. 메모리 할당, 에러 로깅
    @param		user_data	사용자 구분 위한 데이터
    @param		mobile_type	iOS, Android 구분 위한 값. IPHONE / ANDROID 둘 중 하나의 값이어야함
    @param		device_key	device key
    @return		device key로 등록한 Push 발송용 endpoint ARN 반환. 실패시 NULL 반환
*/
const char *	tb_sns_add_push_key (request_rec * r, const char * user_data, const char * mobile_type, const char * device_key)
{
	AWS_RESPONSE_T *	res = tb_sns_add_push_key_raw(r, user_data, mobile_type, device_key) ;
	if (!res || res->status != 200)
		return	NULL ;

	return	tb_sns_parse_arn(r->pool, res->body) ;
}

/** @fn int	tb_sns_arn_delete (request_rec * r, const char * sns_arn)
    @brief	Push 발송용 endpoint ARN 삭제
    @param	r	request_rec. 메모리 할당, 에러 로깅
    @param	sns_arn	삭제할 endpoint ARN
    @return	성공시 SUCCESS, 실패시 FAIL
*/
int	tb_sns_arn_delete (request_rec * r, const char * sns_arn)
{
	if (! sns_arn)
		return	FAIL ;

	AWS_RESPONSE_T *	res = send_aws_request(r, AWS_SERVICE_SNS, "/", apr_psprintf(r->pool, "Action=DeleteEndpoint&EndpointArn=%s", tb_escape_url(r->pool, sns_arn))) ;
	if (!res || res->status != 200)
		return	FAIL ;

	return	SUCCESS ;
}

struct	CUSTOM_PARAM_T
{
	apr_array_header_t *	a ;
	apr_pool_t *		pool ;
} ;

static	int	add_param_to_array (void * rec, const char * key, const char * value)
{
	struct CUSTOM_PARAM_T *	add = (struct CUSTOM_PARAM_T *)rec ;
	if (!add->a || !add->pool || !key)
		return	1 ;

	value = value ? : "" ;
	APR_ARRAY_PUSH(add->a, const char *) = apr_psprintf(add->pool, "\\\"%s\\\":\\\"%s\\\"", key, tb_json_escaped_string(add->pool, value)) ;

	return	1 ;
}

#define	ALERT_TEMPLATE		"<<<alert>>>"
#define	IPHONE_PAYLOAD_SIZE	256

/** @fn int	tb_sns_push_send (request_rec * r, const char * mobile_type, const char * sns_arn, const char * message, int badge, apr_table_t * custom, int real)
    @brief	Push 발송. IPHONE 배지 표시 가능한 함수
    @param	r		request_rec. 메모리 할당, 에러 로깅
    @param	mobile_type	IPHONE / ANDROID
    @param	sns_arn		Push 발송할 endpoint ARN
    @param	message		발송할 메세지
    @param	badge		앱 아이콘에 표시할 배지수. IPHONE에만 해당함
    @param	custom		기본 필드 외에 추가로 붙일 custom field table
    @param	real		IPHONE SANDBOX 구분 위한 값. 1이면 APNS, 1이 아니면 APNS SANDBOX로 발송
    @return	성공시 AWS_RESPONSE_T 포인터 반환, 실패시 NULL 반환
*/
AWS_RESPONSE_T *	tb_sns_push_send (request_rec * r, const char * mobile_type, const char * sns_arn, const char * message, int badge, apr_table_t * custom, int real)
{
	AWS_RESPONSE_T *	response = NULL ;
	if (!sns_arn || !mobile_type || !message)
		return	response ;

	int	type = get_mobile_type(mobile_type) ;
	if (type == -1 || !*push_arn[type])
		return	response ;

	const char *	custom_add = "" ;
	if (custom)
	{
		apr_array_header_t *	a = apr_array_make(r->pool, 2, sizeof(char *)) ;
		struct CUSTOM_PARAM_T	add = { .a = a, .pool = r->pool } ;
		apr_table_do(add_param_to_array, &add, custom, NULL) ;

		custom_add = apr_array_pstrcat(r->pool, a, ',') ;
	}

	const char *	data = NULL ;
	if (type == MOBILE_TYPE_IPHONE)
	{
		/* 256byte 제한이 있어서 잘라서 보내기 */
		const char *	badge_add = badge > 0 ? apr_psprintf(r->pool, ",\\\"badge\\\":%d", badge) : "" ;
		const char *	template = apr_psprintf(r->pool, "\"{\\\"aps\\\":{\\\"alert\\\":\\\"%s\\\", \\\"sound\\\":\\\"default\\\"%s}%s%s}\"", ALERT_TEMPLATE, badge_add, *custom_add ? ", " : "", custom_add) ;
		size_t		message_n = strlen(message) ;
		size_t		len = strlen(template) - strlen(ALERT_TEMPLATE) + message_n ;
		if (len > IPHONE_PAYLOAD_SIZE)
		{
			/* 90byte로 하면 한글 기준으로 2줄 거의 다 차서 나옴 */
			size_t	curtail_n = message_n - (len - IPHONE_PAYLOAD_SIZE) ;
			if (curtail_n > 90) curtail_n = 90 ;
			message = tb_curtail_string(r->pool, message, curtail_n, "...") ;
		}

		const char *	payload = tb_replace_string(r->pool, template, ALERT_TEMPLATE, tb_json_escaped_string(r->pool, tb_json_escaped_string(r->pool, message))) ;
		data = apr_psprintf(r->pool, "{ \"APNS%s\":%s }", real ? "" : "_SANDBOX", payload) ;
	}
	else if (type == MOBILE_TYPE_ANDROID)
	{
		const char *	key = "message" ;
		data = apr_psprintf(r->pool, "{ \"GCM\":\"{\\\"data\\\":{\\\"%s\\\":\\\"%s\\\"%s%s} }\"}", key, tb_json_escaped_string(r->pool, tb_json_escaped_string(r->pool, message)), *custom_add ? ", " : "", custom_add) ;
	}

	if (! data)
		return	response ;

	response = send_aws_request(r, AWS_SERVICE_SNS, "/", apr_psprintf(r->pool, "Action=Publish&TargetArn=%s&Message=%s&MessageStructure=json", tb_escape_url(r->pool, sns_arn), tb_escape_url(r->pool, data))) ;
	if (response)
		response->data = data ;

	return	response ;
}

/** @fn int	tb_sns_push_publish (request_rec * r, const char * mobile_type, const char * sns_arn, const char * message, apr_table_t * custom, int real)
    @brief	Push 발송
    @param	r		request_rec. 메모리 할당, 에러 로깅
    @param	mobile_type	IPHONE / ANDROID
    @param	sns_arn		Push 발송할 endpoint ARN
    @param	message		발송할 메세지
    @param	custom		기본 필드 외에 추가로 붙일 custom field table
    @param	real		IPHONE SANDBOX 구분 위한 값. 1이면 APNS, 1이 아니면 APNS SANDBOX로 발송
    @return	성공시 AWS_RESPONSE_T 포인터 반환, 실패시 NULL 반환
*/
AWS_RESPONSE_T *	tb_sns_push_publish (request_rec * r, const char * mobile_type, const char * sns_arn, const char * message, apr_table_t * custom, int real)
{
	return	tb_sns_push_send(r, mobile_type, sns_arn, message, 0, custom, real) ;
}

/** @fn int	tb_sns_set_endpoint_attributes (request_rec * r, const char * sns_arn, const char * key, const char * value)
    @brief	Endpoint attribute 설정
    @param	r		request_rec. 메모리 할당, 에러 로깅
    @param	sns_arn		endpoint ARN
    @param	key		설정할 attribute key
    @param	value		설정할 attirbute value
    @return	성공시 SUCCESS, 실패시 FAIL
*/
int	tb_sns_set_endpoint_attributes (request_rec * r, const char * sns_arn, const char * key, const char * value)
{
	if (!sns_arn || !key || !value)
		return	FAIL ;

	AWS_RESPONSE_T *	res = send_aws_request(r, AWS_SERVICE_SNS, "/", apr_psprintf(r->pool, "Action=SetEndpointAttributes&Attributes.entry.1.key=%s&Attributes.entry.1.value=%s&EndpointArn=%s", tb_escape_url(r->pool, key), tb_escape_url(r->pool, value), tb_escape_url(r->pool, sns_arn))) ;
	if (!res || res->status != 200)
		return	FAIL ;

	return	SUCCESS ;
}

static	char		cf_key_pair_id [64] ;
static	EVP_PKEY *	cf_pkey ;

/** @fn void	tb_cf_signer_init (const char * key_pair_id, char * private_key)
    @brief	CloudFront signed URL 생성기 초기화
    @param	key_pair_id	CloudFront Key Pair Access Key ID
    @param	private_key	Private Key 파일 내용을 문자열로 전달
*/
void	tb_cf_signer_init (const char * key_pair_id, char * private_key)
{
	tb_strncopy(cf_key_pair_id, key_pair_id, _N(cf_key_pair_id)) ;

	BIO *	bio = BIO_new_mem_buf(private_key, strlen(private_key)) ;
	cf_pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL) ;
	BIO_free(bio) ;
}

/** @fn void	tb_cf_signer_final (void)
    @brief	CloudFront signed URL 생성기 완료
*/
void	tb_cf_signer_final (void)
{
	if (cf_pkey)
		EVP_PKEY_free(cf_pkey) ;
}

static	void	cf_url_safe (char * src)
{
	char *	p = src ;
	while (*p)
	{
		if (*p == '+')
			*p = '-' ;
		else if (*p == '=')
			*p = '_' ;
		else if (*p == '/')
			*p = '~' ;

		p++ ;
	}
}

/** @fn const char *	tb_cf_signer_get_url (apr_pool_t * pool, const char * base_url, time_t expire)
    @brief	CloudFront signed URL 생성
    @param	pool		메모리 할당 풀
    @param	base_url	resource에 대한 base URL. http 로 시작해야함
    @param	expire		expire 시간
    @return	base_url에 대한 signed URL 반환. 실패시 NULL 반환
*/
const char *	tb_cf_signer_get_url (apr_pool_t * pool, const char * base_url, time_t expire)
{
	const char *	resource = base_url ;
	if (strncmp(base_url, "http", 4))
	{
		char *	p = strstr(base_url, "://") ;
		if (p)
			resource = apr_psprintf(pool, "http%s", p) ;
		else
			resource = apr_psprintf(pool, "http://%s", base_url) ;
	}

	const char *	canned_policy = apr_psprintf(pool, "{\"Statement\":[{\"Resource\":\"%s\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":%ld}}}]}", resource, expire) ;
	EVP_MD_CTX *	md_ctx = EVP_MD_CTX_create() ;
	const EVP_MD *	md = EVP_sha1() ;
	unsigned int	signature_len = EVP_PKEY_size(cf_pkey) ;
	unsigned char	signature[signature_len + 1] ;

	EVP_SignInit(md_ctx, md) ;
	if (!EVP_SignUpdate(md_ctx, canned_policy, strlen(canned_policy)) || !EVP_SignFinal(md_ctx, signature, &signature_len, cf_pkey))
		return	NULL ;

	char		encoded_signature[signature_len * 2 +1] ;
	if (apr_base64_encode(encoded_signature, (const char *)signature, signature_len) <= 0)
		return	NULL ;
	cf_url_safe(encoded_signature) ;

	return	apr_psprintf(pool, "%s?Expires=%ld&Signature=%s&Key-Pair-Id=%s", resource, expire, encoded_signature, cf_key_pair_id) ;
}

