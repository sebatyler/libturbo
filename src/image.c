//vim:ts=8

/** @file image.c
  * 이미지 변환
  */

#include <curl/curl.h>

#include "apr_base64.h"
#include "turbo.h"

/** @fn	void		tb_image_init ()
    @brief		이미지 변환 초기화
*/
void		tb_image_init ()
{
	MagickWandGenesis() ;
}

/** @fn void		tb_image_final ()
    @brief		이미지 변환 종료
*/
void		tb_image_final ()
{
	MagickWandTerminus() ;
}

/** @fn const char *	tb_image_resize_crop (apr_pool_t * pool, const char * data, size_t data_n, size_t * result_len, int width, int height)
    @brief		이미지 resize & crop
    @param		pool		메모리 할당 풀
    @param		data		이미지 데이터
    @param		data_n		데이터 사이즈
    @param		result_len	변환한 이미지 데이터 사이즈 반환
    @param		width		변환할 이미지 width
    @param		height		변환할 이미지 height
    @return		변환한 이미지 데이터 포인터. 실패시 NULL 반환
*/
const char *	tb_image_resize_crop (apr_pool_t * pool, const char * data, size_t data_n, size_t * result_len, int width, int height)
{
	char *	result = NULL ;

	do {
		if (!data || data_n <= 0)
			break ;

		/* resize & crop */
		MagickWand *	wand = NewMagickWand() ;
		if (! wand)
			break ;

		if (MagickReadImageBlob(wand, data, data_n) == MagickFalse)
			break ;

		int	w = MagickGetImageWidth(wand);
		int	h = MagickGetImageHeight(wand);
		double	ratio_w = (double)width / w ; 
		double	ratio_h = (double)height / h ;
		double	ratio = ratio_w > ratio_h ? ratio_w : ratio_h ;
		int	new_w = w * ratio ;
		int	new_h = h * ratio ;

		if (MagickResizeImage(wand, new_w, new_h, 0, 1) == MagickFalse)
			break ;
		if (MagickCropImage(wand, width, height, (new_w - width) / 2, (new_h - height) / 2) == MagickFalse)
			break ;
		if (MagickSetImageCompressionQuality(wand, 95) == MagickFalse)
			break ;

		MagickResetIterator(wand) ;
		unsigned char *	image = MagickGetImageBlob(wand, result_len) ;
		if (!image || *result_len <= 0)
			break ;

		result = apr_palloc(pool, *result_len) ;
		memcpy(result, image, *result_len) ;

		MagickRelinquishMemory(image) ;
		DestroyMagickWand(wand) ;
	} while (0) ;

	return	result ;
}

