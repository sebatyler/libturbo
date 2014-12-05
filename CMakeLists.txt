cmake_minimum_required(VERSION 2.8)

project(libturbo)

add_library(turbo SHARED src/request.c src/util.c src/dateutil.c src/aws.c src/image.c)
include_directories(./ /usr/include/ImageMagick /usr/local/include/httpd /usr/local/include/apr /usr/local/include/apr-util)

add_definitions(-std=gnu99 -Wall)

install(TARGETS turbo DESTINATION lib)
install(FILES src/turbo.h DESTINATION include)
