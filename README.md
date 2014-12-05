# libturbo

## Intro

libturbo is a library to develop apache module easily.
It provides parsing http request parameters(get, post & multipart) and image resize & crop and AWS function and etc.

## Dependency

### apr 1.5.x & apr-util 1.5.x

- [Download](https://apr.apache.org/download.cgi)

### apache 2.4.x

- [Download](http://httpd.apache.org/download.cgi#apache24)

After compilation, you should make symbolic link for include directories in /usr/local/include directory.
Example is below.

```bash
ll apr apr-util httpd
lrwxrwxrwx 1 root root 41 Jan 21 21:21 apr -> /home/ubuntu/apr/include/apr-1/
lrwxrwxrwx 1 root root 46 Jan 21 21:22 apr-util -> /home/ubuntu/apr-util/include/apr-1/
lrwxrwxrwx 1 root root 37 Jan 21 21:21 httpd -> /home/ubuntu/httpd/include/
```

Or you can modify directory path in CMakeLists.txt.

### ImageMagick

Default, include directory is /usr/include/ImageMagick.
You can modify directory path in CMakeLists.txt.

## Build & Install

```bash
cmake ./
make
sudo make install
```

After install, output paths is below.

header file : /usr/local/include/turbo.h
library file : /usr/local/lib/libturbo.so

