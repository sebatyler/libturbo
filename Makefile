# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

# Default target executed when no arguments are given to make.
default_target: all
.PHONY : default_target

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# The program to use to edit the cache.
CMAKE_EDIT_COMMAND = /usr/bin/ccmake

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ubuntu/src/libturbo

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ubuntu/src/libturbo

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/usr/bin/ccmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache
.PHONY : edit_cache/fast

# Special rule for the target install
install: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Install the project..."
	/usr/bin/cmake -P cmake_install.cmake
.PHONY : install

# Special rule for the target install
install/fast: preinstall/fast
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Install the project..."
	/usr/bin/cmake -P cmake_install.cmake
.PHONY : install/fast

# Special rule for the target install/local
install/local: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing only the local directory..."
	/usr/bin/cmake -DCMAKE_INSTALL_LOCAL_ONLY=1 -P cmake_install.cmake
.PHONY : install/local

# Special rule for the target install/local
install/local/fast: install/local
.PHONY : install/local/fast

# Special rule for the target install/strip
install/strip: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing the project stripped..."
	/usr/bin/cmake -DCMAKE_INSTALL_DO_STRIP=1 -P cmake_install.cmake
.PHONY : install/strip

# Special rule for the target install/strip
install/strip/fast: install/strip
.PHONY : install/strip/fast

# Special rule for the target list_install_components
list_install_components:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Available install components are: \"Unspecified\""
.PHONY : list_install_components

# Special rule for the target list_install_components
list_install_components/fast: list_install_components
.PHONY : list_install_components/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache
.PHONY : rebuild_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/ubuntu/src/libturbo/CMakeFiles /home/ubuntu/src/libturbo/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/ubuntu/src/libturbo/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean
.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named turbo

# Build rule for target.
turbo: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 turbo
.PHONY : turbo

# fast build rule for target.
turbo/fast:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/build
.PHONY : turbo/fast

src/aws.o: src/aws.c.o
.PHONY : src/aws.o

# target to build an object file
src/aws.c.o:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/aws.c.o
.PHONY : src/aws.c.o

src/aws.i: src/aws.c.i
.PHONY : src/aws.i

# target to preprocess a source file
src/aws.c.i:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/aws.c.i
.PHONY : src/aws.c.i

src/aws.s: src/aws.c.s
.PHONY : src/aws.s

# target to generate assembly for a file
src/aws.c.s:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/aws.c.s
.PHONY : src/aws.c.s

src/dateutil.o: src/dateutil.c.o
.PHONY : src/dateutil.o

# target to build an object file
src/dateutil.c.o:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/dateutil.c.o
.PHONY : src/dateutil.c.o

src/dateutil.i: src/dateutil.c.i
.PHONY : src/dateutil.i

# target to preprocess a source file
src/dateutil.c.i:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/dateutil.c.i
.PHONY : src/dateutil.c.i

src/dateutil.s: src/dateutil.c.s
.PHONY : src/dateutil.s

# target to generate assembly for a file
src/dateutil.c.s:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/dateutil.c.s
.PHONY : src/dateutil.c.s

src/image.o: src/image.c.o
.PHONY : src/image.o

# target to build an object file
src/image.c.o:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/image.c.o
.PHONY : src/image.c.o

src/image.i: src/image.c.i
.PHONY : src/image.i

# target to preprocess a source file
src/image.c.i:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/image.c.i
.PHONY : src/image.c.i

src/image.s: src/image.c.s
.PHONY : src/image.s

# target to generate assembly for a file
src/image.c.s:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/image.c.s
.PHONY : src/image.c.s

src/request.o: src/request.c.o
.PHONY : src/request.o

# target to build an object file
src/request.c.o:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/request.c.o
.PHONY : src/request.c.o

src/request.i: src/request.c.i
.PHONY : src/request.i

# target to preprocess a source file
src/request.c.i:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/request.c.i
.PHONY : src/request.c.i

src/request.s: src/request.c.s
.PHONY : src/request.s

# target to generate assembly for a file
src/request.c.s:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/request.c.s
.PHONY : src/request.c.s

src/util.o: src/util.c.o
.PHONY : src/util.o

# target to build an object file
src/util.c.o:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/util.c.o
.PHONY : src/util.c.o

src/util.i: src/util.c.i
.PHONY : src/util.i

# target to preprocess a source file
src/util.c.i:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/util.c.i
.PHONY : src/util.c.i

src/util.s: src/util.c.s
.PHONY : src/util.s

# target to generate assembly for a file
src/util.c.s:
	$(MAKE) -f CMakeFiles/turbo.dir/build.make CMakeFiles/turbo.dir/src/util.c.s
.PHONY : src/util.c.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... install"
	@echo "... install/local"
	@echo "... install/strip"
	@echo "... list_install_components"
	@echo "... rebuild_cache"
	@echo "... turbo"
	@echo "... src/aws.o"
	@echo "... src/aws.i"
	@echo "... src/aws.s"
	@echo "... src/dateutil.o"
	@echo "... src/dateutil.i"
	@echo "... src/dateutil.s"
	@echo "... src/image.o"
	@echo "... src/image.i"
	@echo "... src/image.s"
	@echo "... src/request.o"
	@echo "... src/request.i"
	@echo "... src/request.s"
	@echo "... src/util.o"
	@echo "... src/util.i"
	@echo "... src/util.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system
