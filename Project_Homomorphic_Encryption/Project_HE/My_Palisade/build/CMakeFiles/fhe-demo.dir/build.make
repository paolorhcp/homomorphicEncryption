# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.18

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
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
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ie/Scrivania/My_Palisade

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ie/Scrivania/My_Palisade/build

# Include any dependencies generated for this target.
include CMakeFiles/fhe-demo.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/fhe-demo.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/fhe-demo.dir/flags.make

CMakeFiles/fhe-demo.dir/simple-integers.cpp.o: CMakeFiles/fhe-demo.dir/flags.make
CMakeFiles/fhe-demo.dir/simple-integers.cpp.o: ../simple-integers.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ie/Scrivania/My_Palisade/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/fhe-demo.dir/simple-integers.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/fhe-demo.dir/simple-integers.cpp.o -c /home/ie/Scrivania/My_Palisade/simple-integers.cpp

CMakeFiles/fhe-demo.dir/simple-integers.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/fhe-demo.dir/simple-integers.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ie/Scrivania/My_Palisade/simple-integers.cpp > CMakeFiles/fhe-demo.dir/simple-integers.cpp.i

CMakeFiles/fhe-demo.dir/simple-integers.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/fhe-demo.dir/simple-integers.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ie/Scrivania/My_Palisade/simple-integers.cpp -o CMakeFiles/fhe-demo.dir/simple-integers.cpp.s

# Object files for target fhe-demo
fhe__demo_OBJECTS = \
"CMakeFiles/fhe-demo.dir/simple-integers.cpp.o"

# External object files for target fhe-demo
fhe__demo_EXTERNAL_OBJECTS =

fhe-demo: CMakeFiles/fhe-demo.dir/simple-integers.cpp.o
fhe-demo: CMakeFiles/fhe-demo.dir/build.make
fhe-demo: /usr/local/lib/libPALISADEpke.so.1.11.6
fhe-demo: /usr/local/lib/libPALISADEbinfhe.so.1.11.6
fhe-demo: /usr/local/lib/libPALISADEcore.so.1.11.6
fhe-demo: CMakeFiles/fhe-demo.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ie/Scrivania/My_Palisade/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable fhe-demo"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/fhe-demo.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/fhe-demo.dir/build: fhe-demo

.PHONY : CMakeFiles/fhe-demo.dir/build

CMakeFiles/fhe-demo.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/fhe-demo.dir/cmake_clean.cmake
.PHONY : CMakeFiles/fhe-demo.dir/clean

CMakeFiles/fhe-demo.dir/depend:
	cd /home/ie/Scrivania/My_Palisade/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ie/Scrivania/My_Palisade /home/ie/Scrivania/My_Palisade /home/ie/Scrivania/My_Palisade/build /home/ie/Scrivania/My_Palisade/build /home/ie/Scrivania/My_Palisade/build/CMakeFiles/fhe-demo.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/fhe-demo.dir/depend
