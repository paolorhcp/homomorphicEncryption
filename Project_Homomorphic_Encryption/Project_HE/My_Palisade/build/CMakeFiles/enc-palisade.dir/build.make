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
include CMakeFiles/enc-palisade.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/enc-palisade.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/enc-palisade.dir/flags.make

CMakeFiles/enc-palisade.dir/enc_palisade.cpp.o: CMakeFiles/enc-palisade.dir/flags.make
CMakeFiles/enc-palisade.dir/enc_palisade.cpp.o: ../enc_palisade.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ie/Scrivania/My_Palisade/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/enc-palisade.dir/enc_palisade.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/enc-palisade.dir/enc_palisade.cpp.o -c /home/ie/Scrivania/My_Palisade/enc_palisade.cpp

CMakeFiles/enc-palisade.dir/enc_palisade.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/enc-palisade.dir/enc_palisade.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ie/Scrivania/My_Palisade/enc_palisade.cpp > CMakeFiles/enc-palisade.dir/enc_palisade.cpp.i

CMakeFiles/enc-palisade.dir/enc_palisade.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/enc-palisade.dir/enc_palisade.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ie/Scrivania/My_Palisade/enc_palisade.cpp -o CMakeFiles/enc-palisade.dir/enc_palisade.cpp.s

# Object files for target enc-palisade
enc__palisade_OBJECTS = \
"CMakeFiles/enc-palisade.dir/enc_palisade.cpp.o"

# External object files for target enc-palisade
enc__palisade_EXTERNAL_OBJECTS =

enc-palisade: CMakeFiles/enc-palisade.dir/enc_palisade.cpp.o
enc-palisade: CMakeFiles/enc-palisade.dir/build.make
enc-palisade: /usr/local/lib/libPALISADEpke.so.1.11.6
enc-palisade: /usr/local/lib/libPALISADEbinfhe.so.1.11.6
enc-palisade: /usr/local/lib/libPALISADEcore.so.1.11.6
enc-palisade: CMakeFiles/enc-palisade.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ie/Scrivania/My_Palisade/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable enc-palisade"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/enc-palisade.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/enc-palisade.dir/build: enc-palisade

.PHONY : CMakeFiles/enc-palisade.dir/build

CMakeFiles/enc-palisade.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/enc-palisade.dir/cmake_clean.cmake
.PHONY : CMakeFiles/enc-palisade.dir/clean

CMakeFiles/enc-palisade.dir/depend:
	cd /home/ie/Scrivania/My_Palisade/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ie/Scrivania/My_Palisade /home/ie/Scrivania/My_Palisade /home/ie/Scrivania/My_Palisade/build /home/ie/Scrivania/My_Palisade/build /home/ie/Scrivania/My_Palisade/build/CMakeFiles/enc-palisade.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/enc-palisade.dir/depend
