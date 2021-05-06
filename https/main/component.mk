#
# "main" pseudo-component makefile.
#
# (Uses default behaviour of compiling all source files in directory, adding 'include' to include path.)
COMPONENT_SRCDIRS += ../libraries \
	../libraries/acmeclient ../libraries/arduinojson \
	../components/esp_littlefs ../components/littlefs

COMPONENT_ADD_INCLUDEDIRS := ../libraries \
	../libraries/acmeclient \
	../libraries/arduinojson \
	../components/esp_littlefs ../components/littlefs \
	../components \
	.

#
# These lines were copied from make/component_wrapper.mk in the esp-idf distro
# Obviously renamed COMPONENT_OBJS to MY_COMPONENT_OBJS
#
# Currently a copy from the v3.1.3 version
#
MY_COMPONENT_OBJS := $(foreach compsrcdir,$(COMPONENT_SRCDIRS),$(patsubst %.c,%.o,$(wildcard $(COMPONENT_PATH)/$(compsrcdir)/*.c)))
MY_COMPONENT_OBJS += $(foreach compsrcdir,$(COMPONENT_SRCDIRS),$(patsubst %.cpp,%.o,$(wildcard $(COMPONENT_PATH)/$(compsrcdir)/*.cpp)))
MY_COMPONENT_OBJS += $(foreach compsrcdir,$(COMPONENT_SRCDIRS),$(patsubst %.cc,%.o,$(wildcard $(COMPONENT_PATH)/$(compsrcdir)/*.cc)))
MY_COMPONENT_OBJS += $(foreach compsrcdir,$(COMPONENT_SRCDIRS),$(patsubst %.S,%.o,$(wildcard $(COMPONENT_PATH)/$(compsrcdir)/*.S)))
# Make relative by removing COMPONENT_PATH from all found object paths
MY_COMPONENT_OBJS := $(patsubst $(COMPONENT_PATH)/%,%,$(MY_COMPONENT_OBJS))
MY_COMPONENT_OBJS := $(call stripLeadingParentDirs,$(MY_COMPONENT_OBJS))
MY_COMPONENT_OBJS := $(foreach obj,$(MY_COMPONENT_OBJS),$(if $(filter $(abspath $(obj)),$(abspath $(COMPONENT_OBJEXCLUDE))), ,$(obj)))
MY_COMPONENT_OBJS := $(call uniq,$(MY_COMPONENT_OBJS))

#
# Build info
#
COMPONENT_EXTRA_CLEAN := build.h

build.h:	${MY_COMPONENT_OBJS}
	echo "Regenerating build timestamp .."
	echo -n '#define __BUILD__ "' >build.h
	echo -n `date '+%Y/%m/%d %T'` >>build.h
	echo '"' >>build.h

$(COMPONENT_LIBRARY):	$(COMPONENT_BUILD_DIR)/build_date.o

build_date.o: build.h

