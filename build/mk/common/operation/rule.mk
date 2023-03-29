# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

## This function will generate $(1)_objs variables which provided
## the objects needed to compile to the $(1) module.
##
## Args:
##    $(1) : the module name

define eval_objs
ifneq ($(NO_OBJFILE_SORT),y)
$(1)_c_obj_files   = $$(sort $$(patsubst %.c,%.o,$$($(1)_c_files)))
$(1)_cpp_obj_files = $$(sort $$(patsubst %.cpp,%.o,$$($(1)_cpp_files)))
$(1)_asm_obj_files = $$(sort $$(patsubst %.s,%.o,$$($(1)_asm_files)))
$(1)_ASM_obj_files = $$(sort $$(patsubst %.S,%.o,$$($(1)_ASM_files)))
else
$(1)_c_obj_files   = $$(patsubst %.c,%.o,$$($(1)_c_files))
$(1)_cpp_obj_files = $$(patsubst %.cpp,%.o,$$($(1)_cpp_files))
$(1)_asm_obj_files = $$(patsubst %.s,%.o,$$($(1)_asm_files))
$(1)_ASM_obj_files = $$(patsubst %.S,%.o,$$($(1)_ASM_files))
endif

$(1)_objs  = $$(addprefix $(BUILD_DIR)/,$$($(1)_c_obj_files))
$(1)_objs += $$(addprefix $(BUILD_DIR)/,$$($(1)_cpp_obj_files))
$(1)_objs += $$(addprefix $(BUILD_DIR)/,$$($(1)_asm_obj_files))
$(1)_objs += $$(addprefix $(BUILD_DIR)/,$$($(1)_ASM_obj_files))
$(1)_objs += $$(addprefix $(BUILD_DIR)/,$$(patsubst %.c,%.o,$$(CFILES)))
$(1)_objs += $$(addprefix $(BUILD_DIR)/,$$(patsubst %.cpp,%.o,$$(CPPFILES)))
$(1)_objs += $$(addprefix $(BUILD_DIR)/,$$(patsubst %.s,%.o,$$(asmFILES)))
$(1)_objs += $$(addprefix $(BUILD_DIR)/,$$(patsubst %.S,%.o,$$(ASMFILES)))
endef

## provide the static linked target compile rules.
## Args:
##  $(1)  : the $(MODULE_FOLDER) needed to be compile.
##  $(2)  : the $(MODULE_FILE) needed to be generated.
define eval_libs
$(2): $$($(1)_objs)
	@echo "[ AR2 ] $$@ $$^"
	$$(VER)$$(AR) rD $$@ $$^
endef

define eval_elf
$(2): $$($(1)_objs)
	@echo "[ LD ] $$@"
	@test -d $$(dir $$@) || mkdir -p $$(dir $$@)
	$$(VER)$$(LD) $$($(1)_objs) $$($(1)_extracted_objs) $$(LDFLAGS) --build-id=none \
	$$($(1)_LDFLAGS) -o $$@
	$$(OBJCOPY) $$@
endef

## This function will generate $(1)_extracted_objs variables which are
## extracted from the $(2) archive file and provided the objects needed to
## compile to the $(1) module.
##  $(1)  : $(MODULE_FOLDER) needed to be compile.
##  $(2)  : $(PREBUILD_ARCHIVE) needed to be extracted.
##  $(3)  : the $(BUILD_DIR) where target generates.
define eval_extracted_objs
$(1)_extracted_objs += $$(addprefix $(3)/,$$(shell $$(AR) -t $(2)))
endef

## provide an extra archive dependence for the app/driver target
## and the extraction rule
##  $(1)  : the $(BUILD_DIR) where target generates.
##  $(2)  : the $(MODULE_FILE) needed to be generated.
##  $(3)  : the $(PREBUILD_ARCHIVE) needed to be extracted.
define eval_extract_ar
$(1)/.extracted: $(3)
	@echo "extracting $(3)"
	@test -d $$(dir $$@) || mkdir -p $$(dir $$@)
	$$(VER)cd $(1) && $$(AR) -x $(3)
	@touch $$@
$(2): $(1)/.extracted
endef

GENERAL_OPTIONS := -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -fsigned-char -fno-strict-aliasing \
                   -pipe -Wall -Wextra -Werror -fno-common

FILTER_MODULE := open_source openssl bounds_checking_function

# we need function is_filter_module to remove open source files
is_filter_module = $(strip $(foreach module,$(FILTER_MODULE),$(findstring $(module),$1)))

last_component = $(shell echo $1 | awk -F '//' '{print $$NF}')

# we need function uniq to deduplication
uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))

is_abs_path = $(filter $(shell echo $1 | head -c 1),/)

## compile object file rules:
$(BUILD_DIR)/%.o: %.cpp
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CXX ] $@"
	$(VER)$(CXX) -MMD -MP -MF $(BUILD_DIR)/$<.d $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: %.cxx
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CXX ] $@"
	$(VER)$(CXX) -MMD -MP -MF $(BUILD_DIR)/$<.d $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: %.c
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ CC ] $@ "
	$(VER)$(CC) -MMD -MP -MF $(BUILD_DIR)/$<.d $(if $(call is_filter_module,$(call last_component,$@)), \
	$(filter-out -Werror, $(CFLAGS) $(CPPFLAGS)),$(call uniq, \
	$(CFLAGS) $(CPPFLAGS) $(GENERAL_OPTIONS))) -c -o $@ $<

$(BUILD_DIR)/%.o: %.S
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ ASM ] $@"
	$(VER)$(CC) -MMD -MP -MF $(BUILD_DIR)/$<.d $(CPPFLAGS) $(ASFLAGS) -D__ASM__ -c -o $@ $<

$(BUILD_DIR)/%.o: %.s
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo "[ asm ] $@"
	$(VER)$(CC) -MMD -MP -MF $(BUILD_DIR)/$<.d $(CPPFLAGS) $(ASFLAGS) -c -o $@ $<

CPPFLAGS += $(inc-flags)
CFLAGS += $(flags) $(c-flags)
CXXFLAGS += $(cxx-flags)
ASFLAGS += $(asflags)

rwildcard=$(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))

DEPS := $(patsubst %.c,$(BUILD_DIR)/%.c.d,$(call rwildcard,./,*.c))
DEPS += $(patsubst %.cxx,%$(BUILD_DIR)/.cxx.d,$(call rwildcard,./,*.cxx))
DEPS += $(patsubst %.cpp,$(BUILD_DIR)/%.cpp.d,$(call rwildcard,./,*.cpp))
DEPS += $(patsubst %.S,$(BUILD_DIR)/%.S.d,$(call rwildcard,./,*.S))
DEPS += $(patsubst %.s,$(BUILD_DIR)/%.s.d,$(call rwildcard,./,*.s))

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif
