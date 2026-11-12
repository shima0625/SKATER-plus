ifeq ($(strip $(DEVKITARM)),)
$(error "DEVKITARM is not set. Set DEVKITARM to the devkitARM directory")
endif

include $(DEVKITARM)/3ds_rules

TARGET      := skater-plus-patcher
BUILD       := build
SOURCES     := source
INCLUDES    := include
ROMFS       := romfs
APP_TITLE   := SKATER+ Patcher
APP_DESCRIPTION := Install or remove the SKATER+ browser patch
APP_AUTHOR  := shima0625
# CIA title version: (major << 10) | (minor << 4) | micro = 0.1.1.
APP_TITLE_VERSION := 17

ARCH        := -march=armv6k -mtune=mpcore -mfloat-abi=hard -mtp=soft
CFLAGS      := -g -Wall -Wextra -Werror -O2 -mword-relocations -ffunction-sections $(ARCH)
CFLAGS      += $(INCLUDE) -D__3DS__
LDFLAGS     := -specs=3dsx.specs -g $(ARCH) -Wl,-Map,$(notdir $*.map),--gc-sections
LIBS        := -lcurl -lmbedtls -lmbedx509 -lmbedcrypto -lz -lctru -lm
LIBDIRS     := $(PORTLIBS) $(CTRULIB)

ifneq ($(BUILD),$(notdir $(CURDIR)))
export OUTPUT := $(CURDIR)/$(TARGET)
export TOPDIR := $(CURDIR)
export VPATH := $(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR := $(CURDIR)/$(BUILD)
CFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
export OFILES := $(CFILES:.c=.o)
export LD := $(CC)
export INCLUDE := $(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) $(foreach dir,$(LIBDIRS),-I$(dir)/include) -I$(CURDIR)/$(BUILD)
export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib)
export _3DSXDEPS := $(OUTPUT).smdh
export _3DSXFLAGS := --smdh=$(OUTPUT).smdh --romfs=$(CURDIR)/$(ROMFS)
export APP_ICON := $(CTRULIB)/default_icon.png

.PHONY: all cia clean
all: $(BUILD)
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile

cia: all
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile cia-package

$(BUILD):
	@mkdir -p $@



clean:
	@rm -rf $(BUILD) $(TARGET).elf $(TARGET).3dsx $(TARGET).smdh $(TARGET).cia

else
DEPENDS := $(OFILES:.o=.d)

.PHONY: all-inner
all-inner: $(OUTPUT).3dsx

$(OUTPUT).3dsx: $(OUTPUT).elf $(OUTPUT).smdh

$(OUTPUT).elf: $(OFILES)

.PHONY: cia-package
cia-package: $(OUTPUT).elf $(OUTPUT).smdh
	$(if $(MAKEROM),$(MAKEROM),makerom) -f cia -o $(OUTPUT).cia -target t -exefslogo -elf $(OUTPUT).elf \
		-ver $(APP_TITLE_VERSION) \
		-rsf $(TOPDIR)/app.rsf -icon $(OUTPUT).smdh -banner $(TOPDIR)/assets/banner.bin \
		-DAPP_ROMFS=$(TOPDIR)/romfs

-include $(DEPENDS)
endif
