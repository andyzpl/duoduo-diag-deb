TARGET := iphone:clang:16.5:13.0
THEOS_PACKAGE_SCHEME = rootless
ARCHS = arm64
INSTALL_TARGET_PROCESSES = AMStation

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = DuoduoDiag
DuoduoDiag_FILES = Tweak.xm
DuoduoDiag_FRAMEWORKS = UIKit Security Foundation
DuoduoDiag_CFLAGS = -fobjc-arc -Wno-unused-parameter

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 AMStation 2>/dev/null || true"
