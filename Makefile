GO ?= go

BIN_PATH = $(CURDIR)/bin
CONFIG_PATH = $(CURDIR)/config
SYSTEMD_UNIT_FILE = $(CONFIG_PATH)/bvs2.service
LOG_FILE = $(CONFIG_PATH)/log.xml
SERVER_CONF_FILE = $(CONFIG_PATH)/server_config.json
SYSTEMD_SERVICE_FILE = /lib/systemd/system/bvs2.service
MULTI_USER_TARGET_WANTS_FILE = /etc/systemd/system/multi-user.target.wants/bvs2.service

all: build

build:
	mkdir -p $(BIN_PATH);
	$(GO) build -o $(BIN_PATH)/bvs2 $(CURDIR)/src/imageserver.go;

clean:
	$(GO) clean;
	if [ -f "$(SYSTEMD_UNIT_FILE)" ]; then \
		rm $(SYSTEMD_UNIT_FILE); \
	fi;
	if [ -f "$(LOG_FILE)" ]; then \
		rm $(LOG_FILE); \
	fi;
	if [ -f "$(SERVER_CONF_FILE)" ]; then \
		rm $(SERVER_CONF_FILE); \
	fi;

install:
	if [ ! -f "$(SYSTEMD_SERVICE_FILE)" ]; then \
		cp $(SYSTEMD_UNIT_FILE) $(SYSTEMD_SERVICE_FILE); \
	fi;
	if [ ! -f "$(MULTI_USER_TARGET_WANTS_FILE)" ]; then \
		ln -s $(SYSTEMD_SERVICE_FILE) $(MULTI_USER_TARGET_WANTS_FILE); \
	fi;
	systemctl daemon-reload;
uninstall:
	#XNOTE stop service and rm /usr/sbin/bvs2, SYSTEMD_SERVICE_FILE and MULTI_USER_TARGET_WANTS_FILE
	#XNOTE reload systemd daemon
