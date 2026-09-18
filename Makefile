# ============================================================================
# Makefile для tping / tping3
# Сборка: make
# Очистка: make clean
# ============================================================================

CXX      = g++
CXXFLAGS = -O2 -pthread -std=c++17 -Wall
LDFLAGS_COMMON = -pthread

# Linux: используется -lcap для tping, -lcurl -lssl -lcrypto для tping3
# macOS:  замените -lcap на пустоту, libcurl/openssl через brew --prefix
# Windows (MSYS2): -lcap уберите, добавьте -lws2_32

TARGET_TPING  = tping
TARGET_TPING3 = tping3

# Флаги для tping
TPING_LIBS  = -lcap

# Флаги для tping3
TPING3_LIBS = -lcurl -lssl -lcrypto

all: $(TARGET_TPING) $(TARGET_TPING3)

# ---------- Сборка tping ----------
$(TARGET_TPING): tping.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(TPING_LIBS) $(LDFLAGS_COMMON)

# ---------- Сборка tping3 ----------
$(TARGET_TPING3): tping3.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(TPING3_LIBS) $(LDFLAGS_COMMON)

# ---------- Установка в систему ----------
install: all
	sudo cp $(TARGET_TPING)  /usr/local/bin/$(TARGET_TPING)
	sudo cp $(TARGET_TPING3) /usr/local/bin/$(TARGET_TPING3)
	sudo setcap cap_net_raw+ep /usr/local/bin/$(TARGET_TPING)
	@echo "[+] Установка завершена."

# ---------- Удаление ----------
uninstall:
	sudo rm -f /usr/local/bin/$(TARGET_TPING)
	sudo rm -f /usr/local/bin/$(TARGET_TPING3)
	@echo "[-] Удалено."

# ---------- Очистка ----------
clean:
	rm -f $(TARGET_TPING) $(TARGET_TPING3)
	rm -rf logs report.html

.PHONY: all install uninstall clean