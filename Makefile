# ============================================================================
# Makefile для tping / tping2 / tping3 / tping4
# Сборка:    make
# Установка: sudo make install
# Очистка:   make clean
# ============================================================================

CXX      = g++
CXXFLAGS = -O2 -pthread -std=c++17 -Wall
LDFLAGS_COMMON = -pthread

TARGET_TPING  = tping
TARGET_TPING2 = tping2
TARGET_TPING3 = tping3
TARGET_TPING4 = tping4

# Флаги для tping (сетевой нагрузчик, UDP/IPSO/ICMP)
TPING_LIBS  = -lcap

# Флаги для tping2 (низкоуровневый конструктор пакетов, аналог hping3)
TPING2_LIBS = -lcap

# Флаги для tping3 (HTTP/HTTPS нагрузчик)
TPING3_LIBS = -lcurl -lssl -lcrypto

# Флаги для tping4 (L7 slowloris)
TPING4_LIBS =

all: $(TARGET_TPING) $(TARGET_TPING2) $(TARGET_TPING3) $(TARGET_TPING4)

# ---------- Сборка tping ----------
$(TARGET_TPING): tping.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(TPING_LIBS) $(LDFLAGS_COMMON)

# ---------- Сборка tping2 ----------
$(TARGET_TPING2): tping2.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(TPING2_LIBS) $(LDFLAGS_COMMON)

# ---------- Сборка tping3 ----------
$(TARGET_TPING3): tping3.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(TPING3_LIBS) $(LDFLAGS_COMMON)

# ---------- Сборка tping4 ----------
$(TARGET_TPING4): tping4.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(TPING4_LIBS) $(LDFLAGS_COMMON)

# ---------- Установка в систему ----------
install: all
	sudo cp $(TARGET_TPING)  /usr/local/bin/$(TARGET_TPING)
	sudo cp $(TARGET_TPING2) /usr/local/bin/$(TARGET_TPING2)
	sudo cp $(TARGET_TPING3) /usr/local/bin/$(TARGET_TPING3)
	sudo cp $(TARGET_TPING4) /usr/local/bin/$(TARGET_TPING4)
	sudo setcap cap_net_raw+ep /usr/local/bin/$(TARGET_TPING)
	sudo setcap cap_net_raw+ep /usr/local/bin/$(TARGET_TPING2)
	sudo setcap cap_net_raw+ep /usr/local/bin/$(TARGET_TPING3)
	sudo setcap cap_net_raw+ep /usr/local/bin/$(TARGET_TPING4)
	@echo "[+] Установка завершена."

# ---------- Удаление ----------
uninstall:
	sudo rm -f /usr/local/bin/$(TARGET_TPING)
	sudo rm -f /usr/local/bin/$(TARGET_TPING2)
	sudo rm -f /usr/local/bin/$(TARGET_TPING3)
	sudo rm -f /usr/local/bin/$(TARGET_TPING4)
	@echo "[-] Удалено."

# ---------- Очистка ----------
clean:
	rm -f $(TARGET_TPING) $(TARGET_TPING2) $(TARGET_TPING3) $(TARGET_TPING4)
	rm -rf logs report.html

.PHONY: all install uninstall clean