CC = gcc
CFLAGS = -Wall -Iinclude -I/usr/local/include
LIBS = -lnetfilter_queue -lbloom

# source file for firewall project
SRC = src/main.c src/config_parser.c src/blacklist.c src/packet_filter.c src/bloom_wrapper.c
OBJ = main.o config_parser.o blacklist.o packet_filter.o bloom_wrapper.o

# Streamlit related variable
VENV_NAME = streamlit_env
PYTHON = python3
PIP = pip3
APP_FILE = app.py

# Default target to build firewall
all: firewall

# compile the firewall project
firewall: $(SRC)
	$(CC) $(CFLAGS) -o firewall $(SRC) $(LIBS)

# Run Streamlit app inside the virtual environment
run: $(VENV_NAME)/bin/activate
	$(VENV_NAME)/bin/streamlit run $(APP_FILE)
	@echo "Streamlit app finished. Please deactivate the environment if you are done."


clean:
	rm -f firewall *.o
	rm -rf $(VENV_NAME)

# Optional: Remove virtual environment (if you want to clean up)
clean_venv:
	rm -rf $(VENV_NAME)

# Install dependencies (useful if you have a requirements.txt for Streamlit or other packages)
install: $(VENV_NAME)/bin/activate
	$(VENV_NAME)/bin/$(PIP) install -r requirements.txt
