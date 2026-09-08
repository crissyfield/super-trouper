.PHONY: check-devkit vet build install run

check-devkit:
	@test -n "$(FRIDA_DEVKIT)" || { printf '%s\n' 'FRIDA_DEVKIT must point to a Frida Core devkit'; exit 1; }
	@test -f "$(FRIDA_DEVKIT)/include/frida-core.h" || { printf '%s\n' 'FRIDA_DEVKIT must contain include/frida-core.h'; exit 1; }
	@test -f "$(FRIDA_DEVKIT)/lib/libfrida-core.a" || { printf '%s\n' 'FRIDA_DEVKIT must contain lib/libfrida-core.a'; exit 1; }

vet: check-devkit
	CGO_ENABLED=1 CGO_CFLAGS="-I$(FRIDA_DEVKIT)/include" CGO_LDFLAGS="-L$(FRIDA_DEVKIT)/lib" go vet ./...

build: check-devkit
	CGO_ENABLED=1 CGO_CFLAGS="-I$(FRIDA_DEVKIT)/include" CGO_LDFLAGS="-L$(FRIDA_DEVKIT)/lib" go build ./...

install: check-devkit
	CGO_ENABLED=1 CGO_CFLAGS="-I$(FRIDA_DEVKIT)/include" CGO_LDFLAGS="-L$(FRIDA_DEVKIT)/lib" go install .

run: check-devkit
	CGO_ENABLED=1 CGO_CFLAGS="-I$(FRIDA_DEVKIT)/include" CGO_LDFLAGS="-L$(FRIDA_DEVKIT)/lib" go run . attach
