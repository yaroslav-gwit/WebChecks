build:
	go build -o bin/webchecks main.go

# Run with table output
runt:
	go build -o bin/webchecks main.go
	bin/webchecks cli

# Run with JSON output
runj:
	go build -o bin/webchecks main.go
	bin/webchecks cli --json

install:
	mkdir -p /opt/webchecks/
	/usr/local/go/bin/go build -o /opt/webchecks/webchecks main.go
	cp db.json.example-1 /opt/webchecks/db.json

update:
	test -e /opt/webchecks/
	/usr/local/go/bin/go build -o /opt/webchecks/webchecks main.go
