# LLDP Network Scanner (Go)

Real-time SNMP & LLDP network topology discovery, port history (InfluxDB 2), and interactive Web UI (Graph & Tree views).

## Build & Run

```bash
go build -o lldp_scanner .
./lldp_scanner --mode=monitor24h --duration=24h --output=results/24h
```
