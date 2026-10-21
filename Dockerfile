# 1-bosqich: Dasturni Go yordamida kompilatsiya qilish
FROM golang:1.25-alpine AS builder

# Ishchi katalogni yaratish
WORKDIR /app

# Go modullarini nusxalash va yuklab olish
COPY go.mod go.sum ./
RUN go mod download

# Barcha kodlarni nusxalash
COPY . .

# Dasturni kompilatsiya qilish (statically linked, CGO o'chirilgan)
RUN CGO_ENABLED=0 GOOS=linux go build -o lldp_scanner .


# 2-bosqich: Faqat kerakli narsalarni o'z ichiga olgan minimal imig (Alpine) yaratish
FROM alpine:latest

# Ishchi katalog
WORKDIR /app

# Kerakli paketlarni o'rnatish: tzdata, SNMP tools, ping
RUN apk add --no-cache tzdata net-snmp-tools iputils

# Builder'dan dasturni va kerakli frontend fayllarini olib o'tish
COPY --from=builder /app/lldp_scanner .
COPY --from=builder /app/www ./www/
COPY --from=builder /app/static ./static/
COPY --from=builder /app/swich_ips ./

# Output kataloglarini oldindan yaratib qo'yish
RUN mkdir -p results captures influxdb mermaid_images instrumens

# Dasturning ishlashi uchun kirish nuqtasi
ENTRYPOINT ["./lldp_scanner"]
