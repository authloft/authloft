module authloft

go 1.26.1

require (
	connectrpc.com/connect v1.21.1
	github.com/go-sql-driver/mysql v1.10.1
	github.com/go-webauthn/webauthn v0.18.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	// HTTP 框架：Echo v5（docs/后端架构.md §1.5 / CODE_GUIDE §2.3——v5.4.6，
	// 2026-03-31 起 API 冻结；service 及以下不感知框架类型）。
	github.com/labstack/echo/v5 v5.4.6
	github.com/medivhzhan/weapp/v3 v3.8.4
	github.com/pressly/goose/v3 v3.24.0
	// gnata：JSONata 求值统一库（2026-11-05 定稿；后端架构
	// §1.5/§3.12——唯一依赖点 internal/jsonata 封装层，不自研求值器；
	// 文档写 RecoLabs，库 go.mod 声明小写 recolabs，按库声明引入）。
	github.com/recolabs/gnata v0.6.2
	// Redis 客户端：rueidis（RESP3），经 internal/cache 适配层翻译为
	// 自有结果类型，rueidiscompat 不引入。
	github.com/redis/rueidis v1.0.80
	github.com/vmihailenco/msgpack/v5 v5.4.1
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/uptrace/bun v1.3.0
	github.com/uptrace/bun/dialect/mysqldialect v1.3.0
	github.com/uptrace/bun/dialect/pgdialect v1.3.0
	github.com/uptrace/bun/driver/pgdriver v1.3.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/puzpuzpuz/xsync/v3 v3.5.1 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	github.com/sethvargo/go-retry v0.3.0 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/tmthrgd/go-hex v0.0.0-20190904060850-447a3041c3bc // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opentelemetry.io/otel v1.40.0 // indirect
	go.opentelemetry.io/otel/trace v1.40.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	mellium.im/sasl v0.3.2 // indirect
)
