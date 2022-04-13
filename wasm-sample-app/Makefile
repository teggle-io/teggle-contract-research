.PHONY: build _build
build: _build compress-wasm optimize-wasm
_build:
	RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown --features="debug-print"

.PHONY: build-profile _build-profile
build-profile: _build-profile compress-wasm optimize-wasm
_build-profile:
	cargo build --release --target wasm32-unknown-unknown


.PHONY: compress-wasm
compress-wasm:
	cp ./target/wasm32-unknown-unknown/release/*.wasm ./contract.wasm
	@## The following line is not necessary, may work only on linux (extra size optimization)
	@# wasm-opt -Os ./contract.wasm -o ./contract.wasm
	cat ./contract.wasm | gzip -9 > ./contract.wasm.gz

.PHONY: optimize-wasm
optimize-wasm:
	wasm-opt -Oz contract.wasm -o ./optimized.wasm
	cat ./optimized.wasm | gzip -9 > ./optimized.wasm.gz

.PHONY: clean
clean:
	cargo clean
	-rm -f ./contract.wasm ./contract.wasm.gz
	-rm -f ./optimized.wasm ./optimized.wasm.gz
