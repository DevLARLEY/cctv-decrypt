# CCTV.com Decrypter

`tea_decrypt` (`func57` in WASM) uses the Tiny Encryption Algorithm (TEA) with 16 cycles and precomputed sums to encrypt a 64-bit block every 80 bytes of a NAL unit (type 1, 5 or 25).
The 128 bt key for each NAL unit starts at [index 16](decrypt.dcmp#L23075) and the encrypted data at [index 32](decrypt.dcmp#L23077).

`cctv.py` decrypts a single ts segment.

## Usage
```shell
python cctv.py [infile] [outfile]
```

## Credits
+ [ts_decrypt.js](https://github.com/letr007/CCTVVideoDownloader/blob/main/src/decrypt/ts_decrypt.js) (TS parser implementation and reference decrypter)
