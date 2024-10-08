# DLL Proxy Generator

Generate a proxy dll for arbitrary dll, while also loading a user-defined secondary dll.

## Usage

`dll-proxy-generator.exe [OPTIONS] --import-dll <IMPORT_DLL> --import <IMPORT> <DLL>`

### Arguments

`<DLL>  Path to dll to proxy`

### Options

```
-d, --import-dll <IMPORT_DLL>      Extra dll to import
-i, --import <IMPORT>              Import name or ordinal
-p, --proxy-target <PROXY_TARGET>  Target of proxy, defaults to path of same file in System32
-o, --output <OUTPUT>              Output file
-m, --machine <MACHINE>            COFF Machine magic. Defaults to x64's [default: 34404]
-h, --help                         Print help
-V, --version                      Print version
```

## Credits

Thanks to [@mrexodia](https://github.com/mrexodia) for the [target dll trick](https://github.com/mrexodia/perfect-dll-proxy/)
