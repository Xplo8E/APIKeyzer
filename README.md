# APIKeyzer

[APIKeyzer](README.md) = [Apiguesser](https://github.com/daffainfo/apiguesser) + [Keyhacks](https://github.com/streaak/keyhacks)


```
  ___  ______ _____ _   __
 / _ \ | ___ \_   _| | / /
/ /_\ \| |_/ / | | | |/ /  ___ _   _ _______ _ __
|  _  ||  __/  | | |    \ / _ \ | | |_  / _ \ '__|
| | | || |    _| |_| |\  \  __/ |_| |/ /  __/ |
\_| |_/\_|    \___/\_| \_/\___|\__, /___\___|_|
                                __/ |
                               |___/  v1.0
                                      @Xplo8E
```

## Usage
```
Examples:
  apiKeyzer --key "YOUR-API-KEY"
  apiKeyzer --list keys.txt
  cat keys.txt | apiKeyzer
  apiKeyzer --key "YOUR-API-KEY" --config custom-patterns.json

Usage:
  apiKeyzer [flags]

Flags:
  -c, --config string   Path to patterns configuration file (default will be used if not provided)
  -h, --help            help for apiKeyzer
  -k, --key string      Single API key to validate
  -l, --list string     File containing API keys (one per line)
  -v, --verbose         Enable verbose output

```

## TODO

- Add Validators for other services [patterns.json](cmd/apiKeyzer/config/patterns.json)

## Credits

- https://github.com/daffainfo/apiguesser
- https://github.com/daffainfo/all-about-apikey
- https://github.com/streaak/keyhacks
- https://github.com/ozguralp/gmapsapiscanner