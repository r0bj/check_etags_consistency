# check_etags_consistency
HTTP ETag consistency check across web nodes cluster for nagios

```
usage: check_etags_consistency [<flags>] <servers>

Flags:
      --help            Show context-sensitive help (also try --help-long and --help-man).
  -c, --concurrent=100  max number of concurrent HTTP requests
  -t, --timeout=10      timeout for HTTP requests
  -u, --url="http://stalker.wikia.com/wiki/Main_Page"
                        URL

Args:
  <servers>  comma separated list of HTTP servers
```
