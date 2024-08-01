# Config file

Trivy can be customized by tweaking a `trivy.yaml` file.
The config path can be overridden by the `--config` flag.

An example is [here][example].

## Global Options

```yaml
cache: 
  # Same as '--cache-dir'
  # Default is /path/to/cache
  dir: /path/to/cache

# Same as '--debug'
# Default is false
debug: false

# Same as '--insecure'
# Default is false
insecure: false

# Same as '--quiet'
# Default is false
quiet: false

# Same as '--timeout'
# Default is 5m0s
timeout: 5m0s

```
## Cache Options

```yaml
cache: 
  # Same as '--cache-backend'
  # Default is fs
  backend: fs

  # Same as '--clear-cache'
  # Default is false
  clear: false

  redis: 
    # Same as '--redis-ca'
    # Default is empty
    ca: 

    # Same as '--redis-cert'
    # Default is empty
    cert: 

    # Same as '--redis-key'
    # Default is empty
    key: 

    # Same as '--redis-tls'
    # Default is false
    tls: false

  # Same as '--cache-ttl'
  # Default is 0s
  ttl: 0s

```
## Client/Server Options

```yaml
server: 
  # Same as '--server'
  # Default is empty
  addr: 

  # Same as '--custom-headers'
  # Default is []
  custom-headers: []

  # Same as '--listen'
  # Default is localhost:4954
  listen: localhost:4954

  # Same as '--token'
  # Default is empty
  token: 

  # Same as '--token-header'
  # Default is Trivy-Token
  token-header: Trivy-Token

```
## License Options

```yaml
license: 
  # Same as '--license-confidence-level'
  # Default is 0.9
  confidenceLevel: 0.9

  # Default is [AGPL-1.0 AGPL-3.0 CC-BY-NC-1.0 CC-BY-NC-2.0 CC-BY-NC-2.5 CC-BY-NC-3.0 CC-BY-NC-4.0 CC-BY-NC-ND-1.0 CC-BY-NC-ND-2.0 CC-BY-NC-ND-2.5 CC-BY-NC-ND-3.0 CC-BY-NC-ND-4.0 CC-BY-NC-SA-1.0 CC-BY-NC-SA-2.0 CC-BY-NC-SA-2.5 CC-BY-NC-SA-3.0 CC-BY-NC-SA-4.0 Commons-Clause Facebook-2-Clause Facebook-3-Clause Facebook-Examples WTFPL]
  forbidden: 
  - AGPL-1.0
  - AGPL-3.0
  - CC-BY-NC-1.0
  - CC-BY-NC-2.0
  - CC-BY-NC-2.5
  - CC-BY-NC-3.0
  - CC-BY-NC-4.0
  - CC-BY-NC-ND-1.0
  - CC-BY-NC-ND-2.0
  - CC-BY-NC-ND-2.5
  - CC-BY-NC-ND-3.0
  - CC-BY-NC-ND-4.0
  - CC-BY-NC-SA-1.0
  - CC-BY-NC-SA-2.0
  - CC-BY-NC-SA-2.5
  - CC-BY-NC-SA-3.0
  - CC-BY-NC-SA-4.0
  - Commons-Clause
  - Facebook-2-Clause
  - Facebook-3-Clause
  - Facebook-Examples
  - WTFPL

  # Same as '--license-full'
  # Default is false
  full: false

  # Same as '--ignored-licenses'
  # Default is []
  ignored: []

  # Default is [AFL-1.1 AFL-1.2 AFL-2.0 AFL-2.1 AFL-3.0 Apache-1.0 Apache-1.1 Apache-2.0 Artistic-1.0-cl8 Artistic-1.0-Perl Artistic-1.0 Artistic-2.0 BSL-1.0 BSD-2-Clause-FreeBSD BSD-2-Clause-NetBSD BSD-2-Clause BSD-3-Clause-Attribution BSD-3-Clause-Clear BSD-3-Clause-LBNL BSD-3-Clause BSD-4-Clause BSD-4-Clause-UC BSD-Protection CC-BY-1.0 CC-BY-2.0 CC-BY-2.5 CC-BY-3.0 CC-BY-4.0 FTL ISC ImageMagick Libpng Lil-1.0 Linux-OpenIB LPL-1.02 LPL-1.0 MS-PL MIT NCSA OpenSSL PHP-3.01 PHP-3.0 PIL Python-2.0 Python-2.0-complete PostgreSQL SGI-B-1.0 SGI-B-1.1 SGI-B-2.0 Unicode-DFS-2015 Unicode-DFS-2016 Unicode-TOU UPL-1.0 W3C-19980720 W3C-20150513 W3C X11 Xnet Zend-2.0 zlib-acknowledgement Zlib ZPL-1.1 ZPL-2.0 ZPL-2.1]
  notice: 
  - AFL-1.1
  - AFL-1.2
  - AFL-2.0
  - AFL-2.1
  - AFL-3.0
  - Apache-1.0
  - Apache-1.1
  - Apache-2.0
  - Artistic-1.0-cl8
  - Artistic-1.0-Perl
  - Artistic-1.0
  - Artistic-2.0
  - BSL-1.0
  - BSD-2-Clause-FreeBSD
  - BSD-2-Clause-NetBSD
  - BSD-2-Clause
  - BSD-3-Clause-Attribution
  - BSD-3-Clause-Clear
  - BSD-3-Clause-LBNL
  - BSD-3-Clause
  - BSD-4-Clause
  - BSD-4-Clause-UC
  - BSD-Protection
  - CC-BY-1.0
  - CC-BY-2.0
  - CC-BY-2.5
  - CC-BY-3.0
  - CC-BY-4.0
  - FTL
  - ISC
  - ImageMagick
  - Libpng
  - Lil-1.0
  - Linux-OpenIB
  - LPL-1.02
  - LPL-1.0
  - MS-PL
  - MIT
  - NCSA
  - OpenSSL
  - PHP-3.01
  - PHP-3.0
  - PIL
  - Python-2.0
  - Python-2.0-complete
  - PostgreSQL
  - SGI-B-1.0
  - SGI-B-1.1
  - SGI-B-2.0
  - Unicode-DFS-2015
  - Unicode-DFS-2016
  - Unicode-TOU
  - UPL-1.0
  - W3C-19980720
  - W3C-20150513
  - W3C
  - X11
  - Xnet
  - Zend-2.0
  - zlib-acknowledgement
  - Zlib
  - ZPL-1.1
  - ZPL-2.0
  - ZPL-2.1

  # Default is []
  permissive: []

  # Default is [APSL-1.0 APSL-1.1 APSL-1.2 APSL-2.0 CDDL-1.0 CDDL-1.1 CPL-1.0 EPL-1.0 EPL-2.0 FreeImage IPL-1.0 MPL-1.0 MPL-1.1 MPL-2.0 Ruby]
  reciprocal: 
  - APSL-1.0
  - APSL-1.1
  - APSL-1.2
  - APSL-2.0
  - CDDL-1.0
  - CDDL-1.1
  - CPL-1.0
  - EPL-1.0
  - EPL-2.0
  - FreeImage
  - IPL-1.0
  - MPL-1.0
  - MPL-1.1
  - MPL-2.0
  - Ruby

  # Default is [BCL CC-BY-ND-1.0 CC-BY-ND-2.0 CC-BY-ND-2.5 CC-BY-ND-3.0 CC-BY-ND-4.0 CC-BY-SA-1.0 CC-BY-SA-2.0 CC-BY-SA-2.5 CC-BY-SA-3.0 CC-BY-SA-4.0 GPL-1.0 GPL-2.0 GPL-2.0-with-autoconf-exception GPL-2.0-with-bison-exception GPL-2.0-with-classpath-exception GPL-2.0-with-font-exception GPL-2.0-with-GCC-exception GPL-3.0 GPL-3.0-with-autoconf-exception GPL-3.0-with-GCC-exception LGPL-2.0 LGPL-2.1 LGPL-3.0 NPL-1.0 NPL-1.1 OSL-1.0 OSL-1.1 OSL-2.0 OSL-2.1 OSL-3.0 QPL-1.0 Sleepycat]
  restricted: 
  - BCL
  - CC-BY-ND-1.0
  - CC-BY-ND-2.0
  - CC-BY-ND-2.5
  - CC-BY-ND-3.0
  - CC-BY-ND-4.0
  - CC-BY-SA-1.0
  - CC-BY-SA-2.0
  - CC-BY-SA-2.5
  - CC-BY-SA-3.0
  - CC-BY-SA-4.0
  - GPL-1.0
  - GPL-2.0
  - GPL-2.0-with-autoconf-exception
  - GPL-2.0-with-bison-exception
  - GPL-2.0-with-classpath-exception
  - GPL-2.0-with-font-exception
  - GPL-2.0-with-GCC-exception
  - GPL-3.0
  - GPL-3.0-with-autoconf-exception
  - GPL-3.0-with-GCC-exception
  - LGPL-2.0
  - LGPL-2.1
  - LGPL-3.0
  - NPL-1.0
  - NPL-1.1
  - OSL-1.0
  - OSL-1.1
  - OSL-2.0
  - OSL-2.1
  - OSL-3.0
  - QPL-1.0
  - Sleepycat

  # Default is [CC0-1.0 Unlicense 0BSD]
  unencumbered: 
  - CC0-1.0
  - Unlicense
  - 0BSD

```
## Kubernetes Options

```yaml
kubernetes: 
  # Same as '--burst'
  # Default is 10
  burst: 10

  # Same as '--disable-node-collector'
  # Default is false
  disableNodeCollector: false

  exclude: 
    # Same as '--exclude-nodes'
    # Default is []
    nodes: []

    # Same as '--exclude-owned'
    # Default is false
    owned: false

  # Same as '--exclude-kinds'
  # Default is []
  excludeKinds: []

  # Same as '--exclude-namespaces'
  # Default is []
  excludeNamespaces: []

  # Same as '--include-kinds'
  # Default is []
  includeKinds: []

  # Same as '--include-namespaces'
  # Default is []
  includeNamespaces: []

  # Same as '--k8s-version'
  # Default is empty
  k8s-version: 

  # Same as '--kubeconfig'
  # Default is empty
  kubeconfig: 

  node-collector: 
    # Same as '--node-collector-imageref'
    # Default is ghcr.io/aquasecurity/node-collector:0.3.1
    imageref: ghcr.io/aquasecurity/node-collector:0.3.1

    # Same as '--node-collector-namespace'
    # Default is trivy-temp
    namespace: trivy-temp

  # Same as '--qps'
  # Default is 5
  qps: 5

  # Same as '--skip-images'
  # Default is false
  skipImages: false

  # Same as '--tolerations'
  # Default is []
  tolerations: []

```
[example]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/examples/trivy-conf/trivy.yaml