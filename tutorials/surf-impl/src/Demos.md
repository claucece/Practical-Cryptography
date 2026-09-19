## Browser demos

Two demos render a real web page fetched over SURF. They take opposite
approaches, and only one of them works in both SURF modes.

| | `SurfProxy` | `SurfDemo` |
|---|---|---|
| Architecture | localhost HTTP proxy, the browser drives | writes files to disk, the browser reads `file://` |
| Asset discovery | the browser's, over real HTTP | Gumbo, pre-parsing the HTML |
| Bytes delivered | the origin's, verbatim | rewritten to point at local copies |
| SURF mode | TRUE only | both |
| Rounds | one connection per browser request, in-process | one round per process, via a handoff directory |

### Before either

Build the circuits, as with any other SURF binary:

```shell
cd build
cmake ../ -DBENCHMARKING=ON
make
./DeriveCircuits
mv *.txt ../2pc/key-derivation/
```

`SurfDemo` additionally needs `libgumbo`, and its target must live inside the
`if(BENCHMARKING)` guard in `src/CMakeLists.txt`, since that is where gumbo is
located. `SurfProxy` needs neither and can be built unguarded.

### `SurfProxy` — browsing over SURF

A plain-HTTP listener on localhost. The browser talks to it in the clear: each
browser request is relayed over its own SURF/TLS connection to the origin, and
the response bytes are handed back unmodified.

```
browser --HTTP--> prover --SURF/TLS--> origin
                     |
                     +--MPC--> verifier
```

One request is one connection. That is forced by TRUE mode: nothing is readable
until `KEY_RELEASE`, which needs the record stream to be complete, so the
connection has to end before the prover can read what it fetched.

#### Running

```shell
cd build
../demo/run_proxy.sh --host cutler.pl --stage
```

That starts the verifier, waits for it to bind, starts the prover, and opens a
browser at `http://127.0.0.1:8080/`.

Script flags:

| Flag | Meaning |
|---|---|
| `--host` | Origin to fetch from. Required. |
| `--port` | Browser listener port (default `8080`). |
| `--verifier-port` | Verifier port (default `9500`). |
| `--stage` | Rewrite stylesheet links to be non-render-blocking. See below. |
| `--fetch-favicon` | Fetch `/favicon.ico` instead of 404ing it locally. |
| `--no-csp` | Do not inject a `Content-Security-Policy` header. |
| `--build-dir` | Where `SurfProxy` lives (default `$(pwd)`). |
| `--timeout` | Verifier idle timeout, seconds (default `600`). |

By hand, in two terminals:

```shell
# Terminal 1: the verifier. Stays up for the whole session.
SURF_TRUE=1 ./SurfProxy --is_verifier --ip 127.0.0.1 -v 9500

# Terminal 2: the prover and browser listener.
SURF_TRUE=1 ./SurfProxy --host cutler.pl -v 9500 -b 8080 --open
```

#### Endpoints

| Path | |
|---|---|
| anything else | Relayed to the origin over SURF. |
| `/__surf` | Provenance: per-resource bytes, records, 2PC blocks, timings. Served locally, costs no round. |
| `/__done` | Stops the proxy. |

#### Ordering and `--stage`

Browsers dispatch a page's subresources near-simultaneously across parallel
connections, so left alone the serve order is whichever TCP connect landed
first. The accept loop instead drains everything pending and sorts by
`Sec-Fetch-Dest` — document, then style, script, font, image — so the page
fills in the order a browser would have wanted.

### `SurfDemo` — a page assembled on disk

No server and no JavaScript. The prover fetches `/`, parses it with Gumbo,
fetches each discovered same-origin asset over a resumed round, writes
everything under `--outdir`, and rewrites the HTML to reference the local
copies. A provenance banner is injected into the page itself. While the fetch
is incomplete the page carries a meta-refresh so an already-open browser picks
up each rewrite.

```
<outdir>/raw/page.html    the origin's bytes, untouched
<outdir>/raw/<file>       each asset, untouched
<outdir>/manifest.tsv     one row per fetched resource
<outdir>/index.html       rewritten page + banner; the file to open
```

Like `E2EBench` and the `MultiGet` benches, this runs **one round per
process**, with a handoff directory carrying the ticket and PSK shares.

#### Running

```shell
cd build
../demo/run.sh --host cutler.pl --assets 2
```

| Flag | Meaning |
|---|---|
| `--host` | Origin. Required. |
| `--path` | Initial path (default `/`). |
| `--assets` | Cap on assets fetched (default 4). |
| `--mode` | `true` or `masked`. |
| `--outdir` | Output directory (default `/tmp/surf_demo`). |
| `--build-dir` | Where `SurfDemo` lives. |
| `--allow-unclean-close` | Accept a response without `close_notify`. |

To iterate on the rendering without re-fetching:

```shell
./SurfDemo --build_only --outdir /tmp/surf_demo --host cutler.pl --open
```
