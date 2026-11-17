"""Generate bounded cache observers outside the source tree; never edit vendor/."""
import argparse
import hashlib
import json
from pathlib import Path


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('instrumentation anchor is not unique: ' + old[:90])
    return text.replace(old, new, 1)


C_OBSERVER = r'''
/* Test-only, in-memory observations; all callers hold the existing store lock.
 * No clock, file output, random draw or protocol continuation is added here. */
struct cache_event {
    unsigned before, count, mask;
    int commit;
    char path[32];
};
static struct cache_event cache_events[128];
static unsigned cache_used, cache_overflow;

static void cache_observe_locked(int commit, const name_set *s,
                                 const char *path, size_t len, unsigned before)
{
    if (cache_used == 128u) {
        cache_overflow++;
        return;
    }
    struct cache_event *e = &cache_events[cache_used++];
    e->commit = commit;
    e->before = before;
    e->count = s->count;
    e->mask = find(s, (const uint8_t *)"/", 1u) >= 0 ? 1u : 0u;
    for (unsigned i = 0; i < 20u; i++) {
        char key[16];
        int n = snprintf(key, sizeof key, "/h%u", i);
        if (find(s, (const uint8_t *)key, (size_t)n) >= 0)
            e->mask |= 1u << (i + 1u);
    }
    if (path != NULL && len < sizeof e->path) {
        memcpy(e->path, path, len);
        e->path[len] = '\0';
    } else {
        memcpy(e->path, "-", 2u);
    }
}

void lc_cache_trace_dump(void)
{
    if (store_lock() != 0)
        return;
    fprintf(stderr, "CACHE_BEGIN %u %u\n", cache_used, cache_overflow);
    for (unsigned i = 0; i < cache_used; i++) {
        const struct cache_event *e = &cache_events[i];
        fprintf(stderr, "CACHE %u %s %u %u %u %s\n", i,
                e->commit ? "commit" : "draw", e->before, e->count, e->mask, e->path);
    }
    fprintf(stderr, "CACHE_END %u\n", cache_used);
    store_unlock();
}
'''


GO_OBSERVER = r'''package reality

// Test-only observers. The existing maps mutex serializes both observation and
// the eventual dump; nothing is written to a file while traffic is running.
import (
    "fmt"
    "os"
    "strconv"
)

type cacheTraceEvent struct {
    kind, path string
    before, count int
    mask uint32
}

var cacheTraceEvents [128]cacheTraceEvent
var cacheTraceUsed, cacheTraceOverflow int

func cacheObserveLocked(kind string, paths map[string]struct{}, path string, before int) {
    if cacheTraceUsed == len(cacheTraceEvents) {
        cacheTraceOverflow++
        return
    }
    e := &cacheTraceEvents[cacheTraceUsed]
    cacheTraceUsed++
    *e = cacheTraceEvent{kind: kind, path: path, before: before, count: len(paths)}
    if _, ok := paths["/"]; ok { e.mask = 1 }
    for i := 0; i < 20; i++ {
        if _, ok := paths["/h" + strconv.Itoa(i)]; ok { e.mask |= 1 << (i + 1) }
    }
}

func DumpCacheTrace() {
    maps.Lock()
    defer maps.Unlock()
    fmt.Fprintf(os.Stderr, "CACHE_BEGIN %d %d\n", cacheTraceUsed, cacheTraceOverflow)
    for i := 0; i < cacheTraceUsed; i++ {
        e := cacheTraceEvents[i]
        fmt.Fprintf(os.Stderr, "CACHE %d %s %d %d %d %s\n", i, e.kind, e.before, e.count, e.mask, e.path)
    }
    fmt.Fprintf(os.Stderr, "CACHE_END %d\n", cacheTraceUsed)
}
'''


def prepare(root, output, *, native_reference=False):
    root, output = root.resolve(), output.resolve()
    if output == root or root in output.parents:
        raise ValueError('observer output must be outside the source tree')
    entry = ('tools/vendorcap/nativeclient/runner/main.go' if native_reference
             else 'vendor/Xray-core/main/run.go')
    run_name = 'runner.trace.go' if native_reference else 'run.trace.go'
    files = ['src/reality/paths.c', 'src/cmd/lc-tunnel/main.c',
             'vendor/Xray-core/transport/internet/reality/reality.go',
             entry]
    originals = {name: (root / name).read_bytes() for name in files}
    source = {name: data.decode() for name, data in originals.items()}
    paths = source[files[0]]
    paths = replace_once(paths, 'int lc_spider_path(const char *host, char **out, size_t *len)',
                         C_OBSERVER + '\nint lc_spider_path(const char *host, char **out, size_t *len)')
    paths = replace_once(paths, 'int       rc = s != NULL ? draw(s, out, len) : -1;',
                         'int       rc = s != NULL ? draw(s, out, len) : -1;\n'
                         '    if (rc == 0) cache_observe_locked(0, s, *out, *len, 0u);')
    paths = replace_once(paths, '    for (size_t i = 0; s != NULL && i < sink->npending; i++)',
                         '    unsigned cache_before = s != NULL ? s->count : 0u;\n'
                         '    for (size_t i = 0; s != NULL && i < sink->npending; i++)')
    paths = replace_once(paths, '            break;\n    store_unlock();\n}',
                         '            break;\n'
                         '    if (s != NULL) cache_observe_locked(1, s, NULL, 0u, cache_before);\n'
                         '    store_unlock();\n}')
    main = replace_once(source[files[1]], 'int main(int argc, char **argv)',
                        'void lc_cache_trace_dump(void);\n\nint main(int argc, char **argv)')
    main = replace_once(main, '        if (want_stats) {\n            report_stats();',
                        '        if (want_stats) {\n            lc_cache_trace_dump();\n            report_stats();')
    reality = replace_once(source[files[2]], 'firstURL := string(prefix) + getPathLocked(paths)',
                           'firstPath := getPathLocked(paths)\n'
                           '\t\t\tcacheObserveLocked("draw", paths, firstPath, 0)\n'
                           '\t\t\tfirstURL := string(prefix) + firstPath')
    reality = replace_once(reality, '\t\t\t\t\tmaps.Lock()\n\t\t\t\t\tfor _, m := range href.FindAllSubmatch(body, -1) {',
                           '\t\t\t\t\tmaps.Lock()\n\t\t\t\t\tcacheBefore := len(paths)\n'
                           '\t\t\t\t\tfor _, m := range href.FindAllSubmatch(body, -1) {')
    reality = replace_once(reality, '\t\t\t\t\treq.URL.Path = getPathLocked(paths)',
                           '\t\t\t\t\tcacheObserveLocked("commit", paths, "-", cacheBefore)\n'
                           '\t\t\t\t\treq.URL.Path = getPathLocked(paths)')
    if native_reference:
        run = replace_once(source[files[3]],
                           '_ "github.com/xtls/xray-core/transport/internet/reality"',
                           'cachetrace "github.com/xtls/xray-core/transport/internet/reality"')
    else:
        run = replace_once(source[files[3]], 'import (',
                           'import (\n cachetrace "github.com/xtls/xray-core/transport/internet/reality"')
    run = replace_once(run, '\tdefer server.Close()',
                       '\tdefer cachetrace.DumpCacheTrace()\n\tdefer server.Close()')
    changed = {'paths.trace.c': paths, 'main.trace.c': main,
               'reality.trace.go': reality, run_name: run,
               'cache.trace.go': GO_OBSERVER}
    output.mkdir(parents=True, exist_ok=False)
    for name, text in changed.items():
        (output / name).write_text(text, encoding='utf-8', newline='\n')
    for name, data in originals.items():
        (output / (Path(name).name + '.original')).write_bytes(data)
    mapping = {str(root / files[2]): str(output / 'reality.trace.go'),
               str(root / files[3]): str(output / run_name),
               str(root / 'vendor/Xray-core/transport/internet/reality/cache_trace.go'):
               str(output / 'cache.trace.go')}
    (output / 'go-overlay.json').write_text(json.dumps({'Replace': mapping}, indent=2) + '\n')
    schema = 'spider-cache-observers-native-v1' if native_reference else 'spider-cache-observers-v1'
    receipt = {'schema': schema, 'originals':
               {name: hashlib.sha256(data).hexdigest() for name, data in originals.items()},
               'observers': {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                             for name in changed}}
    (output / 'observer-inputs.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--native-reference', action='store_true',
                        help='Observe the protobuf reference runner instead of full Xray main.')
    args = parser.parse_args()
    prepare(args.source, args.output, native_reference=args.native_reference)
