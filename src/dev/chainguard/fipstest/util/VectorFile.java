package dev.chainguard.fipstest.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser for the CAVP .rsp-style vector format used under vectors/:
 *
 *   # comment / provenance header
 *   [keySize = 256]          <- group parameter, applies until next header
 *   [tagSize = 128]
 *
 *   tcId = 47
 *   comment = Flipped bit 0 in tag
 *   result = invalid
 *   key = 0001...
 *   msg =
 *
 * Records are separated by blank lines. Group parameters are merged into
 * each record (record keys win). "result" is valid|invalid|acceptable and
 * drives the disposition of vector-driven cases.
 */
public final class VectorFile {

    public static final class Record {
        private final Map<String, String> values;
        private final int lineNumber;

        Record(Map<String, String> values, int lineNumber) {
            this.values = values;
            this.lineNumber = lineNumber;
        }

        public String id() {
            String tc = values.get("tcId");
            return tc != null ? "tc" + tc : "line" + lineNumber;
        }

        public boolean has(String key) {
            return values.containsKey(key);
        }

        public String get(String key) {
            String v = values.get(key);
            if (v == null) {
                throw new IllegalArgumentException("vector record " + id()
                        + " is missing key '" + key + "'");
            }
            return v;
        }

        public String getOrDefault(String key, String def) {
            return values.getOrDefault(key, def);
        }

        /** Hex-decoded value; an empty string decodes to an empty array. */
        public byte[] bytes(String key) {
            return Hex.decode(get(key));
        }

        public int intValue(String key) {
            return Integer.parseInt(get(key));
        }

        /** result field: "valid" and "acceptable" are truthy, "invalid" is not. */
        public boolean expectedValid() {
            return !"invalid".equals(getOrDefault("result", "valid"));
        }

        public String result() {
            return getOrDefault("result", "valid");
        }

        public String comment() {
            return getOrDefault("comment", "");
        }
    }

    private final List<Record> records;
    private final Path source;

    private VectorFile(Path source, List<Record> records) {
        this.source = source;
        this.records = records;
    }

    public List<Record> records() {
        return records;
    }

    public Path source() {
        return source;
    }

    public static VectorFile parse(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        List<Record> records = new ArrayList<>();
        Map<String, String> group = new LinkedHashMap<>();
        Map<String, String> current = null;
        int recordStartLine = 0;

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                if (current != null) {
                    records.add(new Record(current, recordStartLine));
                    current = null;
                }
                continue;
            }
            if (line.startsWith("#")) {
                continue;
            }
            if (line.startsWith("[") && line.endsWith("]")) {
                if (current != null) {
                    records.add(new Record(current, recordStartLine));
                    current = null;
                }
                String inner = line.substring(1, line.length() - 1);
                int eq = inner.indexOf('=');
                if (eq < 0) {
                    throw new IOException(path + ":" + (i + 1)
                            + ": malformed group header: " + line);
                }
                group.put(inner.substring(0, eq).trim(), inner.substring(eq + 1).trim());
                continue;
            }
            int eq = line.indexOf('=');
            if (eq < 0) {
                throw new IOException(path + ":" + (i + 1) + ": malformed line: " + line);
            }
            if (current == null) {
                current = new LinkedHashMap<>(group);
                recordStartLine = i + 1;
            }
            current.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
        }
        if (current != null) {
            records.add(new Record(current, recordStartLine));
        }
        if (records.isEmpty()) {
            throw new IOException(path + ": no vector records found");
        }
        return new VectorFile(path, records);
    }
}
