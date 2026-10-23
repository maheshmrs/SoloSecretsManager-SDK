package com.aidigiapps.solosecretsmanager.sdk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON reader and string quoting: objects become Map, arrays List, numbers Double or Long.
 * ponytail: just enough for the server's responses and the contract file, so the SDK has no dependencies.
 */
final class Json {
    private final String s;
    private int i;

    private Json(String s) { this.s = s; }

    static Object parse(String s) {
        Json j = new Json(s);
        Object v = j.value();
        j.ws();
        if (j.i != s.length()) throw new IllegalArgumentException("trailing data in JSON");
        return v;
    }

    static String quote(String v) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : v.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }

    private char peek() {
        ws();
        if (i >= s.length()) throw new IllegalArgumentException("unexpected end of JSON");
        return s.charAt(i);
    }

    private void expect(char c) { if (peek() != c) throw new IllegalArgumentException("expected " + c); i++; }

    private Object value() {
        char c = peek();
        if (c == '{') {
            i++;
            Map<String, Object> m = new LinkedHashMap<>();
            if (peek() == '}') { i++; return m; }
            do { String k = string(); expect(':'); m.put(k, value()); } while (comma());
            expect('}');
            return m;
        }
        if (c == '[') {
            i++;
            List<Object> l = new ArrayList<>();
            if (peek() == ']') { i++; return l; }
            do { l.add(value()); } while (comma());
            expect(']');
            return l;
        }
        if (c == '"') return string();
        for (String lit : new String[] {"true", "false", "null"}) {
            if (s.startsWith(lit, i)) { i += lit.length(); return lit.equals("null") ? null : Boolean.valueOf(lit); }
        }
        int start = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
        String n = s.substring(start, i);
        if (n.isEmpty()) throw new IllegalArgumentException("bad JSON value");
        return n.matches("-?\\d+") ? (Object) Long.valueOf(n) : Double.valueOf(n);
    }

    private boolean comma() { if (peek() == ',') { i++; return true; } return false; }

    private String string() {
        expect('"');
        StringBuilder b = new StringBuilder();
        while (true) {
            if (i >= s.length()) throw new IllegalArgumentException("unterminated string");
            char c = s.charAt(i++);
            if (c == '"') return b.toString();
            if (c != '\\') { b.append(c); continue; }
            char e = s.charAt(i++);
            switch (e) {
                case 'n' -> b.append('\n');
                case 't' -> b.append('\t');
                case 'r' -> b.append('\r');
                case 'b' -> b.append('\b');
                case 'f' -> b.append('\f');
                case 'u' -> { b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
                default -> b.append(e);
            }
        }
    }
}
