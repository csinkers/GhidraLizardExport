package lizardexport;

import java.util.ArrayList;
import java.util.List;

/*
 * Used to convert an array of ints into a compact base64 representation and back again.
 * It is assumed that each int will typically be a little bit higher than the previous one.
 */
public class PackedBase64Offsets {

    public static int[] ConvertToOffsets(int baseAddress, int[] values) {
        int[] results = new int[values.length];
        int last = baseAddress;
        for (int i = 0; i < values.length; i++) {
            results[i] = values[i] - last;
            last = values[i];
        }
        return results;
    }

    public static int[] ConvertToAbsolute(int baseAddress, int[] offsets) {
        if (offsets.length == 0)
            return new int[0];

        int[] results = new int[offsets.length];
        results[0] = offsets[0] + baseAddress;
        for (int i = 1; i < offsets.length; i++)
            results[i] = results[i - 1] + offsets[i];

        return results;
    }

    public static String Encode(int[] offsets) {
        String base64Digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        StringBuilder sb = new StringBuilder();
        int[] digits = new int[6];

        for (int offset : offsets) {
            int n = offset < 0 ? -offset : offset;

            if (n < 63) {
                sb.append(base64Digits.charAt(n));
            } else {
                sb.append('[');
                boolean writing = false;
                for (int i = 0; i < 6; i++) {
                    digits[i] = GetDigit(n, 5 - i);
                    if (digits[i] != 0 || writing) {
                        writing = true;
                        sb.append(base64Digits.charAt(digits[i]));
                    }
                }
                sb.append(']');
            }

            if (offset < 0)
                sb.append('-');
        }
        return sb.toString();
    }

    public static int[] Decode(String s) {

        List<Integer> results = new ArrayList<>();
        int cur = 0;
        boolean multichar = false;

        for (char c : s.toCharArray()) {
            if (c == '-') {
                if (!results.isEmpty())
                    results.set(results.size() - 1, -results.get(results.size() - 1));
                continue;
            }

            if (c == '[') {
                multichar = true;
                cur = 0;
                continue;
            }

            if (multichar) {
                if (c == ']') {
                    results.add(cur);
                    multichar = false;
                    continue;
                }

                int d = TryGetDigit(c);
                if (d == -1)
                    continue;

                cur *= 64;
                cur += d;
            } else {
                int d = TryGetDigit(c);
                if (d == -1)
                    continue;
                results.add(d);
            }
        }

        int[] output = new int[results.size()];
        for (int i = 0; i < output.length; i++)
            output[i] = results.get(i);

        return output;
    }

    private static int GetDigit(int n, int d) {
        // 6 bits per digit, 32-bit number = ceil(32/6) = 6 digits
        int shiftBy = d * 6;
        int mask = 0x3f << shiftBy;
        int bits = n & mask;
        return bits >> shiftBy;
    }

    private static int TryGetDigit(char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    }
}
