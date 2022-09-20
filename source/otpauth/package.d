module otpauth;

import std.digest.hmac;
import std.digest.sha;
import std.bitmanip : nativeToBigEndian, read, Endian;
import std.array : split;
import std.format : format;
import std.math.exponential : pow;
import std.regex : regex, replaceFirst;
import std.uni : toUpper;
import std.conv : to;
import base32;
import url;

V frontOrDefault(R, V)(R range, V defaultValue = V.init)
{
    if (range.empty)
    {
        return defaultValue;
    }
    return range.front;
}

class OTPAuth
{
    string account;
    string secret;
    string algorithm;
    int period;
    int digits;
    string issuer;

    this(URL url)
    {
        if (url.scheme != "otpauth")
        {
            throw new Exception("Cannot work with " ~ url.scheme);
        }

        if (url.host != "totp")
        {
            throw new Exception("Cannot work with " ~ url.host);
        }

        this.account = url.path.split(":")[$ - 1].replaceFirst(regex("^/"), "");
        this.secret = url.queryParams["secret"].front.toUpper;
        this.algorithm = url.queryParams["algorithm"].frontOrDefault("sha1").toUpper;
        this.period = url.queryParams["period"].frontOrDefault("30").to!int;
        this.digits = url.queryParams["digits"].frontOrDefault("6").to!int;
        this.issuer = url.queryParams["issuer"].front;
    }

    override string toString()
    {
        // dfmt off
        return "otpauth://totp/" ~ this.account
            ~ "?secret=" ~ this.secret
            ~ "&algorithm=" ~ algorithm
            ~ "&period=" ~ period.to!string
            ~ "&digits=" ~ digits.to!string
            ~ "&issuer=" ~ issuer;
        // dfmt on
    }

    string totp(Digest)(Digest digest, long time)
    {
        auto interval = time / period;
        digest.start;

        digest.put(interval.nativeToBigEndian);

        auto code = digest.finish;
        auto offset = code[$ - 1] & 0x0f;
        auto otpBytes = code[offset .. offset + 4];

        auto otp = read!(int, Endian.bigEndian)(otpBytes);
        otp = otp & 0x7FFFFFFF;
        otp = otp % (pow(10, digits));

        return format("%0" ~ digits.to!string ~ "d", otp);
    }

    string totp(long time)
    {
        auto s = Base32.decode(secret);
        switch (algorithm)
        {
        case "SHA1":
            return totp(hmac!SHA1(s), time);
        case "SHA256":
            return totp(hmac!SHA256(s), time);
        case "SHA512":
            return totp(hmac!SHA512(s), time);
        default:
            throw new Exception("Cannot handle digest '" ~ algorithm ~ "'");
        }
    }
}
