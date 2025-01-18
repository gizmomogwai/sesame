module otpauth;

import std.array : split;
import std.bitmanip : Endian, nativeToBigEndian, read;
import std.conv : to;
import std.digest.hmac;
import std.digest.sha;
import std.format : format;
import std.math.exponential : pow;
import std.regex : regex, replaceFirst;
import std.uni : toUpper;
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
    string staticPrefix;

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
        this.staticPrefix = url.queryParams["staticPrefix"].frontOrDefault("");
    }

    void toString(Sink, Format)(Sink sink, Format format) const
    {
        // dfmt off
        sink("otpauth://totp/");
        sink(this.account);
        sink("?secret=");
        sink(this.secret);
        sink("&algorithm=");
        sink(algorithm);
        sink("&period=");
        sink(period.to!string);
        sink("&digits=");
        sink(digits.to!string);
        sink("&issuer=");
        sink(issuer);
        sink("&staticPrefix=");
        sink(staticPrefix);
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

        return format("%s%0" ~ digits.to!string ~ "d",staticPrefix, otp);
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
