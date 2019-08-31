import base32;
import colored;
import dyaml;
import std.digest.hmac;
import std.digest.sha;
import std;
import std;
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

int editData()
{
    import dyaml;

    auto home = environment["HOME"];
    auto editor = environment["EDITOR"];
    auto filename = "/tmp/sesame";

    auto gpgAccount = Loader.fromFile(home ~ "/.sesame.yaml").load()["gpg-account"].as!string;

    auto sesameAccounts = home ~ "/.sesame-accounts.txt.gpg";

    auto result = ["gpg", "--decrypt", "--quiet", "--output", filename, sesameAccounts].execute;
    enforce(result.status == 0);
    scope (exit)
    {
        filename.remove;
    }

    result = (editor ~ " " ~ filename).executeShell;
    enforce(result.status == 0);

    // dfmt off
    result = ["gpg", "--encrypt", "--recipient", gpgAccount, "--quiet", "--output", sesameAccounts, filename].execute;
    // dfmt on
    enforce(result.status == 0);

    return 0;
}

int main(string[] args)
{
    bool asciiTable = false;
    bool edit = false;
    // dfmt off
    auto result = getopt(args,
                         "asciiTable|t", "Render as table", &asciiTable,
                         "edit|e", "Edit data", &edit);
    // dfmt on
    if (result.helpWanted)
    {
        defaultGetoptPrinter("sesam", result.options);
        return 0;
    }

    if (edit)
    {
        return editData;
    }

    auto input = File(environment["HOME"] ~ "/.sesame-accounts.txt");
    auto now = Clock.currTime().toUnixTime;

    auto otps = input.byLineCopy.filter!(not!(line => line.startsWith("#")))
        .map!(line => new OTPAuth(line.parseURL));
    if (asciiTable)
    {
        import asciitable;

        //dfmt off
        auto table = new AsciiTable(5);
        table.header
            .add("Issuer").add("Account").add("Last").add("Current").add("Next");
        foreach (otpauth; otps)
        {
            table.row()
                .add(otpauth.issuer.green)
                .add(otpauth.account)
                .add(otpauth.totp(now - otpauth.period))
                .add(otpauth.totp(now).green)
                .add(otpauth.totp(now + otpauth.period));
        }
        table
            .format
            .parts(new UnicodeParts)
            .rowSeparator(true)
            .columnSeparator(true)
            .borders(true)
            .writeln;
        // dfmt on
    }
    else
    {
        foreach (otpauth; otps)
        {
            // dfmt off
            writeln(otpauth.issuer.green, "/",
                    otpauth.account, ": ",
                    otpauth.totp(now - otpauth.period), " ",
                    otpauth.totp(now).green, " ",
                    otpauth.totp(now + otpauth.period)
            );
            // dfmt on
        }
    }

    return 0;
}
