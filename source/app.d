import base32;
import colored;
import dyaml;
import std.digest.hmac;
import std.digest.sha;
import std;
import std;
import url;

string totp(Digest)(Digest digest, long interval, int digits)
{
    digest.start;

    auto intervalBytes = nativeToBigEndian(interval);
    digest.put(intervalBytes);

    auto code = digest.finish;
    auto offset = code[$ - 1] & 0x0f;
    auto otpBytes = code[offset .. offset + 4];

    auto otp = read!(int, std.system.Endian.bigEndian)(otpBytes);
    otp = otp & 0x7FFFFFFF;
    otp = otp % (pow(10, digits));

    return format("%0" ~ digits.to!string ~ "d", otp);
}

auto totp(string digest, ubyte[] secret, long interval, int digits)
{
    switch (digest)
    {
    case "SHA1":
        return hmac!SHA1(secret).totp(interval, digits);
    case "SHA256":
        return hmac!SHA256(secret).totp(interval, digits);
    case "SHA512":
        return hmac!SHA512(secret).totp(interval, digits);
    default:
        throw new Exception("Cannot handle digest '" ~ digest ~ "'");
    }
}

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
        return "otpauth://totp/" ~ this.account ~ "?secret=" ~ this.secret ~ "&algorithm=" ~ algorithm
            ~ "&period=" ~ period.to!string ~ "&digits=" ~ digits.to!string ~ "&issuer=" ~ issuer;
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
        filename.remove;

    result = (editor ~ " " ~ filename).executeShell;
    enforce(result.status == 0);

    result = ["gpg", "--encrypt", "--recipient", gpgAccount, "--quiet",
        "--output", sesameAccounts, filename].execute;
    enforce(result.status == 0);
    return 0;
}

int main(string[] args)
{
    bool asciiTable = false;
    bool edit = false;
    auto result = getopt(args, "asciiTable|t", "Render as table", &asciiTable,
            "edit|e", "Edit data", &edit);

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
    import asciitable;

    auto table = new AsciiTable(5);
    // dfmt off
    if (asciiTable)
    {
        table.header
            .add("Issuer").add("Account").add("Last").add("Current").add("Next");
    }
    foreach (otpauth;
             input
                 .byLineCopy
                 .filter!(line => !line.startsWith("#"))
                 .map!(line => new OTPAuth(line.parseURL)))
    {
        auto interval = now / otpauth.period;
        if (asciiTable)
        {
            table.row()
                .add(otpauth.issuer.green)
                .add(otpauth.account)
                .add(totp(otpauth.algorithm, Base32.decode(otpauth.secret), interval - 1, otpauth.digits))
                .add(totp(otpauth.algorithm, Base32.decode(otpauth.secret), interval + 0, otpauth.digits).green)
                .add(totp(otpauth.algorithm, Base32.decode(otpauth.secret), interval + 1, otpauth.digits));
        }
        else
        {
            writeln(otpauth.issuer.green, "/", otpauth.account, ": ",
                    totp(otpauth.algorithm, Base32.decode(otpauth.secret), interval - 1, otpauth.digits),
                    " ",
                    totp(otpauth.algorithm, Base32.decode(otpauth.secret), interval, otpauth.digits).green,
                    " ",
                    totp(otpauth.algorithm, Base32.decode(otpauth.secret), interval + 1, otpauth.digits)
            );
        }
    }
    if (asciiTable)
    {
        table
            .format
            .parts(new UnicodeParts)
            .rowSeparator(true)
            .columnSeparator(true)
            .borders(true)
            .writeln;
    }
    // dfmt on
    return 0;
}
