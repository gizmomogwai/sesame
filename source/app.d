import otpauth;

import colored;
import dyaml;
import std;
import url;

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

    auto inputFile = environment["HOME"] ~ "/.sesame-accounts.txt.gpg";
    auto decodeResult = ["gpg", "--decrypt", "--quiet", inputFile].execute;
    enforce(decodeResult.status == 0);

    auto now = Clock.currTime().toUnixTime;

    auto otps = decodeResult.output.split.filter!(not!(line => line.startsWith("#")))
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
