import otpauth;

import colored;
import dyaml;
import std;
import url;

int editData(string home, EncryptDecrypt encdec, Node settings)
{
    import dyaml;

    auto editor = environment["EDITOR"];
    auto filename = "/tmp/sesame";

    auto accountsBase = home ~ "/.sesame-accounts.txt";

    encdec.decryptToFile(home, settings, accountsBase, filename);
    scope (exit)
    {
        filename.remove;
    }

    auto exitCode = [editor, filename].spawnProcess.wait;
    (exitCode == 0).enforce("Cannot spawn '%s'".format(editor));

    encdec.encrypt(home, settings, filename, accountsBase);

    return 0;
}

class EncryptDecrypt
{
    string extension;
    protected string accountsFile(string accountsBase)
    {
        return accountsBase ~ "." ~ extension;
    }

    protected this(string extension)
    {
        this.extension = extension;
    }

    abstract void decryptToFile(string home, Node settings, string accountsBase, string outputFile);
    abstract string decryptToString(string home, string accountsBase, Node settings);
    abstract void encrypt(string home, Node settings, string input, string accountsBase);
}

class GPGEncryptDecrypt : EncryptDecrypt
{
    this()
    {
        super("gpg");
    }

    override void decryptToFile(string home, Node settings, string accountsBase, string outputFile)
    {
        auto file = accountsFile(accountsBase);
        //dfmt off
        auto result = [
            "gpg",
            "--decrypt",
            "--quiet",
            "--output", outputFile,
            file,
        ].execute;
        // dfmt on
        (result.status == 0).enforce("Cannot decrypt '%s'".format(file));
    }

    override string decryptToString(string home, string accountsBase, Node settings)
    {
        auto file = accountsFile(accountsBase);
        // dfmt off
        auto result = [
          "gpg",
          "--decrypt",
          "--quiet",
          file
        ].execute;
        // dfmt on
        (result.status == 0).enforce("Cannot decrypt '%s'".format(file));
        return result.output;
    }

    override void encrypt(string home, Node settings, string input, string accountsBase)
    {
        auto file = accountsFile(accountsBase);
        // dfmt off
        auto result = [
            "gpg",
            "--encrypt",
            "--recipient", settings["gpg-account"].as!string,
            "--quiet",
            "--output", file,
            input
        ].execute;
        // dfmt on
        (result.status == 0).enforce("Cannot encrypt '%s'".format(file));
    }
}

class AgeEncryptDecrypt : EncryptDecrypt
{
    this()
    {
        super("age");
    }

    override void decryptToFile(string home, Node settings, string accountsBase, string outputFile)
    {
        auto file = accountsFile(accountsBase);
        // dfmt off
        auto result = [
            "age",
            "--decrypt",
            "--identity",  home ~ "/.age/" ~ settings["age-key"].as!string,
            "--output", outputFile,
            file
        ].execute;
        // dfmt on
        (result.status == 0).enforce("Cannot decrypt '%s'".format(file));
    }

    override string decryptToString(string home, string accountsBase, Node settings)
    {
        auto file = accountsFile(accountsBase);
        // dfmt off
        auto result = [
            "age",
            "--decrypt",
            "--identity", home ~ "/.age/" ~ settings["age-key"].as!string,
            file,
        ].execute;
        // dfmt on
        (result.status == 0).enforce("Cannot decrypt '%s'".format(file));
        return result.output;
    }

    override void encrypt(string home, Node settings, string input, string accountsBase)
    {
        auto file = accountsFile(accountsBase);
        // dfmt off
        auto result = [
            "age",
            "--encrypt",
            "--identity", home ~ "/.age/" ~ settings["age-key"].as!string,
            "--output", file,
            input,
        ].execute;
        // dfmt on
        (result.status == 0).enforce("Cannot encrypt '%s'".format(file));
    }
}

enum Encryption
{
    GPG,
    AGE,
}

EncryptDecrypt toObject(Encryption e)
{
    switch (e) with (Encryption)
    {
    case GPG:
        return new GPGEncryptDecrypt();
    case AGE:
        return new AgeEncryptDecrypt();
    default:
        false.enforce("Unknown Encryption '%s'".format(e));
    }
    assert(false);
}

int main(string[] args)
{
    bool asciiTable = false;
    bool edit = false;
    Encryption encryption = Encryption.GPG;
    // dfmt off
    auto result = getopt(args,
                         "encryption|c", "Encryption", &encryption,
                         "asciiTable|t", "Render as table", &asciiTable,
                         "edit|e", "Edit data", &edit);
    // dfmt on
    if (result.helpWanted)
    {
        defaultGetoptPrinter("sesam", result.options);
        return 0;
    }

    auto encdec = encryption.toObject;

    auto home = environment["HOME"];
    auto settings = Loader.fromFile(home ~ "/.sesame.yaml").load();
    if (edit)
    {
        return editData(home, encdec, settings);
    }
    auto accountsBase = home ~ "/.sesame-accounts.txt";
    auto lines = encdec.decryptToString(home, accountsBase, settings);

    auto now = Clock.currTime().toUnixTime;

    auto otps = lines.split
        .filter!(not!(line => line.startsWith("#")))
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
