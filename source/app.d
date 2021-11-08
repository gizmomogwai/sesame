import otpauth;

import colored;
import dyaml;
import std;
import url;

auto executeCommand(string[] command, string errorMessage, Node settings)
{
    if (settings["verbose"].as!bool)
    {
        stderr.writeln("Running ", command);
    }
    auto result = command.execute;
    (result.status == 0).enforce(errorMessage);
    return result;
}

int editData(string home, EncryptDecrypt encdec, Node settings)
{
    import dyaml;

    auto editor = environment["EDITOR"];
    auto filename = "/tmp/sesame";

    auto accountsBase = home ~ "/.sesame-accounts.txt";

    encdec.decryptToFile(home, accountsBase, filename, settings);
    scope (exit)
    {
        filename.remove;
    }

    auto exitCode = [editor, filename].spawnProcess.wait;
    (exitCode == 0).enforce("Cannot spawn '%s'".format(editor));

    encdec.encrypt(home, filename, accountsBase, settings);

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

    abstract void decryptToFile(string home, string accountsBase, string outputFile, Node settings);
    abstract string decryptToString(string home, string accountsBase, Node settings);
    abstract void encrypt(string home, string input, string accountsBase, Node settings);
}

class GPGEncryptDecrypt : EncryptDecrypt
{
    this()
    {
        super("gpg");
    }

    override void decryptToFile(string home, string accountsBase, string outputFile, Node settings)
    {
        auto file = accountsFile(accountsBase);
        // dfmt off
        [
          "gpg",
          "--decrypt",
          "--quiet",
          "--output",
          outputFile,
          file,
        ].executeCommand("Cannot decrypt '%s'".format(file), settings);
        // dfmt on
    }

    override string decryptToString(string home, string accountsBase, Node settings)
    {
        auto file = accountsFile(accountsBase);
        // dfmt off
        return [
          "gpg",
          "--decrypt",
          "--quiet",
          file
        ].executeCommand("Cannot decrypt '%s'".format(file), settings).output;
        // dfmt on
    }

    override void encrypt(string home, string input, string accountsBase, Node settings)
    {
        auto file = accountsFile(accountsBase);
        // dfmt off
        [
            "gpg",
            "--encrypt",
            "--recipient", settings["gpg-account"].as!string,
            "--quiet",
            "--output", file,
            input
        ].executeCommand("Cannot encrypt '%s'".format(file), settings);
        // dfmt on
    }
}

class AgeEncryptDecrypt : EncryptDecrypt
{
    this()
    {
        super("age");
    }

    override void decryptToFile(string home, string accountsBase, string outputFile, Node settings)
    {
        auto file = accountsFile(accountsBase);
        // dfmt off
        [
          "age",
          "--decrypt",
          "--identity",  home ~ "/.age/" ~ settings["age-key"].as!string,
          "--output", outputFile,
          file
        ].executeCommand("Cannot decrypt '%s'".format(file), settings);
        // dfmt on
    }

    override string decryptToString(string home, string accountsBase, Node settings)
    {
        auto file = accountsFile(accountsBase);
        // dfmt off
        return [
            "age",
            "--decrypt",
            "--identity", home ~ "/.age/" ~ settings["age-key"].as!string,
            file,
        ].executeCommand("Cannot decrypt '%s'".format(file), settings).output;
        // dfmt on
    }

    override void encrypt(string home, string input, string accountsBase, Node settings)
    {
        auto file = accountsFile(accountsBase);
        // dfmt off
        [
            "age",
            "--encrypt",
            "--identity", home ~ "/.age/" ~ settings["age-key"].as!string,
            "--output", file,
            input,
        ].executeCommand("Cannot encrypt '%s'".format(file), settings);
        // dfmt on
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

auto getWithDefault(Node settings, string key, string defaultValue)
{
    if (settings.containsKey(key))
    {
        return settings[key].as!string;
    }
    else
    {
        return defaultValue;
    }
}

int main(string[] args)
{
    bool verbose = false;
    bool asciiTable = false;
    bool edit = false;
    auto home = environment["HOME"];
    auto settingsFile = home ~ "/.config/.sesame.yaml";
    auto settings = Loader.fromFile(settingsFile).load();
    Encryption encryption = settings.getWithDefault("encryption", "GPG").to!Encryption;

    // dfmt off
    auto result = getopt(args,
                         "verbose|v", "Verbose output", &verbose,
                         "encryption|c", "Encryption", &encryption,
                         "asciiTable|t", "Render as table", &asciiTable,
                         "edit|e", "Edit data", &edit);
    settings["verbose"] = verbose;

    // dfmt on
    if (result.helpWanted)
    {
        defaultGetoptPrinter("sesam", result.options);
        return 0;
    }

    auto encdec = encryption.toObject;

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
