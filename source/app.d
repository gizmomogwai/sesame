import otpauth;
import argparse : CLI, Command, NamedArgument, ArgumentGroup, ansiStylingArgument, SubCommands, Default, Config;
import colored;
import dyaml;
import url;
import packageinfo;
import asciitable : AsciiTable;
import std.algorithm : sort, fold, filter, startsWith, map;
import std.sumtype : SumType, match;
import std.conv : to;
import std.stdio : stderr, writeln;
import std.process : execute, environment, spawnProcess, wait;
import std.exception : enforce;
import std.file : remove;
import std.format : format;
import std.string : split, replace;
import std.functional : not;
import std.datetime : Clock;

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

int editData(string accountsBase, EncryptDecrypt encdec, Node settings)
{
    const editor = environment["EDITOR"];
    const home = environment["HOME"];
    const filename = "/tmp/sesame";

    encdec.decryptToFile(accountsBase, filename, settings);
    scope (exit)
    {
        filename.remove;
    }

    auto exitCode = [editor, filename].spawnProcess.wait;
    (exitCode == 0).enforce("Cannot spawn '%s'".format(editor));

    encdec.encrypt(filename, accountsBase, settings);

    return 0;
}

string accountsFile(string accountsBase, string extension)
{
    return accountsBase ~ "." ~ extension;
}

class EncryptDecrypt
{
    protected string extension;
    protected this(string extension)
    {
        this.extension = extension;
    }

    abstract void decryptToFile(string accountsBase, string outputFile, Node settings);
    abstract string decryptToString(string accountsBase, Node settings);
    abstract void encrypt(string input, string accountsBase, Node settings);
}

class GPGEncryptDecrypt : EncryptDecrypt
{
    this()
    {
        super("gpg");
    }

    override void decryptToFile(string accountsBase, string outputFile, Node settings)
    {
        auto file = accountsBase.accountsFile(extension);
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

    override string decryptToString(string accountsBase, Node settings)
    {
        auto file = accountsBase.accountsFile(extension);
        // dfmt off
        return [
          "gpg",
          "--decrypt",
          "--quiet",
          file
        ].executeCommand("Cannot decrypt '%s'".format(file), settings).output;
        // dfmt on
    }

    override void encrypt(string input, string accountsBase, Node settings)
    {
        auto file = accountsBase.accountsFile(extension);
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

    string id(Node settings)
    {
        return environment["HOME"] ~ "/.config/age/" ~ settings["age-key"].as!string;
    }

    override void decryptToFile(string accountsBase, string outputFile, Node settings)
    {
        auto file = accountsBase.accountsFile(extension);
        // dfmt off
        [
          "age",
          "--decrypt",
          "--identity",  id(settings),
          "--output", outputFile,
          file
        ].executeCommand("Cannot decrypt '%s'".format(file), settings);
        // dfmt on
    }

    override string decryptToString(string accountsBase, Node settings)
    {
        auto file = accountsBase.accountsFile(extension);
        // dfmt off
        return [
            "age",
            "--decrypt",
            "--identity", id(settings),
            file,
        ].executeCommand("Cannot decrypt '%s'".format(file), settings).output;
        // dfmt on
    }

    override void encrypt(string input, string accountsBase, Node settings)
    {
        auto file = accountsBase.accountsFile(extension);
        // dfmt off
        [
            "age",
            "--encrypt",
            "--identity", id(settings),
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

auto calcOtps(EncryptDecrypt encdec, string accountsBase, Node settings, long now)
{
    auto lines = encdec.decryptToString(accountsBase, settings);
    return lines
        .split
        .filter!(not!(line => line.startsWith("#")))
        .map!(line => new OTPAuth(line.parseURL));
}

void list(string accountsBase, Node settings, EncryptDecrypt encdec, List l)
{
    auto now = Clock.currTime().toUnixTime;
    auto otps = encdec.calcOtps(accountsBase, settings, now);
    if (l.table)
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
}

@(Command("list", "l"))
struct List
{
    @(NamedArgument("asciiTable", "table", "t").Description("Render as ascii table."))
    bool table = false;
}

@(Command("edit", "e"))
struct Edit
{
}

@(Command("copy", "c"))
struct Copy
{
    @(NamedArgument("asciiTable", "table", "t").Description("Render as ascii table."))
    bool table;
}

auto color(T)(string s, T color)
{
    return Arguments.withColors == Config.StylingMode.on ? color(s).to!string : s;
}

@(Command("")
  .Epilog(() => "PackageInfo:\n" ~ packages
                        .sort!((a, b) => a.name < b.name)
                        .fold!((table, p) =>
                               table
                               .row
                                   .add(p.name.color(&white))
                                   .add(p.semVer.color(&lightGray))
                                   .add(p.license.color(&lightGray)).table)
                            (new AsciiTable(3)
                                .header
                                    .add("Package".color(&bold))
                                    .add("Version".color(&bold))
                                    .add("License".color(&bold)).table)
                        .format
                            .prefix("    ")
                            .headerSeparator(true)
                            .columnSeparator(true)
     .to!string))

struct Arguments
{
    @ArgumentGroup("Common arguments")
    {
        @(NamedArgument("verbose", "v").Description("Verbose output."))
        bool verbose = false;

        @(NamedArgument("settings", "s").Description("Settings to use."))
        string settingsFileName = "$HOME/.config/sesame/settings.yaml";

        @(NamedArgument("accounts", "a").Description("Accounts file."))
        string accounts = "$HOME/.config/sesame/accounts.txt";

        @(NamedArgument("colors", "c").Description("Use ansi colors."))
        static auto withColors = ansiStylingArgument;
    }
    @SubCommands SumType!(Default!List, Edit, Copy) subcommands;
}

int _main(Arguments arguments)
{
    const home = environment["HOME"];
    auto settingsFile = arguments
        .settingsFileName
        .replace("$HOME", home);
    auto settings = Loader.fromFile(settingsFile).load();
    auto encdec = settings
        .getWithDefault("encryption", "GPG")
        .to!Encryption.toObject;
    auto accountsBase = arguments
        .accounts
        .replace("$HOME", home);
    settings["verbose"] = arguments.verbose;

    // dfmt off
    arguments.subcommands.match!(
        (List l)
        {
            accountsBase.list(settings, encdec, l);
        },
        (Edit e)
        {
            accountsBase.editData(encdec, settings);
        },
        (Copy c)
        {
            
        },
    );
    return 0;
}

mixin CLI!(Arguments).main!((arguments) {
    _main(arguments);
});
