import argparse.api.cli : CLI;

import argparse : ansiStylingArgument, ArgumentGroup, CLI, Command, Config,
    Default, Description, Epilog, NamedArgument, SubCommand, matchCmd;
import argparse.api.argument : PositionalArgument, Optional, Required;
import asciitable : AsciiTable, UnicodeParts;
import colored : bold, green, lightGray, white;
import dyaml : Loader, Node;
import fuzzed : fuzzed;
import otpauth : OTPAuth;
import packageinfo : packages;
import std.algorithm : filter, find, fold, map, sort, startsWith;
import std.array : array;
import std.conv : to;
import std.datetime : Clock;
import std.exception : enforce;
import std.file : remove;
import std.format : format;
import std.functional : not;
import std.process : environment, escapeShellCommand, execute, executeShell, spawnProcess, wait;
import std.range : empty;
import std.stdio : stderr, writeln, File;
import std.string : replace, split;
import std.uni : toLower;
import url : parseURL;

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
    final switch (e) with (Encryption)
    {
    case GPG:
        return new GPGEncryptDecrypt();
    case AGE:
        return new AgeEncryptDecrypt();
    }
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

auto calcOtps(EncryptDecrypt encdec, string accountsBase, Node settings, long now, string filter)
{
    auto lines = encdec.decryptToString(accountsBase, settings);
    return lines.split
        .filter!(not!(line => line.startsWith("#")))
        .filter!((line) {
            if (filter is null)
            {
                return true;
            }
            return !line.toLower.find(filter.toLower).empty;
        })
        .map!(line => new OTPAuth(line.parseURL));
}

void list(string accountsBase, Node settings, EncryptDecrypt encdec, List l, string filter)
{
    auto now = Clock.currTime().toUnixTime;
    auto otps = encdec.calcOtps(accountsBase, settings, now, filter);
    if (l.table)
    {
        //dfmt off
        auto table = new AsciiTable(5);
        table.header
            .add("Issuer").add("Account").add("Last").add("Current").add("Next");
        foreach (otpauth; otps)
        {
            table.row()
                .add(otpauth.issuer.color(&green))
                .add(otpauth.account)
                .add(otpauth.totp(now - otpauth.period))
                .add(otpauth.totp(now).color(&green))
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
            writeln(otpauth.issuer.color(&green), "/",
                    otpauth.account, ": ",
                    otpauth.totp(now - otpauth.period), " ",
                    otpauth.totp(now).color(&green), " ",
                    otpauth.totp(now + otpauth.period)
            );
            // dfmt on
        }
    }
}

@(Command("list", "l").Description("List totps"))
struct List
{
    @(NamedArgument)
    bool table = false;

    @(PositionalArgument().Optional())
    string filter = "";
}

@Command("edit", "e")
struct Edit
{
}

@Command("copy", "c")
struct Copy
{
    @(PositionalArgument(0).Optional())
    string filter = "";
}

@Command("openvpn")
struct OpenVPN
{
    @(NamedArgument.Required())
    string user;
    @(NamedArgument.Required())
    string filter;
    @(NamedArgument.Required())
    string config;
}

auto color(T)(string s, T color)
{
    return Arguments.withColors ? color(s).to!string : s;
}

// dfmt off
@(Command("").Epilog(
    () =>
      "PackageInfo:\n" ~
        packages
          .sort!((a, b) => a.name < b.name)
          .fold!(
            (table, p) =>
              table.row.add(p.name.color(&white))
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
 // dfmt on

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

        @(NamedArgument().Description("Use ansi colors."))
        static auto withColors = ansiStylingArgument;
    }

    SubCommand!(Default!List, Edit, Copy, OpenVPN) subcommands;
}

string copy2ClipboardCommand()
{
    version (OSX)
    {
        return "pbcopy";
    }

    version (linux)
    {
        return "xsel --clipboard --input";
    }

    assert(false);
}

auto toEncryption(string s)
{
    return s.to!Encryption.toObject;
}

string credentialsFileName() => format!("%s/tmp/openvpn-credentials")(environment.get("HOME"));
extern (C) void signal(int sig, void function(int));
extern (C) void exit(int exit_val);

extern (C) void handle(int sig)
{
    credentialsFileName.remove;
    exit(0);
}

int _main(Arguments arguments)
{
    const home = environment["HOME"];
    auto settingsFile = arguments.settingsFileName.replace("$HOME", home);
    auto settings = Loader.fromFile(settingsFile).load();
    auto encdec = settings.getWithDefault("encryption", "GPG").toEncryption;
    auto accountsBase = arguments.accounts.replace("$HOME", home);
    settings["verbose"] = arguments.verbose;
    // dfmt off
    arguments.subcommands.matchCmd!(
        (List l)
        {
            accountsBase.list(settings, encdec, l, l.filter);
        },
        (Edit e)
        {
            accountsBase.editData(encdec, settings);
        },
        (Copy c)
        {
            auto now = Clock.currTime().toUnixTime;
            auto otps = encdec
                .calcOtps(accountsBase, settings, now, c.filter).array;
            string code = null;
            if (otps.length == 1)
            {
                code = otps[0].totp(now);
            }
            else
            {
                auto strings = otps.map!(otp => "%s/%s: %s".format(otp.issuer.green, otp.account, otp.totp(now))).array;
                auto selection = fuzzed(strings);
                if (selection !is null)
                {
                    code = otps[selection.index].totp(now);
                }
            }
            if (code !is null) {
                auto result = "bash -c 'echo -n %s | %s'".format(code, copy2ClipboardCommand).executeShell;
                if (result.status == 0)
                {
                    "Copied otp to clipboard".writeln;
                }
            }
        },
        (OpenVPN openVpn) {
            auto now = Clock.currTime().toUnixTime;
            auto otps = encdec
                .calcOtps(accountsBase, settings, now, openVpn.filter).array;
            string code = null;
            if (otps.length == 1)
            {
                code = otps[0].totp(now);
            } else {
                throw new Exception("More than one totp config found for " ~ openVpn.filter);
            }
            {
                auto credentialsFile = File(credentialsFileName, "w");
                credentialsFile.writeln("christian.koestlin");
                credentialsFile.writeln(code);
            }
            enum SIGINT = 2;
            signal(SIGINT,&handle);

            auto openVpnProcess = execute(["sudo", "openvpn", "--config", openVpn.config, "--auth-user-pass", credentialsFileName]);
            if (openVpnProcess.status != 0) writeln("OpenVPN failed:\n", openVpnProcess.output);
        },
    );
    return 0;
}

mixin CLI!(Arguments).main!((arguments) { return _main(arguments); });
