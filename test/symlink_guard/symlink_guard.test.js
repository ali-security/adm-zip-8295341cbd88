"use strict";

// CVE-2026-76845 (GHSA-vwc7-r8mq-g2x9): adm-zip followed symbolic links that
// already existed inside the extraction directory. sanitize() only checks the
// textual entry path against the root, and writeFileTo()/makeDir() then open()
// or mkdir() through any symlinked path component, so an archive entry such as
// "evil/pwned.txt" landed wherever the pre-planted "evil" link pointed - no
// "../" needed. Extraction must now refuse to write through such a link.

const assert = require("assert");
const fs = require("fs");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");

const PAYLOAD = "PWNED";
const IN_THE_WAY = /There is a file in the way/;

// Create a symlink, or return false when this platform/user cannot (e.g. Windows
// without the symlink privilege). Directory links are created as junctions on
// Windows, which need no privilege and which lstat reports as symbolic links;
// the type argument is ignored elsewhere.
function trySymlink(target, link, isDir) {
    try {
        fs.symlinkSync(pth.resolve(target), link, isDir ? "junction" : "file");
        return true;
    } catch (e) {
        if (e && ["EPERM", "EACCES", "ENOSYS", "ENOTSUP", "EOPNOTSUPP"].indexOf(e.code) !== -1) return false;
        throw e;
    }
}

// Round-trip through a buffer so the archive is parsed like one read from disk.
function makeZip(entries) {
    const zip = new Zip();
    entries.forEach((e) => zip.addFile(e[0], e[1] === null ? null : Buffer.from(e[1])));
    return new Zip(zip.toBuffer());
}

describe("ADM-ZIP - symlinkguard: extraction refuses to write through symlinks (CVE-2026-76845)", () => {
    const root = pth.join(__dirname, "xxx");
    const destination = pth.join(root, "dest");
    const outside = pth.join(root, "outside");

    beforeEach(() => {
        fs.mkdirSync(destination, { recursive: true });
        fs.mkdirSync(outside, { recursive: true });
    });

    afterEach((done) => rimraf(root, done));

    // plant destination/evil -> outside
    function plantDirLink(ctx) {
        if (!trySymlink(outside, pth.join(destination, "evil"), true)) ctx.skip();
    }

    it("symlinkguard: extractAllTo does not write a file through a symlinked directory", function () {
        plantDirLink(this);
        const zip = makeZip([["evil/pwned.txt", PAYLOAD]]);

        assert.throws(() => zip.extractAllTo(destination), IN_THE_WAY);
        assert.strictEqual(fs.existsSync(pth.join(outside, "pwned.txt")), false);
    });

    it("symlinkguard: extractAllTo does not create a directory through a symlinked directory", function () {
        plantDirLink(this);
        const zip = makeZip([["evil/sub/", null]]);

        assert.throws(() => zip.extractAllTo(destination, true), IN_THE_WAY);
        assert.strictEqual(fs.existsSync(pth.join(outside, "sub")), false);
    });

    it("symlinkguard: extractAllTo with overwrite does not overwrite the target of a file symlink", function () {
        const victim = pth.join(outside, "victim.txt");
        fs.writeFileSync(victim, "ORIGINAL");
        if (!trySymlink(victim, pth.join(destination, "victim.txt"), false)) this.skip();
        const zip = makeZip([["victim.txt", PAYLOAD]]);

        assert.throws(() => zip.extractAllTo(destination, true), IN_THE_WAY);
        assert.strictEqual(fs.readFileSync(victim, "utf8"), "ORIGINAL");
    });

    it("symlinkguard: extractAllTo without overwrite does not create the target of a dangling symlink", function () {
        const created = pth.join(outside, "created.txt");
        if (!trySymlink(created, pth.join(destination, "new.txt"), false)) this.skip();
        const zip = makeZip([["new.txt", PAYLOAD]]);

        assert.throws(() => zip.extractAllTo(destination, false), IN_THE_WAY);
        assert.strictEqual(fs.existsSync(created), false);
    });

    it("symlinkguard: extractEntryTo does not write a file entry through a symlinked directory", function () {
        plantDirLink(this);
        const zip = makeZip([["evil/pwned.txt", PAYLOAD]]);

        assert.throws(() => zip.extractEntryTo("evil/pwned.txt", destination, true, true), IN_THE_WAY);
        assert.strictEqual(fs.existsSync(pth.join(outside, "pwned.txt")), false);
    });

    it("symlinkguard: extractEntryTo does not write a directory entry's children through a symlinked directory", function () {
        plantDirLink(this);
        const zip = makeZip([
            ["evil/", null],
            ["evil/pwned.txt", PAYLOAD]
        ]);

        assert.throws(() => zip.extractEntryTo("evil/", destination, true, true), IN_THE_WAY);
        assert.strictEqual(fs.existsSync(pth.join(outside, "pwned.txt")), false);
    });

    it("symlinkguard: extractEntryTo with outFileName does not write through a symlinked directory", function () {
        plantDirLink(this);
        const zip = makeZip([["a.txt", PAYLOAD]]);

        assert.throws(() => zip.extractEntryTo("a.txt", destination, false, true, false, "evil/out.txt"), IN_THE_WAY);
        assert.strictEqual(fs.existsSync(pth.join(outside, "out.txt")), false);
    });

    it("symlinkguard: extractAllToAsync does not write a file through a symlinked directory", function () {
        plantDirLink(this);
        const zip = makeZip([["evil/pwned.txt", PAYLOAD]]);

        return assert.rejects(zip.extractAllToAsync(destination, true), IN_THE_WAY).then(() => {
            assert.strictEqual(fs.existsSync(pth.join(outside, "pwned.txt")), false);
        });
    });

    it("symlinkguard: extractAllToAsync does not create a directory through a symlinked directory", function () {
        plantDirLink(this);
        const zip = makeZip([["evil/sub/", null]]);

        return assert.rejects(zip.extractAllToAsync(destination, true), /Unable to create folder/).then(() => {
            assert.strictEqual(fs.existsSync(pth.join(outside, "sub")), false);
        });
    });

    it("symlinkguard: a symlink elsewhere in the destination does not block unrelated entries", function () {
        plantDirLink(this);
        const zip = makeZip([["safe/ok.txt", "OK"]]);

        zip.extractAllTo(destination, true);
        assert.strictEqual(fs.readFileSync(pth.join(destination, "safe", "ok.txt"), "utf8"), "OK");
        assert.deepStrictEqual(fs.readdirSync(outside), []);
    });

    it("symlinkguard: a destination that is itself reached through a symlink still extracts", function () {
        const linkedRoot = pth.join(root, "linked");
        if (!trySymlink(destination, linkedRoot, true)) this.skip();
        const zip = makeZip([["dir/file.txt", "OK"]]);

        zip.extractAllTo(linkedRoot, true);
        assert.strictEqual(fs.readFileSync(pth.join(destination, "dir", "file.txt"), "utf8"), "OK");

        return zip.extractAllToAsync(pth.join(linkedRoot, "async"), true).then(() => {
            assert.strictEqual(fs.readFileSync(pth.join(destination, "async", "dir", "file.txt"), "utf8"), "OK");
        });
    });
});
