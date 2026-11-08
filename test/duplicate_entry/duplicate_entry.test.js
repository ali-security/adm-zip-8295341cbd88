"use strict";

// GHSA-p634-w6r4-rjp2: an archive may declare the same entry name twice.
// adm-zip kept every entry in its entry list but only the last one in its
// name table, so getEntry() (table) returned the last duplicate while
// extractAllTo() (list) wrote the first one to disk under that name. An app
// that validated the bytes returned by getEntry() before extracting could
// approve one file while a different one landed on disk. Such archives are
// now rejected.

const assert = require("assert");
const fs = require("fs");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");

// Build an archive holding "a.txt" (FIRST) and "b.txt" (SECOND), then rename
// "a.txt" to "b.txt" in both the local and the central header, leaving two
// entries named "b.txt" with different content.
function craftDuplicate() {
    const zip = new Zip();
    zip.addFile("a.txt", Buffer.from("FIRST"));
    zip.addFile("b.txt", Buffer.from("SECOND"));
    const buf = zip.toBuffer();
    const from = Buffer.from("a.txt");
    const to = Buffer.from("b.txt");
    let replaced = 0;
    for (let i = buf.indexOf(from); i !== -1; i = buf.indexOf(from, i + from.length)) {
        to.copy(buf, i);
        replaced++;
    }
    assert.strictEqual(replaced, 2);
    return buf;
}

describe("ADM-ZIP - duplicate entry names (GHSA-p634-w6r4-rjp2)", () => {
    const destination = pth.join(__dirname, "xxx");
    const extracted = pth.join(destination, "b.txt");

    afterEach((done) => rimraf(destination, done));

    it("GHSA-p634-w6r4-rjp2: getEntry/readFile/getEntries reject the archive", () => {
        const zip = new Zip(craftDuplicate());
        assert.throws(() => zip.getEntry("b.txt"), /Duplicate entry name "b\.txt"/);
        assert.throws(() => zip.readFile("b.txt"), /Duplicate entry name/);
        assert.throws(() => zip.getEntries(), /Duplicate entry name/);
    });

    it("GHSA-p634-w6r4-rjp2: extractAllTo rejects the archive and writes nothing", () => {
        const zip = new Zip(craftDuplicate());
        assert.throws(() => zip.extractAllTo(destination, true), /Duplicate entry name/);
        assert.strictEqual(fs.existsSync(extracted), false);
    });

    it("GHSA-p634-w6r4-rjp2: validate-then-extract keeps failing after the first error is caught", () => {
        const zip = new Zip(craftDuplicate());
        assert.throws(() => zip.getEntry("b.txt"), /Duplicate entry name/);
        assert.throws(() => zip.extractAllTo(destination, true), /Duplicate entry name/);
        assert.throws(() => zip.getEntry("b.txt"), /Duplicate entry name/);
        assert.strictEqual(fs.existsSync(extracted), false);
    });

    it("GHSA-p634-w6r4-rjp2: extractAllToAsync rejects the archive and writes nothing", () => {
        const zip = new Zip(craftDuplicate());
        return assert.rejects(zip.extractAllToAsync(destination, true), /Duplicate entry name/).then(() => {
            assert.strictEqual(fs.existsSync(extracted), false);
        });
    });

    it("GHSA-p634-w6r4-rjp2: loading with readEntries rejects the archive", () => {
        assert.throws(() => new Zip(craftDuplicate(), { readEntries: true }), /Duplicate entry name/);
    });

    it("GHSA-p634-w6r4-rjp2: names matching Object.prototype keys are not treated as duplicates", () => {
        const names = ["toString", "constructor", "hasOwnProperty", "__proto__", "valueOf"];
        const zip = new Zip();
        names.forEach((name) => zip.addFile(name, Buffer.from(name)));
        const reopened = new Zip(zip.toBuffer());
        assert.deepStrictEqual(
            reopened
                .getEntries()
                .map((e) => e.entryName)
                .sort(),
            names.slice().sort()
        );
        names.forEach((name) => assert.strictEqual(reopened.readFile(name).toString(), name));
    });

    it("GHSA-p634-w6r4-rjp2: names differing only by case are distinct entries", () => {
        const zip = new Zip();
        zip.addFile("b.txt", Buffer.from("lower"));
        zip.addFile("B.txt", Buffer.from("upper"));
        const reopened = new Zip(zip.toBuffer());
        assert.strictEqual(reopened.getEntries().length, 2);
        assert.strictEqual(reopened.readFile("b.txt").toString(), "lower");
        assert.strictEqual(reopened.readFile("B.txt").toString(), "upper");
    });
});
