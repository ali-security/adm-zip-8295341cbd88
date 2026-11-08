const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../../adm-zip");
const Utils = require("../../util/utils");

// Builds a single-entry, DEFLATE-compressed zip archive in memory so the declared
// uncompressed size and CRC can be set independently from the real payload.
function buildDeflatedZip(name, compressed, declaredSize, crc) {
    const fname = Buffer.from(name, "utf8");

    const loc = Buffer.alloc(30);
    loc.writeUInt32LE(0x04034b50, 0); // local file header signature
    loc.writeUInt16LE(20, 4); // version needed to extract
    loc.writeUInt16LE(0, 6); // general purpose bit flag
    loc.writeUInt16LE(8, 8); // compression method: deflate
    loc.writeUInt32LE(0, 10); // modification time + date
    loc.writeUInt32LE(crc >>> 0, 14); // crc-32
    loc.writeUInt32LE(compressed.length, 18); // compressed size
    loc.writeUInt32LE(declaredSize >>> 0, 22); // uncompressed size
    loc.writeUInt16LE(fname.length, 26); // file name length
    loc.writeUInt16LE(0, 28); // extra field length

    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0); // central file header signature
    cen.writeUInt16LE(20, 4); // version made by
    cen.writeUInt16LE(20, 6); // version needed to extract
    cen.writeUInt16LE(0, 8); // general purpose bit flag
    cen.writeUInt16LE(8, 10); // compression method: deflate
    cen.writeUInt32LE(0, 12); // modification time + date
    cen.writeUInt32LE(crc >>> 0, 16); // crc-32
    cen.writeUInt32LE(compressed.length, 20); // compressed size
    cen.writeUInt32LE(declaredSize >>> 0, 24); // uncompressed size
    cen.writeUInt16LE(fname.length, 28); // file name length
    cen.writeUInt16LE(0, 30); // extra field length
    cen.writeUInt16LE(0, 32); // file comment length
    cen.writeUInt16LE(0, 34); // disk number start
    cen.writeUInt16LE(0, 36); // internal file attributes
    cen.writeUInt32LE(0, 38); // external file attributes
    cen.writeUInt32LE(0, 42); // offset of local header

    const cenOffset = loc.length + fname.length + compressed.length;
    const cenSize = cen.length + fname.length;

    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0); // end of central dir signature
    end.writeUInt16LE(0, 4); // number of this disk
    end.writeUInt16LE(0, 6); // disk where central directory starts
    end.writeUInt16LE(1, 8); // number of central directory records on this disk
    end.writeUInt16LE(1, 10); // total number of central directory records
    end.writeUInt32LE(cenSize, 12); // size of central directory
    end.writeUInt32LE(cenOffset, 16); // offset of start of central directory
    end.writeUInt16LE(0, 20); // comment length

    return Buffer.concat([loc, fname, compressed, cen, fname, end]);
}

describe("method - inflater: decompression bomb is capped at the declared size", () => {
    const name = "bomb.txt";
    // 4 MiB of a single repeated byte deflates to a few KiB: a classic bomb payload
    const bombContent = Buffer.alloc(4 * 1024 * 1024, 0x41);
    const bombCompressed = zlib.deflateRawSync(bombContent);
    const smallDeclaredSize = 1024;
    // CRC of the truncated prefix the old code would hand back, so a missing cap
    // cannot hide behind a BAD_CRC failure
    const prefixCrc = Utils.crc32(bombContent.slice(0, smallDeclaredSize));

    it("decompression bomb - sync: rejects output past a non-zero declared size", () => {
        // the payload is highly compressed: a tiny archive expands to megabytes
        expect(bombCompressed.length).to.be.below(bombContent.length / 100);
        const zip = new Zip(buildDeflatedZip(name, bombCompressed, smallDeclaredSize, prefixCrc));
        const entry = zip.getEntry(name);
        expect(entry.header.size).to.equal(smallDeclaredSize);
        let thrown = null;
        let data = null;
        try {
            data = entry.getData();
        } catch (err) {
            thrown = err;
        }
        expect(data, "bomb must not be returned as valid data").to.equal(null);
        expect(thrown).to.be.an("error");
        expect(thrown.code).to.equal("ERR_BUFFER_TOO_LARGE");
    });

    it("decompression bomb - sync: a declared size of 0 does not disable the cap", () => {
        // crc32 of an empty buffer is 0, so without a cap the whole bomb is inflated
        // and silently returned as a "valid" empty entry
        const zip = new Zip(buildDeflatedZip(name, bombCompressed, 0, 0));
        const entry = zip.getEntry(name);
        expect(entry.header.size).to.equal(0);
        let thrown = null;
        let data = null;
        try {
            data = entry.getData();
        } catch (err) {
            thrown = err;
        }
        expect(data, "bomb must not be returned as valid data").to.equal(null);
        expect(thrown).to.be.an("error");
        expect(thrown.code).to.equal("ERR_BUFFER_TOO_LARGE");
    });

    it("decompression bomb - async: rejects output past a non-zero declared size", (done) => {
        const zip = new Zip(buildDeflatedZip(name, bombCompressed, smallDeclaredSize, prefixCrc));
        const entry = zip.getEntry(name);
        entry.getDataAsync(function (data, err) {
            try {
                expect(err).to.be.an("error");
                expect(err.message).to.equal("ADM-ZIP: Decompressed data exceeds the declared uncompressed size");
                expect(data.length).to.be.at.most(smallDeclaredSize);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("decompression bomb - async: a declared size of 0 does not disable the cap", (done) => {
        const zip = new Zip(buildDeflatedZip(name, bombCompressed, 0, 0));
        const entry = zip.getEntry(name);
        entry.getDataAsync(function (data, err) {
            try {
                expect(err).to.be.an("error");
                expect(err.message).to.equal("ADM-ZIP: Decompressed data exceeds the declared uncompressed size");
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("decompression bomb - async: readAsTextAsync reports the cap error", (done) => {
        const zip = new Zip(buildDeflatedZip(name, bombCompressed, 0, 0));
        zip.readAsTextAsync(name, function (data, err) {
            try {
                expect(err).to.be.an("error");
                expect(err.message).to.equal("ADM-ZIP: Decompressed data exceeds the declared uncompressed size");
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("decompression bomb - async: malformed deflate data reports an error instead of crashing", (done) => {
        // 0xff starts a block with the reserved (invalid) block type 3
        const garbage = Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        const zip = new Zip(buildDeflatedZip(name, garbage, 16, 0));
        const entry = zip.getEntry(name);
        entry.getDataAsync(function (data, err) {
            try {
                expect(err).to.be.an("error");
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("decompression bomb - sync/async: a genuinely empty deflated entry with declared size 0 still inflates", (done) => {
        const emptyCompressed = zlib.deflateRawSync(Buffer.alloc(0));
        expect(emptyCompressed.length).to.be.above(0);
        const zip = new Zip(buildDeflatedZip(name, emptyCompressed, 0, 0));
        const entry = zip.getEntry(name);
        expect(entry.getData().length).to.equal(0);
        entry.getDataAsync(function (data, err) {
            try {
                expect(err).to.equal(undefined);
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("decompression bomb - sync/async: output exactly matching the declared size inflates normally", (done) => {
        const content = Buffer.alloc(100 * 1024);
        for (let i = 0; i < content.length; i++) content[i] = (i * 31 + (i >> 7)) & 0xff;
        const zip = new Zip(buildDeflatedZip(name, zlib.deflateRawSync(content), content.length, Utils.crc32(content)));
        const entry = zip.getEntry(name);
        expect(entry.getData().equals(content)).to.equal(true);
        entry.getDataAsync(function (data, err) {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(content)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });
});
