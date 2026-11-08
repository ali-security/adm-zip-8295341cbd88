"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });

    // A well-formed deflate stream that inflates fine but lies about its size. The
    // declared size is clamped to the largest buffer this runtime can hold (2 GB on
    // node 12, more on newer runtimes) so the inflater's output cap stays valid and
    // the call reaches the CRC check on every supported node version.
    const LARGE_DECLARED = Math.min(DECLARED, require("buffer").constants.MAX_LENGTH);
    const validDeflate = () => zlib.deflateRawSync(Buffer.from("A"));

    it("does not allocate the declared size for a valid DEFLATED stream", () => {
        const zip = new Zip(craftBomb(LARGE_DECLARED, 8 /* DEFLATED */, validDeflate()));
        const before = process.memoryUsage().rss;
        // inflates to 1 byte with a wrong crc -> must report the CRC failure without
        // ever touching a buffer of the declared size
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a STORED entry (async)", (done) => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        let cbData, cbErr;
        try {
            zip.getEntries()[0].getDataAsync(function (data, err) {
                cbData = data;
                cbErr = err;
            });
        } catch (e) {
            // the STORED branch also throws after reporting the CRC failure to the callback
            expect(e.message).to.match(/CRC32/);
        }
        try {
            expect(cbErr).to.be.an("error");
            expect(cbErr.message).to.match(/CRC32/);
            expect(cbData.length).to.equal(1);
            const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
            expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
            done();
        } catch (e) {
            done(e);
        }
    });

    it("does not allocate the declared size for a DEFLATED entry (async)", (done) => {
        const zip = new Zip(craftBomb(LARGE_DECLARED, 8 /* DEFLATED */, validDeflate()));
        const before = process.memoryUsage().rss;
        zip.getEntries()[0].getDataAsync(function (data, err) {
            try {
                expect(err).to.be.an("error");
                expect(err.message).to.match(/CRC32/);
                expect(data.length).to.equal(1);
                const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
                expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("rejects an unknown compression method without allocating the declared size", () => {
        const zip = new Zip(craftBomb(DECLARED, 99 /* unsupported */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        expect(() => zip.getEntries()[0].getData()).to.throw(/unsupported compression method/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });
});
