const ELF_MAGIC = [0x7f, 0x45, 0x4c, 0x46];
const EM_AARCH64 = 0x00b7;

const LOGIC_1_NAME = "logic_1_dsu_avb_tbz_to_nop";
const LOGIC_1_DESCRIPTION = "DSU AVB 上下文中的 TBZ 分支改为 NOP";
const TBZ_W0_BIT0 = [0x20, 0x0d, 0x00, 0x36];
const NOP = [0x1f, 0x20, 0x03, 0xd5];

// Function-local DSU AVB gate signature. The two BL instructions are wildcards
// because their relative targets vary with code layout.
const BEFORE = [
  0x28, 0x88, 0x46, 0x39, 0x29, 0x40, 0x43, 0x79,
  0x09, 0x1d, 0x10, 0x33, 0xa9, 0x0c, 0x78, 0x37,
  0x88, 0x02, 0x40, 0xf9, 0xe0, 0x03, 0x14, 0xaa,
  0x08, 0x0d, 0x40, 0xf9, 0x00, 0x01, 0x3f, 0xd6,
];
const AFTER_BRANCH = [
  0xa0, 0x02, 0x40, 0xf9, 0xe1, 0x03, 0x00, 0x91,
  0xff, 0x7f, 0x00, 0xa9, 0xff, 0x0b, 0x00, 0xf9,
];
const AFTER_CALL = [
  0x1f, 0x00, 0x00, 0x71, 0xe8, 0x03, 0x40, 0x39,
  0xfb, 0x17, 0x9f, 0x1a, 0x68, 0x00, 0x00, 0x36,
  0xe0, 0x0b, 0x40, 0xf9,
];
const DSU_SIGNATURE_LENGTH = BEFORE.length + 4 + AFTER_BRANCH.length + 4 + AFTER_CALL.length;

const LOGIC_2_NAME = "logic_2_setup_dm_verity_always_success";
const LOGIC_2_DESCRIPTION = "VBoot V2 SetUpDmVerity 直接返回 true";
const LOGIC_2_PATCH_VA = 0x26a328;
const LOGIC_2_EXPECTED_BYTES = [0xff, 0x03, 0x01, 0xd1, 0xfd, 0x7b, 0x01, 0xa9];
const LOGIC_2_PATCH_BYTES = [0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];

class LogicNotApplicable extends Error {}

function matchesAt(bytes, offset, needle) {
  if (offset < 0 || offset + needle.length > bytes.length) return false;
  for (let index = 0; index < needle.length; index += 1) {
    if (bytes[offset + index] !== needle[index]) return false;
  }
  return true;
}

function sameBytes(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function hex(bytes) {
  return bytes.map(value => value.toString(16).padStart(2, "0")).join(" ");
}

function requireRange(bytes, offset, length, message) {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + length > bytes.length) {
    throw new LogicNotApplicable(message);
  }
}

function readU64AsNumber(view, offset) {
  const low = view.getUint32(offset, true);
  const high = view.getUint32(offset + 4, true);
  const value = high * 0x1_0000_0000 + low;
  if (!Number.isSafeInteger(value)) throw new LogicNotApplicable("ELF 偏移超出浏览器可安全处理的范围");
  return value;
}

function parseElf64Arm64(bytes) {
  if (bytes.length < 0x40 || !matchesAt(bytes, 0, ELF_MAGIC)) {
    throw new LogicNotApplicable("输入文件不是有效的 ELF 二进制。请上传 boot ramdisk 中的 init 文件。");
  }
  if (bytes[4] !== 2 || bytes[5] !== 1) {
    throw new LogicNotApplicable("输入文件不是 64 位小端 ELF，无法作为 ARM64 init 处理。");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint16(18, true) !== EM_AARCH64) {
    throw new LogicNotApplicable("输入文件不是 ARM64 init ELF。");
  }
  const programHeaderOffset = readU64AsNumber(view, 0x20);
  const programHeaderSize = view.getUint16(0x36, true);
  const programHeaderCount = view.getUint16(0x38, true);
  if (programHeaderSize < 56) throw new LogicNotApplicable("ELF program-header 大小无效。");
  requireRange(
    bytes,
    programHeaderOffset,
    programHeaderSize * programHeaderCount,
    "ELF program-header 表被截断。"
  );
  const segments = [];
  for (let index = 0; index < programHeaderCount; index += 1) {
    const header = programHeaderOffset + index * programHeaderSize;
    if (view.getUint32(header, true) !== 1) continue;
    const fileOffset = readU64AsNumber(view, header + 8);
    const virtualAddress = readU64AsNumber(view, header + 16);
    const fileSize = readU64AsNumber(view, header + 32);
    if (fileSize) segments.push({ fileOffset, virtualAddress, fileSize });
  }
  return { segments };
}

function virtualAddressToFileOffset(elf, bytes, address) {
  for (const segment of elf.segments) {
    if (segment.virtualAddress <= address && address < segment.virtualAddress + segment.fileSize) {
      const offset = segment.fileOffset + address - segment.virtualAddress;
      requireRange(bytes, offset, 8, `地址 0x${address.toString(16)} 不在完整文件范围内。`);
      return offset;
    }
  }
  throw new LogicNotApplicable(`地址 0x${address.toString(16)} 不在 PT_LOAD 段内。`);
}

function fileOffsetToVirtualAddress(elf, offset) {
  for (const segment of elf.segments) {
    if (segment.fileOffset <= offset && offset < segment.fileOffset + segment.fileSize) {
      return segment.virtualAddress + offset - segment.fileOffset;
    }
  }
  return null;
}

function findDsuAvbBranchOffsets(bytes) {
  const offsets = [];
  const lastStart = bytes.length - DSU_SIGNATURE_LENGTH;
  for (let start = 0; start <= lastStart; start += 1) {
    if (!matchesAt(bytes, start, BEFORE)) continue;
    const branchOffset = start + BEFORE.length;
    const afterBranch = branchOffset + 4;
    const afterCall = afterBranch + AFTER_BRANCH.length + 4;
    if (matchesAt(bytes, afterBranch, AFTER_BRANCH) && matchesAt(bytes, afterCall, AFTER_CALL)) {
      offsets.push(branchOffset);
    }
  }
  return offsets;
}

function buildResult(bytes, details) {
  const output = bytes.slice();
  output.set(details.replacement, details.patchFileOffset);
  return {
    bytes: output,
    logic: details.logic,
    description: details.description,
    patchVa: details.patchVa,
    patchFileOffset: details.patchFileOffset,
    before: hex(details.before),
    after: hex(details.replacement),
    action: details.action,
    attempts: details.attempts,
    fallbackFrom: details.fallbackFrom,
  };
}

function tryLogic1(bytes, elf, attempts) {
  const offsets = findDsuAvbBranchOffsets(bytes);
  if (offsets.length !== 1) {
    const found = offsets.length ? offsets.map(offset => `0x${offset.toString(16).toUpperCase()}`).join(", ") : "none";
    throw new LogicNotApplicable(`DSU AVB 上下文匹配到 ${offsets.length} 处（${found}）。`);
  }
  const patchFileOffset = offsets[0];
  const before = Array.from(bytes.slice(patchFileOffset, patchFileOffset + 4));
  if (sameBytes(before, TBZ_W0_BIT0)) {
    return buildResult(bytes, {
      logic: LOGIC_1_NAME,
      description: LOGIC_1_DESCRIPTION,
      patchVa: fileOffsetToVirtualAddress(elf, patchFileOffset),
      patchFileOffset,
      before,
      replacement: NOP,
      action: `分支 @ 0x${patchFileOffset.toString(16).toUpperCase()}：TBZ -> NOP`,
      attempts,
      fallbackFrom: null,
    });
  }
  if (sameBytes(before, NOP)) {
    return {
      bytes: bytes.slice(),
      logic: LOGIC_1_NAME,
      description: LOGIC_1_DESCRIPTION,
      patchVa: fileOffsetToVirtualAddress(elf, patchFileOffset),
      patchFileOffset,
      before: hex(before),
      after: hex(before),
      action: `分支 @ 0x${patchFileOffset.toString(16).toUpperCase()}：已经是 NOP，未重复写入`,
      attempts,
      fallbackFrom: null,
    };
  }
  throw new LogicNotApplicable(
    `DSU AVB 分支原始字节异常：${hex(before)}，应为 ${hex(TBZ_W0_BIT0)} 或 ${hex(NOP)}。`
  );
}

function tryLogic2(bytes, elf, attempts) {
  const patchFileOffset = virtualAddressToFileOffset(elf, bytes, LOGIC_2_PATCH_VA);
  if (!matchesAt(bytes, patchFileOffset, LOGIC_2_EXPECTED_BYTES)) {
    throw new LogicNotApplicable(`SetUpDmVerity 入口 0x${LOGIC_2_PATCH_VA.toString(16)} 的原始字节不匹配。`);
  }
  return buildResult(bytes, {
    logic: LOGIC_2_NAME,
    description: LOGIC_2_DESCRIPTION,
    patchVa: LOGIC_2_PATCH_VA,
    patchFileOffset,
    before: LOGIC_2_EXPECTED_BYTES,
    replacement: LOGIC_2_PATCH_BYTES,
    action: `SetUpDmVerity @ 0x${LOGIC_2_PATCH_VA.toString(16).toUpperCase()}：直接返回 true`,
    attempts,
    fallbackFrom: LOGIC_1_NAME,
  });
}

async function sha256(bytes) {
  if (!globalThis.crypto?.subtle) return "当前浏览器不支持 SHA-256";
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), value => value.toString(16).padStart(2, "0")).join("");
}

export async function patchInit(inputBuffer) {
  const bytes = new Uint8Array(inputBuffer.slice(0));
  const elf = parseElf64Arm64(bytes);
  const sourceHash = await sha256(bytes);
  const attempts = [];
  try {
    return { ...tryLogic1(bytes, elf, attempts), sourceHash };
  } catch (error) {
    if (!(error instanceof LogicNotApplicable)) throw error;
    attempts.push(`${LOGIC_1_NAME}：${error.message}`);
  }
  try {
    return { ...tryLogic2(bytes, elf, attempts), sourceHash };
  } catch (error) {
    if (!(error instanceof LogicNotApplicable)) throw error;
    attempts.push(`${LOGIC_2_NAME}：${error.message}`);
    throw new Error(`没有匹配到已验证的补丁逻辑。\n${attempts.join("\n")}`);
  }
}

export async function sha256Hex(bytes) {
  return sha256(bytes);
}
