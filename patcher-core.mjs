const ELF_MAGIC = [0x7f, 0x45, 0x4c, 0x46];
const EM_AARCH64 = 0x00b7;

const LOGIC_1_NAME = "logic_1_setup_dm_verity_always_success";
const LOGIC_1_DESCRIPTION = "VBoot V2 SetUpDmVerity 直接返回 true";
const LOGIC_1_PATCH_VA = 0x26a328;
const LOGIC_1_EXPECTED_BYTES = [0xff, 0x03, 0x01, 0xd1, 0xfd, 0x7b, 0x01, 0xa9];
const LOGIC_1_PATCH_BYTES = [0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];

const LOGIC_2_NAME = "logic_2_enoent_only_verity_failure";
const LOGIC_2_DESCRIPTION = "仅当 verity setup 返回 ENOENT(errno=2) 时放行";
const LOGIC_2_PATCH_VA = 0x268f9c;
const LOGIC_2_EXPECTED_BYTES = [0xfb, 0x03, 0x1f, 0x2a, 0x74, 0x02, 0x00, 0xb9];
const LOGIC_2_PATCH_BYTES = [0x9f, 0x0a, 0x00, 0x71, 0xfb, 0x17, 0x9f, 0x1a];

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

function validateElf64Arm64(bytes) {
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
  return { view, programHeaderOffset, programHeaderSize, programHeaderCount };
}

function virtualAddressToFileOffset(bytes, address) {
  const elf = validateElf64Arm64(bytes);
  for (let index = 0; index < elf.programHeaderCount; index += 1) {
    const header = elf.programHeaderOffset + index * elf.programHeaderSize;
    if (elf.view.getUint32(header, true) !== 1) continue;
    const fileOffset = readU64AsNumber(elf.view, header + 8);
    const virtualAddress = readU64AsNumber(elf.view, header + 16);
    const fileSize = readU64AsNumber(elf.view, header + 32);
    if (virtualAddress <= address && address < virtualAddress + fileSize) {
      const offset = fileOffset + address - virtualAddress;
      requireRange(bytes, offset, 8, `逻辑二地址 0x${address.toString(16)} 不在完整文件范围内。`);
      return offset;
    }
  }
  throw new LogicNotApplicable(`逻辑二地址 0x${address.toString(16)} 不在 PT_LOAD 段内。`);
}

function buildResult(bytes, logic, description, patchVa, patchFileOffset, expected, replacement, attempts, fallbackFrom) {
  const output = bytes.slice();
  output.set(replacement, patchFileOffset);
  return {
    bytes: output,
    logic,
    description,
    patchVa,
    patchFileOffset,
    before: hex(expected),
    after: hex(replacement),
    attempts,
    fallbackFrom,
  };
}

function tryLogic1(bytes, attempts) {
  const patchFileOffset = virtualAddressToFileOffset(bytes, LOGIC_1_PATCH_VA);
  if (!matchesAt(bytes, patchFileOffset, LOGIC_1_EXPECTED_BYTES)) {
    throw new LogicNotApplicable(`逻辑一地址 0x${LOGIC_1_PATCH_VA.toString(16)} 的原始字节不匹配。`);
  }
  return buildResult(
    bytes,
    LOGIC_1_NAME,
    LOGIC_1_DESCRIPTION,
    LOGIC_1_PATCH_VA,
    patchFileOffset,
    LOGIC_1_EXPECTED_BYTES,
    LOGIC_1_PATCH_BYTES,
    attempts,
    null
  );
}

function tryLogic2(bytes, attempts) {
  const patchFileOffset = virtualAddressToFileOffset(bytes, LOGIC_2_PATCH_VA);
  if (!matchesAt(bytes, patchFileOffset, LOGIC_2_EXPECTED_BYTES)) {
    throw new LogicNotApplicable(`逻辑二地址 0x${LOGIC_2_PATCH_VA.toString(16)} 的原始字节不匹配。`);
  }
  return buildResult(
    bytes,
    LOGIC_2_NAME,
    LOGIC_2_DESCRIPTION,
    LOGIC_2_PATCH_VA,
    patchFileOffset,
    LOGIC_2_EXPECTED_BYTES,
    LOGIC_2_PATCH_BYTES,
    attempts,
    LOGIC_1_NAME
  );
}

async function sha256(bytes) {
  if (!globalThis.crypto?.subtle) {
    return "当前浏览器不支持 SHA-256";
  }
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), value => value.toString(16).padStart(2, "0")).join("");
}

export async function patchInit(inputBuffer) {
  const bytes = new Uint8Array(inputBuffer.slice(0));
  validateElf64Arm64(bytes);
  const sourceHash = await sha256(bytes);
  const attempts = [];
  try {
    const result = tryLogic1(bytes, attempts);
    return { ...result, sourceHash };
  } catch (error) {
    if (!(error instanceof LogicNotApplicable)) throw error;
    attempts.push(`${LOGIC_1_NAME}：${error.message}`);
  }
  try {
    const result = tryLogic2(bytes, attempts);
    return { ...result, sourceHash };
  } catch (error) {
    if (!(error instanceof LogicNotApplicable)) throw error;
    attempts.push(`${LOGIC_2_NAME}：${error.message}`);
    throw new Error(`没有匹配到已验证的补丁逻辑。\n${attempts.join("\n")}`);
  }
}

export async function sha256Hex(bytes) {
  return sha256(bytes);
}
