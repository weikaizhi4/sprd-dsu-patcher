const ELF_MAGIC = [0x7f, 0x45, 0x4c, 0x46];
const EM_AARCH64 = 0x00b7;

const TBZ_W0_BIT0 = [0x20, 0x0d, 0x00, 0x36];
const NOP = [0x1f, 0x20, 0x03, 0xd5];

// The two wildcard regions in this function-local signature are BL targets.
// Their displacement varies across init builds, so only stable instructions
// are required for a match.
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

const SIGNATURE_LENGTH = BEFORE.length + 4 + AFTER_BRANCH.length + 4 + AFTER_CALL.length;

function matchesAt(bytes, offset, needle) {
  if (offset + needle.length > bytes.length) return false;
  for (let index = 0; index < needle.length; index += 1) {
    if (bytes[offset + index] !== needle[index]) return false;
  }
  return true;
}

function instructionAt(bytes, offset) {
  return Array.from(bytes.slice(offset, offset + 4));
}

function sameBytes(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function hex(bytes) {
  return bytes.map(value => value.toString(16).padStart(2, "0")).join(" ");
}

function validateElf(bytes) {
  if (bytes.length < 0x40 || !matchesAt(bytes, 0, ELF_MAGIC)) {
    throw new Error("输入文件不是有效的 ELF 二进制。请上传 boot ramdisk 中的 init 文件。");
  }
  if (bytes[4] !== 2 || bytes[5] !== 1) {
    throw new Error("输入文件不是 64 位小端 ELF，无法作为 ARM64 init 处理。");
  }
  const machine = bytes[18] | (bytes[19] << 8);
  if (machine !== EM_AARCH64) {
    throw new Error(`输入文件的架构为 0x${machine.toString(16).padStart(4, "0").toUpperCase()}，不是预期的 ARM64 (0x00B7)。`);
  }
}

export function findDsuAvbBranchOffsets(bytes) {
  const offsets = [];
  const lastStart = bytes.length - SIGNATURE_LENGTH;
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

export function patchInit(inputBuffer) {
  const bytes = new Uint8Array(inputBuffer.slice(0));
  validateElf(bytes);
  const offsets = findDsuAvbBranchOffsets(bytes);
  if (offsets.length !== 1) {
    const found = offsets.length ? offsets.map(offset => `0x${offset.toString(16).toUpperCase()}`).join(", ") : "none";
    throw new Error(
      `拒绝修改：未能唯一定位 DSU AVB 分支函数。上下文匹配到 ${offsets.length} 处（${found}）。` +
      "该 init 的函数布局可能不同，未写入任何数据。"
    );
  }

  const offset = offsets[0];
  const before = instructionAt(bytes, offset);
  let action;
  if (sameBytes(before, TBZ_W0_BIT0)) {
    bytes.set(NOP, offset);
    action = `分支 @ 0x${offset.toString(16).toUpperCase()}：TBZ -> NOP`;
  } else if (sameBytes(before, NOP)) {
    action = `分支 @ 0x${offset.toString(16).toUpperCase()}：已经是 NOP，未重复写入`;
  } else {
    throw new Error(
      `拒绝修改：0x${offset.toString(16).toUpperCase()} 的分支指令不是预期值。` +
      `应为 ${hex(TBZ_W0_BIT0)} 或已补丁的 ${hex(NOP)}，实际为 ${hex(before)}。未写入任何数据。`
    );
  }

  return {
    bytes,
    offset,
    before: hex(before),
    after: hex(instructionAt(bytes, offset)),
    action,
  };
}

export async function sha256Hex(bytes) {
  if (!globalThis.crypto?.subtle) return "当前浏览器不支持 SHA-256";
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), value => value.toString(16).padStart(2, "0")).join("");
}
